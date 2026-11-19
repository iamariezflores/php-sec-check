<?php

namespace Aquilinoflores\PhpSecCheck\Scan;

/**
 * Lightweight PHP call finder based on token_get_all().
 *
 * This is a starting point, not a full taint analyser. Nested assignments
 * and inter-procedural flow need AST-based analysis later.
 */
class PhpFunctionCallScanner
{
    private const UNTRUSTED_VARS = [
        '$_GET', '$_POST', '$_REQUEST', '$_COOKIE', '$_FILES', '$_SERVER', '$argv',
    ];

    private const SKIP_PREVIOUS = [
        T_OBJECT_OPERATOR,
        T_NULLSAFE_OBJECT_OPERATOR,
        T_DOUBLE_COLON,
        T_FUNCTION,
        T_NEW,
    ];

    /**
     * @param list<string> $functionNames
     * @return list<array{function: string, line: int, untrusted: bool, via: string}>
     */
    public function findCalls(string $source, array $functionNames): array
    {
        $calls = [];
        foreach ($this->findCallsWithArguments($source, $functionNames) as $call) {
            $flat = [];
            foreach ($call['arguments'] as $group) {
                foreach ($group as $token) {
                    $flat[] = $token;
                }
            }
            $calls[] = [
                'function'  => $call['function'],
                'line'      => $call['line'],
                'untrusted' => $this->argumentsUseUntrusted($flat),
                'via'       => $call['via'],
            ];
        }

        return $calls;
    }

    /**
     * @param list<string> $functionNames
     * @return list<array{function: string, line: int, via: string, arguments: list<list<string|array{0: int, 1: string, 2: int}>>}>
     */
    public function findCallsWithArguments(string $source, array $functionNames, bool $includeMethods = false): array
    {
        $wanted = array_map('strtolower', $functionNames);
        $tokens = @token_get_all($source);
        if (!is_array($tokens) || $tokens === []) {
            return [];
        }

        $calls = [];
        $count = count($tokens);

        for ($i = 0; $i < $count; $i++) {
            $token = $tokens[$i];

            if ($token === '`' && in_array('shell_exec', $wanted, true)) {
                $inner = $this->captureBacktickInner($tokens, $i);
                $calls[] = [
                    'function'  => 'shell_exec',
                    'line'      => $inner['line'],
                    'via'       => 'backtick',
                    'arguments' => [$inner['tokens']],
                ];
                for ($j = $i + 1; $j < $count; $j++) {
                    if ($tokens[$j] === '`') {
                        $i = $j;
                        break;
                    }
                }
                continue;
            }

            if (is_array($token) && $token[0] === T_EVAL && in_array('eval', $wanted, true)) {
                [$nextIndex, $next] = $this->nextSignificant($tokens, $i);
                if ($next === '(') {
                    $args = $this->extractArgumentTokens($tokens, $nextIndex);
                    $calls[] = [
                        'function'  => 'eval',
                        'line'      => $token[2],
                        'via'       => 'call',
                        'arguments' => $this->splitArguments($args),
                    ];
                }
                continue;
            }

            if (!is_array($token)) {
                continue;
            }

            $name = $this->callableName($token);
            if ($name === null || !in_array($name, $wanted, true)) {
                continue;
            }

            if ($this->shouldSkipCallable($tokens, $i, $includeMethods)) {
                continue;
            }

            [$nextIndex, $next] = $this->nextSignificant($tokens, $i);
            if ($next !== '(') {
                continue;
            }

            $args = $this->extractArgumentTokens($tokens, $nextIndex);
            $calls[] = [
                'function'  => $name,
                'line'      => $token[2],
                'via'       => 'call',
                'arguments' => $this->splitArguments($args),
            ];
        }

        return $calls;
    }

    /**
     * @param list<string|array{0: int, 1: string, 2: int}> $tokens
     * @return array{line: int, tokens: list<string|array{0: int, 1: string, 2: int}>}
     */
    private function captureBacktickInner(array $tokens, int $index): array
    {
        $inner = [];
        $line  = 1;
        $count = count($tokens);

        for ($j = $index + 1; $j < $count; $j++) {
            if ($tokens[$j] === '`') {
                break;
            }
            $inner[] = $tokens[$j];
            if (is_array($tokens[$j])) {
                $line = $tokens[$j][2];
            }
        }

        return ['line' => $line, 'tokens' => $inner];
    }

    /**
     * @param list<string|array{0: int, 1: string, 2: int}> $argTokens
     * @return list<list<string|array{0: int, 1: string, 2: int}>>
     */
    public function splitArguments(array $argTokens): array
    {
        $args    = [];
        $current = [];
        $paren   = 0;
        $bracket = 0;

        foreach ($argTokens as $token) {
            $char = is_array($token) ? null : $token;
            if ($char === '(') {
                $paren++;
            } elseif ($char === ')') {
                $paren--;
            } elseif ($char === '[') {
                $bracket++;
            } elseif ($char === ']') {
                $bracket--;
            }

            if ($char === ',' && $paren === 0 && $bracket === 0) {
                $args[]  = $current;
                $current = [];
                continue;
            }

            $current[] = $token;
        }

        if ($current !== []) {
            $args[] = $current;
        }

        return $args;
    }

    /**
     * @param array{0: int, 1: string, 2: int} $token
     */
    private function callableName(array $token): ?string
    {
        if ($token[0] === T_STRING) {
            return strtolower($token[1]);
        }

        if ($token[0] === T_NAME_FULLY_QUALIFIED) {
            $parts = explode('\\', ltrim($token[1], '\\'));
            if (count($parts) === 1) {
                return strtolower($parts[0]);
            }
        }

        return null;
    }

    /**
     * @param list<string|array{0: int, 1: string, 2: int}> $tokens
     */
    private function shouldSkipCallable(array $tokens, int $index, bool $includeMethods): bool
    {
        [, $prev] = $this->previousSignificant($tokens, $index);
        if (is_array($prev) && in_array($prev[0], [T_FUNCTION, T_NEW], true)) {
            return true;
        }

        if ($includeMethods) {
            return false;
        }

        return $this->isMethodOrQualifiedName($tokens, $index);
    }

    /**
     * @param list<string|array{0: int, 1: string, 2: int}> $tokens
     */
    private function isMethodOrQualifiedName(array $tokens, int $index): bool
    {
        [$prevIndex, $prev] = $this->previousSignificant($tokens, $index);
        if ($prev === null) {
            return false;
        }

        if (is_array($prev) && in_array($prev[0], self::SKIP_PREVIOUS, true)) {
            return true;
        }

        if (is_array($prev) && $prev[0] === T_NS_SEPARATOR) {
            [, $beforeNs] = $this->previousSignificant($tokens, $prevIndex);
            return is_array($beforeNs) && $beforeNs[0] === T_STRING;
        }

        return false;
    }

    /**
     * @param list<string|array{0: int, 1: string, 2: int}> $tokens
     * @return list<string|array{0: int, 1: string, 2: int}>
     */
    private function extractArgumentTokens(array $tokens, int $openParenIndex): array
    {
        $args  = [];
        $depth = 0;
        $count = count($tokens);

        for ($i = $openParenIndex; $i < $count; $i++) {
            $token = $tokens[$i];
            $char  = is_array($token) ? null : $token;

            if ($char === '(') {
                $depth++;
                if ($depth === 1) {
                    continue;
                }
            } elseif ($char === ')') {
                $depth--;
                if ($depth === 0) {
                    break;
                }
            }

            if ($depth > 0) {
                $args[] = $token;
            }
        }

        return $args;
    }

    /**
     * @param list<string|array{0: int, 1: string, 2: int}> $argTokens
     */
    private function argumentsUseUntrusted(array $argTokens): bool
    {
        foreach ($argTokens as $token) {
            if (!is_array($token)) {
                continue;
            }

            if ($token[0] === T_VARIABLE && in_array($token[1], self::UNTRUSTED_VARS, true)) {
                return true;
            }

            if (
                in_array($token[0], [T_CONSTANT_ENCAPSED_STRING, T_ENCAPSED_AND_WHITESPACE], true)
                && stripos($token[1], 'php://input') !== false
            ) {
                return true;
            }
        }

        return false;
    }

    /**
     * @param list<string|array{0: int, 1: string, 2: int}> $tokens
     * @return array{0: int|null, 1: mixed}
     */
    private function nextSignificant(array $tokens, int $index): array
    {
        $count = count($tokens);
        for ($i = $index + 1; $i < $count; $i++) {
            if ($this->isTrivia($tokens[$i])) {
                continue;
            }
            return [$i, $tokens[$i]];
        }

        return [null, null];
    }

    /**
     * @param list<string|array{0: int, 1: string, 2: int}> $tokens
     * @return array{0: int|null, 1: mixed}
     */
    private function previousSignificant(array $tokens, int $index): array
    {
        for ($i = $index - 1; $i >= 0; $i--) {
            if ($this->isTrivia($tokens[$i])) {
                continue;
            }
            return [$i, $tokens[$i]];
        }

        return [null, null];
    }

    private function isTrivia(mixed $token): bool
    {
        return is_array($token) && in_array($token[0], [T_WHITESPACE, T_COMMENT, T_DOC_COMMENT], true);
    }
}
