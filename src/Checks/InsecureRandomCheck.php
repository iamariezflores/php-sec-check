<?php

namespace Aquilinoflores\PhpSecCheck\Checks;

use Aquilinoflores\PhpSecCheck\Issue;
use Aquilinoflores\PhpSecCheck\Scan\PhpFiles;

/**
 * rand(), mt_rand(), or uniqid() in the same statement as a token-like name.
 */
class InsecureRandomCheck implements CheckInterface
{
    public const RULE_ID = 'PSC-SRC-060';

    /** @var list<string> */
    private const WEAK = ['uniqid', 'rand', 'mt_rand', 'lcg_value'];

    public function run(string $projectRoot): array
    {
        $issues = [];
        foreach (PhpFiles::iterate($projectRoot) as $absolute => $relative) {
            $source = @file_get_contents($absolute);
            if ($source === false) {
                continue;
            }
            $tokens = @token_get_all($source);
            if (!is_array($tokens)) {
                continue;
            }

            $statement = [];
            $depth = 0;
            $flush = function () use (&$statement, &$issues, $relative): void {
                if ($statement === []) {
                    return;
                }
                $line = $this->tokenLine($statement);
                if ($line !== null) {
                    $issues[] = new Issue(
                        Issue::MEDIUM,
                        "A token is built with a predictable generator in {$relative}:{$line}.",
                        'InsecureRandomCheck',
                        self::RULE_ID,
                        Issue::HEURISTIC,
                        'Use random_bytes() or random_int() for tokens, CSRF values, and password resets.',
                        $relative,
                        $line,
                    );
                }
                $statement = [];
            };

            foreach ($tokens as $token) {
                $char = is_array($token) ? null : $token;
                if ($char === '(' || $char === '[') {
                    $depth++;
                } elseif ($char === ')' || $char === ']') {
                    $depth--;
                }
                $statement[] = $token;
                if ($char === ';' && $depth <= 0) {
                    $flush();
                }
            }
            $flush();
        }

        return $issues;
    }

    /**
     * @param list<string|array{0: int, 1: string, 2: int}> $statement
     */
    private function tokenLine(array $statement): ?int
    {
        $line = null;
        $named = false;
        $count = count($statement);
        for ($i = 0; $i < $count; $i++) {
            $token = $statement[$i];
            if (!is_array($token)) {
                continue;
            }
            if ($token[0] === T_STRING && in_array(strtolower($token[1]), self::WEAK, true)) {
                $next = $this->next($statement, $i);
                if ($next === '(') {
                    $line = $token[2];
                }
            }
            if ($token[0] === T_VARIABLE || $token[0] === T_CONSTANT_ENCAPSED_STRING) {
                if (preg_match('/token|csrf|nonce|reset|remember/i', $token[1]) === 1) {
                    $named = true;
                }
            }
        }

        return $named ? $line : null;
    }

    /**
     * @param list<string|array{0: int, 1: string, 2: int}> $tokens
     */
    private function next(array $tokens, int $index): mixed
    {
        $count = count($tokens);
        for ($i = $index + 1; $i < $count; $i++) {
            if (is_array($tokens[$i]) && in_array($tokens[$i][0], [T_WHITESPACE, T_COMMENT, T_DOC_COMMENT], true)) {
                continue;
            }
            return $tokens[$i];
        }

        return null;
    }
}
