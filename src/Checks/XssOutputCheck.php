<?php

namespace Aquilinoflores\PhpSecCheck\Checks;

use Aquilinoflores\PhpSecCheck\Issue;
use Aquilinoflores\PhpSecCheck\Output;
use RecursiveDirectoryIterator;
use RecursiveIteratorIterator;
use SplFileInfo;

/**
 * First-pass XSS indicators: unescaped HTML output of untrusted input.
 *
 * This is a token/Blade scan, not a DOM XSS engine. Nested assignments
 * are not followed. JSON responses (Content-Type: application/json) are
 * out of scope for this pass.
 */
class XssOutputCheck implements CheckInterface
{
    private const SKIP_DIR_FRAGMENTS = [
        '/vendor/',
        '/node_modules/',
        '/.git/',
        '/storage/framework/',
        '/bootstrap/cache/',
    ];

    /** @var list<string> */
    private const UNTRUSTED = ['$_GET', '$_POST', '$_REQUEST', '$_COOKIE'];

    /** @var list<string> */
    private const ESCAPE_FUNCS = ['htmlspecialchars', 'htmlentities', 'e'];

    /** @var list<string> */
    private const JSON_FUNCS = ['json_encode'];

    public function run(string $projectRoot): array
    {
        $issues = [];

        echo "[XSS OUTPUT]\n";

        if ($projectRoot === '' || !is_dir($projectRoot)) {
            Output::info('No project root to scan for XSS output.');
            echo "\n";
            return $issues;
        }

        foreach ($this->phpFiles($projectRoot) as $absolute => $relative) {
            $source = @file_get_contents($absolute);
            if ($source === false) {
                continue;
            }

            $jsonApi = $this->looksLikeJsonResponse($source);
            if (!$jsonApi) {
                $this->scanPhpOutput($source, $relative, $issues);
            }

            $this->scanBladeRaw($source, $relative, $issues);
        }

        if ($issues === []) {
            Output::ok('No unescaped HTML output of untrusted input detected.');
        }

        echo "\n";
        return $issues;
    }

    /**
     * @param list<Issue> $issues
     */
    private function scanPhpOutput(string $source, string $relative, array &$issues): void
    {
        $tokens = @token_get_all($source);
        if (!is_array($tokens) || $tokens === []) {
            return;
        }

        $count = count($tokens);
        for ($i = 0; $i < $count; $i++) {
            $token = $tokens[$i];
            if (!is_array($token)) {
                continue;
            }

            $kind = match ($token[0]) {
                T_ECHO              => 'echo',
                T_PRINT             => 'print',
                T_OPEN_TAG_WITH_ECHO => '<?=',
                default             => null,
            };
            if ($kind === null) {
                continue;
            }

            [$expr, $end] = $this->captureExpression($tokens, $i + 1);
            $i = $end;

            if (!$this->hasUnescapedUntrusted($expr)) {
                continue;
            }

            $this->add(
                $issues,
                Issue::CRITICAL,
                "{$kind} in {$relative}:{$token[2]} outputs untrusted input without HTML escaping."
            );
        }
    }

    /**
     * @param list<Issue> $issues
     */
    private function scanBladeRaw(string $source, string $relative, array &$issues): void
    {
        if (!preg_match_all('/\{!!(.*?)!!\}/s', $source, $matches, PREG_OFFSET_CAPTURE)) {
            return;
        }

        foreach ($matches[0] as $index => $full) {
            $inner  = $matches[1][$index][0];
            $line   = substr_count(substr($source, 0, $full[1]), "\n") + 1;
            $expr   = $this->tokensOfEchoSnippet($inner);

            if ($this->hasUnescapedUntrusted($expr)) {
                $this->add(
                    $issues,
                    Issue::CRITICAL,
                    "Blade {!! !!} in {$relative}:{$line} outputs untrusted input without escaping."
                );
                continue;
            }

            if ($this->containsUntrustedText($inner)) {
                continue;
            }

            $this->add(
                $issues,
                Issue::WARN,
                "Blade {!! !!} in {$relative}:{$line} is unescaped HTML output."
            );
        }
    }

    /**
     * @param list<string|array{0: int, 1: string, 2: int}> $tokens
     * @return array{0: list<string|array{0: int, 1: string, 2: int}>, 1: int}
     */
    private function captureExpression(array $tokens, int $start): array
    {
        $expr    = [];
        $paren   = 0;
        $bracket = 0;
        $brace   = 0;
        $count   = count($tokens);
        $end     = $start - 1;

        for ($i = $start; $i < $count; $i++) {
            $end   = $i;
            $token = $tokens[$i];
            $char  = is_array($token) ? null : $token;

            if (is_array($token) && $token[0] === T_CLOSE_TAG && $paren === 0 && $bracket === 0 && $brace === 0) {
                $end = $i;
                break;
            }

            if ($char === ';' && $paren === 0 && $bracket === 0 && $brace === 0) {
                break;
            }

            if ($char === '(') {
                $paren++;
            } elseif ($char === ')') {
                $paren--;
            } elseif ($char === '[') {
                $bracket++;
            } elseif ($char === ']') {
                $bracket--;
            } elseif ($char === '{') {
                $brace++;
            } elseif ($char === '}') {
                $brace--;
            }

            $expr[] = $token;
        }

        return [$expr, $end];
    }

    /**
     * @return list<string|array{0: int, 1: string, 2: int}>
     */
    private function tokensOfEchoSnippet(string $inner): array
    {
        $tokens = @token_get_all('<?php echo ' . $inner . ';');
        if (!is_array($tokens)) {
            return [];
        }

        foreach ($tokens as $i => $token) {
            if (is_array($token) && $token[0] === T_ECHO) {
                [$expr] = $this->captureExpression($tokens, $i + 1);
                return $expr;
            }
        }

        return [];
    }

    /**
     * @param list<string|array{0: int, 1: string, 2: int}> $tokens
     */
    private function hasUnescapedUntrusted(array $tokens): bool
    {
        $pending    = null;
        $stack      = [];
        $unescaped  = false;
        $untrusted  = false;
        $count      = count($tokens);

        for ($i = 0; $i < $count; $i++) {
            $token = $tokens[$i];

            if ($this->isTrivia($token)) {
                continue;
            }

            if (is_array($token) && $token[0] === T_VARIABLE && in_array($token[1], self::UNTRUSTED, true)) {
                $untrusted = true;
                $wrapper   = $this->innermostWrapper($stack);
                if ($wrapper === null || (
                    !in_array($wrapper, self::ESCAPE_FUNCS, true)
                    && !in_array($wrapper, self::JSON_FUNCS, true)
                )) {
                    $unescaped = true;
                }
            }

            $char = is_array($token) ? null : $token;

            if ($char === '(') {
                $stack[]  = $pending;
                $pending  = null;
                continue;
            }

            if ($char === ')') {
                array_pop($stack);
                $pending = null;
                continue;
            }

            if (is_array($token)) {
                $name = $this->functionName($token);
                if ($name !== null && !$this->isMethodCall($tokens, $i)) {
                    $pending = $name;
                    continue;
                }
            }

            $pending = null;
        }

        return $untrusted && $unescaped;
    }

    /**
     * @param list<string|null> $stack
     */
    private function innermostWrapper(array $stack): ?string
    {
        for ($i = count($stack) - 1; $i >= 0; $i--) {
            if ($stack[$i] !== null && $stack[$i] !== '') {
                return $stack[$i];
            }
        }

        return null;
    }

    /**
     * @param array{0: int, 1: string, 2: int} $token
     */
    private function functionName(array $token): ?string
    {
        if ($token[0] === T_STRING) {
            return strtolower($token[1]);
        }

        if ($token[0] === T_NAME_FULLY_QUALIFIED) {
            $parts = explode('\\', ltrim($token[1], '\\'));

            return strtolower((string) end($parts));
        }

        return null;
    }

    /**
     * @param list<string|array{0: int, 1: string, 2: int}> $tokens
     */
    private function isMethodCall(array $tokens, int $index): bool
    {
        for ($i = $index - 1; $i >= 0; $i--) {
            if ($this->isTrivia($tokens[$i])) {
                continue;
            }

            $prev = $tokens[$i];
            if (!is_array($prev)) {
                return false;
            }

            return in_array($prev[0], [
                T_OBJECT_OPERATOR,
                T_NULLSAFE_OBJECT_OPERATOR,
                T_DOUBLE_COLON,
            ], true);
        }

        return false;
    }

    private function looksLikeJsonResponse(string $source): bool
    {
        return (bool) preg_match(
            '/content-type["\'\s,:=]+application\/json/i',
            $source
        );
    }

    private function containsUntrustedText(string $source): bool
    {
        foreach (self::UNTRUSTED as $var) {
            if (str_contains($source, $var)) {
                return true;
            }
        }

        return false;
    }

    private function isTrivia(mixed $token): bool
    {
        return is_array($token) && in_array($token[0], [T_WHITESPACE, T_COMMENT, T_DOC_COMMENT], true);
    }

    /**
     * @return iterable<string, string>
     */
    private function phpFiles(string $projectRoot): iterable
    {
        $root = rtrim(str_replace('\\', '/', $projectRoot), '/');
        $iterator = new RecursiveIteratorIterator(
            new RecursiveDirectoryIterator($projectRoot, RecursiveDirectoryIterator::SKIP_DOTS)
        );

        /** @var SplFileInfo $file */
        foreach ($iterator as $file) {
            if (!$file->isFile() || strtolower($file->getExtension()) !== 'php') {
                continue;
            }

            $absolute = $file->getPathname();
            $relative = ltrim(str_replace('\\', '/', substr(str_replace('\\', '/', $absolute), strlen($root))), '/');
            if ($this->shouldSkip($relative)) {
                continue;
            }

            yield $absolute => $relative;
        }
    }

    private function shouldSkip(string $relative): bool
    {
        $haystack = '/' . $relative;
        foreach (self::SKIP_DIR_FRAGMENTS as $fragment) {
            if (str_contains($haystack, $fragment) || str_starts_with($relative, ltrim($fragment, '/'))) {
                return true;
            }
        }

        return false;
    }

    /**
     * @param list<Issue> $issues
     */
    private function add(array &$issues, string $severity, string $message): void
    {
        $issue = new Issue($severity, $message, 'XssOutputCheck');
        $issues[] = $issue;
        Output::issue($issue);
    }
}
