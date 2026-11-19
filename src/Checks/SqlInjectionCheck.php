<?php

namespace Aquilinoflores\PhpSecCheck\Checks;

use Aquilinoflores\PhpSecCheck\Issue;
use Aquilinoflores\PhpSecCheck\Output;
use Aquilinoflores\PhpSecCheck\Scan\PhpFunctionCallScanner;
use RecursiveDirectoryIterator;
use RecursiveIteratorIterator;
use SplFileInfo;

/**
 * First-pass SQL injection indicators: concatenated / interpolated queries
 * with untrusted input.
 *
 * This is not a SQL parser. Nested assignments are out of scope, same as
 * UnsafeFunctionUsageCheck. Prepared statements and bound parameters are clean.
 */
class SqlInjectionCheck implements CheckInterface
{
    private const SKIP_DIR_FRAGMENTS = [
        '/vendor/',
        '/node_modules/',
        '/.git/',
        '/storage/framework/',
        '/bootstrap/cache/',
    ];

    /** @var list<string> */
    private const UNTRUSTED = [
        '$_GET', '$_POST', '$_REQUEST', '$_COOKIE', '$_FILES', '$_SERVER', '$argv',
    ];

    /**
     * Procedural query helpers. Value is the SQL argument index, or -1 to
     * use the last argument (pg_query).
     *
     * @var array<string, int>
     */
    private const PROCEDURAL = [
        'mysqli_query'       => 1,
        'mysql_query'        => 0,
        'mysqli_real_query'  => 1,
        'mysqli_multi_query' => 1,
        'pg_query'           => -1,
        'sqlite_query'       => 1,
    ];

    /**
     * Method / static names whose first argument is SQL.
     *
     * @var list<string>
     */
    private const SQL_METHODS = [
        'query', 'exec', 'prepare', 'statement', 'unprepared', 'raw',
        'whereraw', 'orwhereraw', 'havingraw', 'selectraw',
        'orderbyraw', 'groupbyraw', 'fromraw',
        'select', 'insert', 'update', 'delete',
    ];

    /** @var list<string> */
    private const BARE_UNTRUSTED_METHODS = [
        'query', 'exec', 'prepare', 'statement', 'unprepared', 'raw',
        'whereraw', 'orwhereraw', 'havingraw', 'selectraw',
        'orderbyraw', 'groupbyraw', 'fromraw',
    ];

    public function __construct(private readonly ?PhpFunctionCallScanner $scanner = null) {}

    public function run(string $projectRoot): array
    {
        $issues = [];

        echo "[SQL INJECTION]\n";

        if ($projectRoot === '' || !is_dir($projectRoot)) {
            Output::info('No project root to scan for SQL injection.');
            echo "\n";
            return $issues;
        }

        $scanner = $this->scanner ?? new PhpFunctionCallScanner();

        foreach ($this->phpFiles($projectRoot) as $absolute => $relative) {
            $source = @file_get_contents($absolute);
            if ($source === false) {
                continue;
            }

            $found = [];
            $this->scanConcatenatedSql($source, $relative, $found);
            $this->scanQueryCalls($scanner, $source, $relative, $found);

            foreach ($found as $issue) {
                $issues[] = $issue;
                Output::issue($issue);
            }
        }

        if ($issues === []) {
            Output::ok('No concatenated SQL with untrusted input detected.');
        }

        echo "\n";
        return $issues;
    }

    /**
     * @param array<int, Issue> $found
     */
    private function scanConcatenatedSql(string $source, string $relative, array &$found): void
    {
        $tokens = @token_get_all($source);
        if (!is_array($tokens) || $tokens === []) {
            return;
        }

        $count = count($tokens);
        for ($i = 0; $i < $count; $i++) {
            $token = $tokens[$i];

            if ($token === '"') {
                [$text, $end, $untrusted, $line] = $this->captureInterpolated($tokens, $i);
                $i = $end;
                if ($untrusted && $this->looksLikeSql($text)) {
                    $this->remember(
                        $found,
                        $line,
                        1,
                        "Concatenated SQL in {$relative}:{$line} uses untrusted input."
                    );
                }
                continue;
            }

            if (!is_array($token) || $token[0] !== T_CONSTANT_ENCAPSED_STRING) {
                continue;
            }

            if (!$this->looksLikeSql($token[1])) {
                continue;
            }

            if ($this->concatChainHasUntrusted($tokens, $i)) {
                $this->remember(
                    $found,
                    $token[2],
                    1,
                    "Concatenated SQL in {$relative}:{$token[2]} uses untrusted input."
                );
            }
        }
    }

    /**
     * @param array<int, Issue> $found
     */
    private function scanQueryCalls(
        PhpFunctionCallScanner $scanner,
        string $source,
        string $relative,
        array &$found
    ): void {
        $wanted = array_values(array_unique(array_merge(
            array_keys(self::PROCEDURAL),
            self::SQL_METHODS
        )));

        foreach ($scanner->findCallsWithArguments($source, $wanted, true) as $call) {
            $name = $call['function'];
            $args = $call['arguments'];
            if ($args === []) {
                continue;
            }

            $index = $this->sqlArgumentIndex($name, $args);
            if (!isset($args[$index])) {
                continue;
            }

            $kind = $this->classifySqlArgument($args[$index]);
            if ($kind === 'clean') {
                continue;
            }

            if ($kind === 'bare' && !$this->bareUntrustedCounts($name, $source, $call['line'])) {
                continue;
            }

            $this->remember(
                $found,
                $call['line'],
                2,
                "{$name}() in {$relative}:{$call['line']} builds SQL from untrusted input."
            );
        }
    }

    /**
     * @param list<list<string|array{0: int, 1: string, 2: int}>> $args
     */
    private function sqlArgumentIndex(string $name, array $args): int
    {
        if (isset(self::PROCEDURAL[$name])) {
            $index = self::PROCEDURAL[$name];
            if ($index < 0) {
                return count($args) - 1;
            }
            if ($index >= count($args)) {
                return 0;
            }

            return $index;
        }

        return 0;
    }

    /**
     * @param list<string|array{0: int, 1: string, 2: int}> $tokens
     * @return 'unsafe'|'bare'|'clean'
     */
    private function classifySqlArgument(array $tokens): string
    {
        if ($this->firstSignificantIsArray($tokens)) {
            return 'clean';
        }

        $untrusted = $this->tokensHaveUntrusted($tokens);
        if (!$untrusted) {
            return 'clean';
        }

        if ($this->hasDotConcat($tokens) || $this->hasInterpolatedSql($tokens)) {
            return 'unsafe';
        }

        if ($this->isBareUntrusted($tokens)) {
            return 'bare';
        }

        if ($this->tokensLookLikeSql($tokens)) {
            return 'unsafe';
        }

        return 'clean';
    }

    private function bareUntrustedCounts(string $name, string $source, int $line): bool
    {
        if (in_array($name, self::BARE_UNTRUSTED_METHODS, true) || isset(self::PROCEDURAL[$name])) {
            return true;
        }

        if (in_array($name, ['select', 'insert', 'update', 'delete'], true)) {
            return $this->callOnLineIsDbFacade($source, $line, $name);
        }

        return false;
    }

    private function callOnLineIsDbFacade(string $source, int $line, string $name): bool
    {
        $tokens = @token_get_all($source);
        if (!is_array($tokens)) {
            return false;
        }

        foreach ($tokens as $i => $token) {
            if (!is_array($token) || $token[2] !== $line) {
                continue;
            }
            $callable = $this->callableName($token);
            if ($callable !== $name) {
                continue;
            }

            $beforeColon = null;
            for ($j = $i - 1; $j >= 0; $j--) {
                if ($this->isTrivia($tokens[$j])) {
                    continue;
                }
                if (is_array($tokens[$j]) && $tokens[$j][0] === T_DOUBLE_COLON) {
                    for ($k = $j - 1; $k >= 0; $k--) {
                        if ($this->isTrivia($tokens[$k])) {
                            continue;
                        }
                        $beforeColon = $tokens[$k];
                        break 2;
                    }
                }
                break;
            }

            if (is_array($beforeColon) && strtolower($beforeColon[1] ?? '') === 'db') {
                return true;
            }
            if (is_array($beforeColon) && $beforeColon[0] === T_NAME_FULLY_QUALIFIED
                && str_ends_with(strtolower($beforeColon[1]), '\\db')) {
                return true;
            }
        }

        return false;
    }

    /**
     * @param list<string|array{0: int, 1: string, 2: int}> $tokens
     */
    private function concatChainHasUntrusted(array $tokens, int $stringIndex): bool
    {
        $i = $this->skipTriviaForward($tokens, $stringIndex + 1);
        while ($i < count($tokens) && $tokens[$i] === '.') {
            [$i, $untrusted] = $this->skipOperandForward($tokens, $i + 1);
            if ($untrusted) {
                return true;
            }
            $i = $this->skipTriviaForward($tokens, $i);
        }

        $i = $this->skipTriviaBackward($tokens, $stringIndex - 1);
        while ($i >= 0 && $tokens[$i] === '.') {
            [$i, $untrusted] = $this->skipOperandBackward($tokens, $i - 1);
            if ($untrusted) {
                return true;
            }
            $i = $this->skipTriviaBackward($tokens, $i);
        }

        return false;
    }

    /**
     * @param list<string|array{0: int, 1: string, 2: int}> $tokens
     * @return array{0: int, 1: bool} next index, saw untrusted
     */
    private function skipOperandForward(array $tokens, int $start): array
    {
        $i         = $this->skipTriviaForward($tokens, $start);
        $count     = count($tokens);
        $paren     = 0;
        $bracket   = 0;
        $brace     = 0;
        $untrusted = false;
        $started   = false;

        for (; $i < $count; $i++) {
            $token = $tokens[$i];
            if (!$started && $this->isTrivia($token)) {
                continue;
            }
            $started = true;
            $char    = is_array($token) ? null : $token;

            if ($this->isUntrustedToken($token)) {
                $untrusted = true;
            }

            if ($char === '(') {
                $paren++;
            } elseif ($char === ')') {
                if ($paren === 0 && $bracket === 0 && $brace === 0) {
                    break;
                }
                $paren--;
            } elseif ($char === '[') {
                $bracket++;
            } elseif ($char === ']') {
                if ($paren === 0 && $bracket === 0 && $brace === 0) {
                    break;
                }
                $bracket--;
            } elseif ($char === '{') {
                $brace++;
            } elseif ($char === '}') {
                if ($paren === 0 && $bracket === 0 && $brace === 0) {
                    break;
                }
                $brace--;
            } elseif (in_array($char, ['.', ',', ';'], true) && $paren === 0 && $bracket === 0 && $brace === 0) {
                break;
            }
        }

        return [$i, $untrusted];
    }

    /**
     * @param list<string|array{0: int, 1: string, 2: int}> $tokens
     * @return array{0: int, 1: bool} index of token before operand, saw untrusted
     */
    private function skipOperandBackward(array $tokens, int $start): array
    {
        $i         = $this->skipTriviaBackward($tokens, $start);
        $paren     = 0;
        $bracket   = 0;
        $brace     = 0;
        $untrusted = false;

        for (; $i >= 0; $i--) {
            $token = $tokens[$i];
            if ($this->isTrivia($token) && $paren === 0 && $bracket === 0 && $brace === 0) {
                continue;
            }
            $char = is_array($token) ? null : $token;

            if ($this->isUntrustedToken($token)) {
                $untrusted = true;
            }

            if ($char === ')') {
                $paren++;
            } elseif ($char === '(') {
                if ($paren === 0 && $bracket === 0 && $brace === 0) {
                    break;
                }
                $paren--;
            } elseif ($char === ']') {
                $bracket++;
            } elseif ($char === '[') {
                if ($paren === 0 && $bracket === 0 && $brace === 0) {
                    break;
                }
                $bracket--;
            } elseif ($char === '}') {
                $brace++;
            } elseif ($char === '{') {
                if ($paren === 0 && $bracket === 0 && $brace === 0) {
                    break;
                }
                $brace--;
            } elseif (in_array($char, ['.', ',', ';'], true) && $paren === 0 && $bracket === 0 && $brace === 0) {
                break;
            }
        }

        return [$i, $untrusted];
    }

    /**
     * @param list<string|array{0: int, 1: string, 2: int}> $tokens
     * @return array{0: string, 1: int, 2: bool, 3: int} text, end index, untrusted, line
     */
    private function captureInterpolated(array $tokens, int $openQuote): array
    {
        $text      = '';
        $untrusted = false;
        $line      = 1;
        $count     = count($tokens);
        $end       = $openQuote;

        for ($i = $openQuote + 1; $i < $count; $i++) {
            $end   = $i;
            $token = $tokens[$i];
            if ($token === '"') {
                break;
            }
            if (is_array($token)) {
                $text .= $token[1];
                $line  = $token[2];
                if ($this->isUntrustedToken($token)) {
                    $untrusted = true;
                }
            }
        }

        return [$text, $end, $untrusted, $line];
    }

    /**
     * @param list<string|array{0: int, 1: string, 2: int}> $tokens
     */
    private function tokensHaveUntrusted(array $tokens): bool
    {
        foreach ($tokens as $token) {
            if ($this->isUntrustedToken($token)) {
                return true;
            }
        }

        return false;
    }

    /**
     * @param list<string|array{0: int, 1: string, 2: int}> $tokens
     */
    private function hasDotConcat(array $tokens): bool
    {
        $paren = 0;
        $bracket = 0;
        foreach ($tokens as $token) {
            $char = is_array($token) ? null : $token;
            if ($char === '(') {
                $paren++;
            } elseif ($char === ')') {
                $paren--;
            } elseif ($char === '[') {
                $bracket++;
            } elseif ($char === ']') {
                $bracket--;
            } elseif ($char === '.' && $paren === 0 && $bracket === 0) {
                return true;
            }
        }

        return false;
    }

    /**
     * @param list<string|array{0: int, 1: string, 2: int}> $tokens
     */
    private function hasInterpolatedSql(array $tokens): bool
    {
        $count = count($tokens);
        for ($i = 0; $i < $count; $i++) {
            if ($tokens[$i] !== '"') {
                continue;
            }
            [$text, $end, $untrusted] = $this->captureInterpolated($tokens, $i);
            $i = $end;
            if ($untrusted && $this->looksLikeSql('"' . $text . '"')) {
                return true;
            }
        }

        return false;
    }

    /**
     * @param list<string|array{0: int, 1: string, 2: int}> $tokens
     */
    private function tokensLookLikeSql(array $tokens): bool
    {
        foreach ($tokens as $token) {
            if (is_array($token) && in_array($token[0], [T_CONSTANT_ENCAPSED_STRING, T_ENCAPSED_AND_WHITESPACE], true)
                && $this->looksLikeSql($token[1])) {
                return true;
            }
        }

        return false;
    }

    /**
     * @param list<string|array{0: int, 1: string, 2: int}> $tokens
     */
    private function isBareUntrusted(array $tokens): bool
    {
        $sawVar = false;
        foreach ($tokens as $token) {
            if ($this->isTrivia($token)) {
                continue;
            }
            if ($this->isUntrustedToken($token)) {
                $sawVar = true;
                continue;
            }
            $char = is_array($token) ? null : $token;
            if (in_array($char, ['[', ']', '(', ')'], true)) {
                continue;
            }
            if (is_array($token) && in_array($token[0], [T_CONSTANT_ENCAPSED_STRING, T_LNUMBER, T_DNUMBER], true)) {
                continue;
            }

            return false;
        }

        return $sawVar;
    }

    /**
     * @param list<string|array{0: int, 1: string, 2: int}> $tokens
     */
    private function firstSignificantIsArray(array $tokens): bool
    {
        foreach ($tokens as $token) {
            if ($this->isTrivia($token)) {
                continue;
            }
            if ($token === '[') {
                return true;
            }
            if (is_array($token) && $token[0] === T_ARRAY) {
                return true;
            }

            return false;
        }

        return false;
    }

    private function looksLikeSql(string $raw): bool
    {
        $s = trim($raw, " \t\n\r\0\x0B'\"");

        return (bool) preg_match(
            '/^(SELECT\b|INSERT\s+INTO\b|UPDATE\b|DELETE\s+FROM\b|REPLACE\b|DROP\s+(TABLE|DATABASE|INDEX)\b|ALTER\s+TABLE\b|CREATE\s+(TABLE|DATABASE|INDEX)\b|TRUNCATE\b|WITH\b|UNION\s+SELECT\b|CALL\b)/i',
            $s
        );
    }

    private function isUntrustedToken(mixed $token): bool
    {
        if (!is_array($token)) {
            return false;
        }

        if ($token[0] === T_VARIABLE && in_array($token[1], self::UNTRUSTED, true)) {
            return true;
        }

        return in_array($token[0], [T_CONSTANT_ENCAPSED_STRING, T_ENCAPSED_AND_WHITESPACE], true)
            && stripos($token[1], 'php://input') !== false;
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

            return strtolower((string) end($parts));
        }

        return null;
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

    /**
     * @param list<string|array{0: int, 1: string, 2: int}> $tokens
     */
    private function skipTriviaForward(array $tokens, int $i): int
    {
        $count = count($tokens);
        while ($i < $count && $this->isTrivia($tokens[$i])) {
            $i++;
        }

        return $i;
    }

    /**
     * @param list<string|array{0: int, 1: string, 2: int}> $tokens
     */
    private function skipTriviaBackward(array $tokens, int $i): int
    {
        while ($i >= 0 && $this->isTrivia($tokens[$i])) {
            $i--;
        }

        return $i;
    }

    private function isTrivia(mixed $token): bool
    {
        return is_array($token) && in_array($token[0], [T_WHITESPACE, T_COMMENT, T_DOC_COMMENT], true);
    }

    /**
     * @param array<int, Issue> $found
     */
    private function remember(array &$found, int $line, int $specificity, string $message): void
    {
        if (isset($found[$line]) && ($found[$line]->message !== $message)) {
            // Prefer query-call wording over a generic concat finding on the same line.
            if ($specificity < 2 && str_contains($found[$line]->message, '()')) {
                return;
            }
        }

        $found[$line] = new Issue(Issue::CRITICAL, $message, 'SqlInjectionCheck');
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
}
