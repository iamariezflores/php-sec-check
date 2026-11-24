<?php

namespace Aquilinoflores\PhpSecCheck\Php;

use Aquilinoflores\PhpSecCheck\Scan\PhpFiles;
use RecursiveDirectoryIterator;
use RecursiveIteratorIterator;
use SplFileInfo;

/**
 * PHP settings written into the target application.
 *
 * The scanner process ini is not consulted. A setting that the project
 * never writes is absent, not assumed from the machine running the scan.
 */
final class ProjectPhpSettings
{
    /** @param list<ProjectDirective> $directives */
    private function __construct(private readonly array $directives) {}

    public static function load(string $projectRoot): self
    {
        if ($projectRoot === '' || !is_dir($projectRoot)) {
            return new self([]);
        }

        $found = [];
        $root = rtrim(str_replace('\\', '/', $projectRoot), '/');
        $iterator = new RecursiveIteratorIterator(
            new RecursiveDirectoryIterator($projectRoot, RecursiveDirectoryIterator::SKIP_DOTS)
        );

        /** @var SplFileInfo $file */
        foreach ($iterator as $file) {
            if (!$file->isFile()) {
                continue;
            }

            $absolute = $file->getPathname();
            $relative = ltrim(str_replace('\\', '/', substr(str_replace('\\', '/', $absolute), strlen($root))), '/');
            if (PhpFiles::skipped($relative)) {
                continue;
            }

            $base = strtolower($file->getFilename());
            if ($base === '.user.ini' || $base === 'php.ini') {
                self::parseIniFile($absolute, $relative, $found);
                continue;
            }

            if ($base === '.htaccess') {
                self::parseHtaccess($absolute, $relative, $found);
            }
        }

        foreach (PhpFiles::iterate($projectRoot) as $absolute => $relative) {
            $source = @file_get_contents($absolute);
            if ($source === false || strlen($source) > 1048576) {
                continue;
            }
            self::parseIniSet($source, $relative, $found);
        }

        return new self($found);
    }

    /**
     * @return list<ProjectDirective>
     */
    public function directives(string $key): array
    {
        $key = strtolower($key);
        $matched = [];
        foreach ($this->directives as $directive) {
            if ($directive->key === $key) {
                $matched[] = $directive;
            }
        }

        return $matched;
    }

    public function has(string $key): bool
    {
        return $this->directives($key) !== [];
    }

    /**
     * @param list<ProjectDirective> $found
     */
    private static function parseIniFile(string $absolute, string $relative, array &$found): void
    {
        $contents = @file_get_contents($absolute);
        if ($contents === false) {
            return;
        }

        $lineNo = 0;
        foreach (preg_split('/\r\n|\n|\r/', $contents) ?: [] as $line) {
            $lineNo++;
            $trimmed = trim($line);
            if ($trimmed === '' || str_starts_with($trimmed, ';') || str_starts_with($trimmed, '#')) {
                continue;
            }
            if (!preg_match('/^([A-Za-z0-9_.]+)\s*=\s*(.*)$/', $trimmed, $m)) {
                continue;
            }
            $found[] = new ProjectDirective(strtolower($m[1]), trim($m[2]), $relative, $lineNo);
        }
    }

    /**
     * @param list<ProjectDirective> $found
     */
    private static function parseHtaccess(string $absolute, string $relative, array &$found): void
    {
        $contents = @file_get_contents($absolute);
        if ($contents === false) {
            return;
        }

        $lineNo = 0;
        foreach (preg_split('/\r\n|\n|\r/', $contents) ?: [] as $line) {
            $lineNo++;
            if (!preg_match('/^\s*php_(?:admin_)?(?:flag|value)\s+(\S+)\s+(\S+)/i', $line, $m)) {
                continue;
            }
            $found[] = new ProjectDirective(strtolower($m[1]), $m[2], $relative, $lineNo);
        }
    }

    /**
     * @param list<ProjectDirective> $found
     */
    private static function parseIniSet(string $source, string $relative, array &$found): void
    {
        $tokens = @token_get_all($source);
        if (!is_array($tokens)) {
            return;
        }

        $count = count($tokens);
        for ($i = 0; $i < $count; $i++) {
            $token = $tokens[$i];
            if (!is_array($token) || $token[0] !== T_STRING) {
                continue;
            }
            if (!in_array(strtolower($token[1]), ['ini_set', 'ini_alter'], true)) {
                continue;
            }

            $previous = self::previousSignificant($tokens, $i);
            if (is_array($previous) && in_array($previous[0], [T_OBJECT_OPERATOR, T_NULLSAFE_OBJECT_OPERATOR, T_DOUBLE_COLON, T_FUNCTION, T_NEW], true)) {
                continue;
            }

            [$open, $next] = self::nextSignificant($tokens, $i);
            if ($next !== '(' || $open === null) {
                continue;
            }

            $args = self::argumentLists($tokens, $open);
            if (count($args) < 2) {
                continue;
            }

            $key = self::literal($args[0]);
            $value = self::literal($args[1]);
            if ($key === null || $value === null) {
                continue;
            }

            $found[] = new ProjectDirective(strtolower($key), $value, $relative, $token[2]);
        }
    }

    /**
     * @param list<string|array{0: int, 1: string, 2: int}> $tokens
     * @return list<list<string|array{0: int, 1: string, 2: int}>>
     */
    private static function argumentLists(array $tokens, int $openIndex): array
    {
        $args = [];
        $current = [];
        $depth = 0;
        $count = count($tokens);

        for ($i = $openIndex; $i < $count; $i++) {
            $token = $tokens[$i];
            $char = is_array($token) ? null : $token;
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

            if ($depth === 1 && $char === ',') {
                $args[] = $current;
                $current = [];
                continue;
            }

            if ($depth >= 1) {
                $current[] = $token;
            }
        }

        if ($current !== []) {
            $args[] = $current;
        }

        return $args;
    }

    /**
     * @param list<string|array{0: int, 1: string, 2: int}> $tokens
     */
    private static function literal(array $tokens): ?string
    {
        $significant = [];
        foreach ($tokens as $token) {
            if (is_array($token) && in_array($token[0], [T_WHITESPACE, T_COMMENT, T_DOC_COMMENT], true)) {
                continue;
            }
            $significant[] = $token;
        }

        if (count($significant) !== 1) {
            return null;
        }

        $token = $significant[0];
        if (!is_array($token)) {
            return null;
        }

        if ($token[0] === T_CONSTANT_ENCAPSED_STRING) {
            return stripcslashes(substr($token[1], 1, -1));
        }

        if ($token[0] === T_LNUMBER) {
            return $token[1];
        }

        if ($token[0] === T_STRING && in_array(strtolower($token[1]), ['true', 'false', 'on', 'off', 'null'], true)) {
            return $token[1];
        }

        return null;
    }

    /**
     * @param list<string|array{0: int, 1: string, 2: int}> $tokens
     * @return array{0: int|null, 1: mixed}
     */
    private static function nextSignificant(array $tokens, int $index): array
    {
        $count = count($tokens);
        for ($i = $index + 1; $i < $count; $i++) {
            if (is_array($tokens[$i]) && in_array($tokens[$i][0], [T_WHITESPACE, T_COMMENT, T_DOC_COMMENT], true)) {
                continue;
            }
            return [$i, $tokens[$i]];
        }

        return [null, null];
    }

    /**
     * @param list<string|array{0: int, 1: string, 2: int}> $tokens
     */
    private static function previousSignificant(array $tokens, int $index): mixed
    {
        for ($i = $index - 1; $i >= 0; $i--) {
            if (is_array($tokens[$i]) && in_array($tokens[$i][0], [T_WHITESPACE, T_COMMENT, T_DOC_COMMENT], true)) {
                continue;
            }
            return $tokens[$i];
        }

        return null;
    }
}
