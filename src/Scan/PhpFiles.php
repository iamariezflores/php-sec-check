<?php

namespace Aquilinoflores\PhpSecCheck\Scan;

use RecursiveDirectoryIterator;
use RecursiveIteratorIterator;
use SplFileInfo;

/**
 * Application PHP files. vendor, node_modules, and .git contents are skipped.
 */
final class PhpFiles
{
    /** @var list<string> */
    private const SKIP = [
        '/vendor/',
        '/node_modules/',
        '/.git/',
    ];

    /**
     * @return iterable<string, string> absolute path => relative path
     */
    public static function iterate(string $projectRoot): iterable
    {
        if ($projectRoot === '' || !is_dir($projectRoot)) {
            return;
        }

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
            if (self::skipped($relative)) {
                continue;
            }

            yield $absolute => $relative;
        }
    }

    public static function skipped(string $relative): bool
    {
        $haystack = '/' . str_replace('\\', '/', $relative);
        foreach (self::SKIP as $fragment) {
            if (str_contains($haystack, $fragment) || str_starts_with($relative, ltrim($fragment, '/'))) {
                return true;
            }
        }

        return false;
    }
}
