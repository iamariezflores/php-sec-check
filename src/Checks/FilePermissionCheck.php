<?php

namespace Aquilinoflores\PhpSecCheck\Checks;

use Aquilinoflores\PhpSecCheck\Issue;
use Aquilinoflores\PhpSecCheck\Scan\ScanContext;
use Aquilinoflores\PhpSecCheck\Scan\TargetLayout;
use RecursiveDirectoryIterator;
use RecursiveIteratorIterator;
use SplFileInfo;

/**
 * World-writable paths in a document root.
 * Meaningful on the server that serves the files. Git checkouts and Windows
 * do not preserve the modes this check is about, so those scans stay quiet.
 */
class FilePermissionCheck implements CheckInterface
{
    public const RULE_ID = 'PSC-FILE-020';

    public function run(string $projectRoot): array
    {
        if (PHP_OS_FAMILY === 'Windows' || ScanContext::profile() !== 'host' || $projectRoot === '' || !is_dir($projectRoot)) {
            return [];
        }

        $issues = [];
        foreach (TargetLayout::documentRoots($projectRoot) as $relative => $absolute) {
            if (!is_dir($absolute)) {
                continue;
            }
            $iterator = new RecursiveIteratorIterator(
                new RecursiveDirectoryIterator($absolute, RecursiveDirectoryIterator::SKIP_DOTS)
            );
            /** @var SplFileInfo $file */
            foreach ($iterator as $file) {
                if (!$file->isFile()) {
                    continue;
                }
                $mode = fileperms($file->getPathname());
                if ($mode === false || ($mode & 0002) === 0) {
                    continue;
                }
                $path = $file->getPathname();
                $root = rtrim(str_replace('\\', '/', $projectRoot), '/');
                $rel = ltrim(str_replace('\\', '/', substr(str_replace('\\', '/', $path), strlen($root))), '/');
                $issues[] = new Issue(
                    Issue::HIGH,
                    "{$rel} is world-writable.",
                    'FilePermissionCheck',
                    self::RULE_ID,
                    Issue::CONFIRMED,
                    'Remove the write bit for other users. Run this profile on the host that serves the files.',
                    $rel,
                    null,
                );
            }
            unset($relative);
        }

        return $issues;
    }
}
