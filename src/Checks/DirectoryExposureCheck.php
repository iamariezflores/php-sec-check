<?php

namespace Aquilinoflores\PhpSecCheck\Checks;

use Aquilinoflores\PhpSecCheck\Git\GitStatus;
use Aquilinoflores\PhpSecCheck\Git\GitWorkingTree;
use Aquilinoflores\PhpSecCheck\Issue;
use Aquilinoflores\PhpSecCheck\Output;
use FilesystemIterator;
use RecursiveCallbackFilterIterator;
use RecursiveDirectoryIterator;
use RecursiveIteratorIterator;
use SplFileInfo;

/**
 * Flags sensitive files and directories sitting in the document root.
 *
 * This is not VendorCheck (gitignore of project-root vendor/) and not
 * EnvCredentialsCheck (leaked .env files). A path is a finding because a
 * web server can serve it, not because .gitignore lists or omits it.
 */
class DirectoryExposureCheck implements CheckInterface
{
    /**
     * Immediate child directories of the document root that must not be public.
     * Laravel `public/storage` is a symlink and is skipped separately.
     *
     * @var array<string, string> basename => severity
     */
    private const SENSITIVE_DIRECTORIES = [
        '.git'    => Issue::CRITICAL,
        'vendor'  => Issue::CRITICAL,
        'storage' => Issue::CRITICAL,
        'backup'  => Issue::CRITICAL,
        'backups' => Issue::CRITICAL,
        'dumps'   => Issue::CRITICAL,
        'dump'    => Issue::CRITICAL,
    ];

    public function __construct(private readonly ?GitStatus $git = null) {}

    public function run(string $projectRoot): array
    {
        $issues = [];

        echo "[DIRECTORY EXPOSURE]\n";

        if ($projectRoot === '' || !is_dir($projectRoot)) {
            Output::info('No project root to scan for exposed directories.');
            echo "\n";
            return $issues;
        }

        $docRoots = $this->documentRoots($projectRoot);
        if ($docRoots === []) {
            Output::info('No document root detected (no public/ directory and no project-root index.php).');
            echo "\n";
            return $issues;
        }

        $git = $this->git ?? new GitWorkingTree($projectRoot);

        foreach ($docRoots as $relative => $absolute) {
            $this->scanDocumentRoot($relative, $absolute, $git, $issues);
        }

        if ($issues === []) {
            Output::ok('No sensitive files or directories found in the document root.');
        }

        echo "\n";
        return $issues;
    }

    /**
     * @return array<string, string> project-relative docroot => absolute path
     */
    private function documentRoots(string $projectRoot): array
    {
        $root    = rtrim(str_replace('\\', '/', $projectRoot), '/');
        $public  = $root . '/public';
        $roots   = [];

        if (is_dir($public)) {
            $roots['public'] = $public;
        }

        $publicIndex = is_file($public . '/index.php');
        $rootIndex   = is_file($root . '/index.php');

        if ($rootIndex && !$publicIndex) {
            $roots[''] = $root;
        }

        return $roots;
    }

    /**
     * @param list<Issue> $issues
     */
    private function scanDocumentRoot(string $relativeDocRoot, string $absoluteDocRoot, GitStatus $git, array &$issues): void
    {
        $prefix = $relativeDocRoot === '' ? '' : $relativeDocRoot . '/';

        foreach (self::SENSITIVE_DIRECTORIES as $name => $severity) {
            $absolute = $absoluteDocRoot . '/' . $name;
            if (!$this->existsOnDisk($absolute)) {
                continue;
            }
            if (is_link($absolute)) {
                continue;
            }

            $this->add(
                $issues,
                $git,
                $prefix . $name,
                $severity,
                $this->directoryMessage($prefix . $name, $name)
            );
        }

        $this->scanFiles($relativeDocRoot, $absoluteDocRoot, $git, $issues);
    }

    /**
     * @param list<Issue> $issues
     */
    private function scanFiles(string $relativeDocRoot, string $absoluteDocRoot, GitStatus $git, array &$issues): void
    {
        $root   = rtrim(str_replace('\\', '/', $absoluteDocRoot), '/');
        $prefix = $relativeDocRoot === '' ? '' : $relativeDocRoot . '/';

        $inner = new RecursiveDirectoryIterator(
            $absoluteDocRoot,
            FilesystemIterator::SKIP_DOTS
        );
        $filter = new RecursiveCallbackFilterIterator(
            $inner,
            function (SplFileInfo $current, $key, $iterator): bool {
                if ($current->isLink()) {
                    return false;
                }
                if ($iterator->hasChildren() && isset(self::SENSITIVE_DIRECTORIES[$current->getFilename()])) {
                    return false;
                }

                return true;
            }
        );
        $iterator = new RecursiveIteratorIterator($filter);

        /** @var SplFileInfo $file */
        foreach ($iterator as $file) {
            if (!$file->isFile()) {
                continue;
            }

            $absolute = str_replace('\\', '/', $file->getPathname());
            if ($this->isUnderSymlink($absolute, $root)) {
                continue;
            }

            $fromDocRoot = ltrim(substr($absolute, strlen($root)), '/');
            if ($fromDocRoot === '') {
                continue;
            }

            if ($this->shouldSkipFile($fromDocRoot)) {
                continue;
            }

            $kind = $this->fileKind($fromDocRoot);
            if ($kind === null) {
                continue;
            }

            $relative = $prefix . $fromDocRoot;
            [$severity, $message] = $this->fileFinding($relative, $kind);
            $this->add($issues, $git, $relative, $severity, $message);
        }
    }

    private function existsOnDisk(string $path): bool
    {
        return is_dir($path) || is_file($path);
    }

    private function shouldSkipFile(string $fromDocRoot): bool
    {
        $normalized = '/' . str_replace('\\', '/', $fromDocRoot);
        foreach (['/.git/', '/vendor/'] as $fragment) {
            if (str_contains($normalized, $fragment) || str_starts_with($normalized, $fragment)) {
                return true;
            }
        }

        $base = basename($fromDocRoot);
        if ($base === '.env' || str_starts_with($base, '.env.')) {
            return true;
        }

        return false;
    }

    private function isUnderSymlink(string $absolute, string $docRoot): bool
    {
        $cursor = $absolute;
        while ($cursor !== $docRoot && strlen($cursor) > strlen($docRoot)) {
            if (is_link($cursor)) {
                return true;
            }
            $parent = dirname($cursor);
            if ($parent === $cursor) {
                break;
            }
            $cursor = str_replace('\\', '/', $parent);
        }

        return false;
    }

    /**
     * @return null|'phpinfo'|'sql'|'log'|'composer'|'htaccess-backup'
     */
    private function fileKind(string $fromDocRoot): ?string
    {
        $base = strtolower(basename($fromDocRoot));

        if ($base === 'phpinfo.php') {
            return 'phpinfo';
        }
        if ($base === 'composer.json' || $base === 'composer.lock') {
            return 'composer';
        }
        if ($this->isHtaccessBackup($base)) {
            return 'htaccess-backup';
        }

        $extension = strtolower(pathinfo($base, PATHINFO_EXTENSION));
        if ($extension === 'sql') {
            return 'sql';
        }
        if ($extension === 'log') {
            return 'log';
        }

        return null;
    }

    private function isHtaccessBackup(string $basename): bool
    {
        return (bool) preg_match('/^\.?htaccess(\.(bak|old|orig|copy|backup|txt)|~)$/', $basename);
    }

    private function directoryMessage(string $relative, string $basename): string
    {
        return match ($basename) {
            '.git' => "{$relative} is inside the document root and can be downloaded. Move repository metadata out of the web root.",
            'vendor' => "{$relative} is inside the document root and can be downloaded. Application dependencies must not be web-accessible.",
            'storage' => "{$relative} is inside the document root. Application storage (logs, sessions, uploads) must not be web-accessible.",
            default => "{$relative} is inside the document root. Backup and dump directories must not be web-accessible.",
        };
    }

    /**
     * @return array{0: string, 1: string} severity, message
     */
    private function fileFinding(string $relative, string $kind): array
    {
        return match ($kind) {
            'phpinfo' => [
                Issue::CRITICAL,
                "{$relative} is web-accessible and exposes PHP configuration.",
            ],
            'sql' => [
                Issue::CRITICAL,
                "{$relative} is inside the document root. Database dumps must not be web-accessible.",
            ],
            'log' => [
                Issue::WARN,
                "{$relative} is inside the document root. Log files must not be web-accessible.",
            ],
            'composer' => [
                Issue::WARN,
                "{$relative} is inside the document root and discloses dependency names.",
            ],
            'htaccess-backup' => [
                Issue::WARN,
                "{$relative} is inside the document root. Backup copies of .htaccess can leak rewrite and access rules.",
            ],
            default => [
                Issue::WARN,
                "{$relative} is inside the document root and should not be web-accessible.",
            ],
        };
    }

    /**
     * @param list<Issue> $issues
     */
    private function add(array &$issues, GitStatus $git, string $relative, string $severity, string $message): void
    {
        if ($git->isRepository() && $git->isTracked($relative)) {
            $message .= ' It is also tracked by git.';
            $severity = Issue::CRITICAL;
        } elseif ($git->isRepository() && $git->isIgnoredByRules($relative)) {
            $message .= ' Git ignore rules do not stop a web server from serving this path.';
        }

        $issue = new Issue($severity, $message, 'DirectoryExposureCheck');
        $issues[] = $issue;
        Output::issue($issue);
    }
}
