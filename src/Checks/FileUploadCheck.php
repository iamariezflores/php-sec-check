<?php

namespace Aquilinoflores\PhpSecCheck\Checks;

use Aquilinoflores\PhpSecCheck\Issue;
use Aquilinoflores\PhpSecCheck\Output;
use Aquilinoflores\PhpSecCheck\Scan\PhpFunctionCallScanner;
use RecursiveDirectoryIterator;
use RecursiveIteratorIterator;
use SplFileInfo;

/**
 * First-pass upload handling: move_uploaded_file() destination heuristics.
 *
 * This is not a full upload pipeline or taint analyser. Nested assignments
 * are out of scope, same as UnsafeFunctionUsageCheck.
 */
class FileUploadCheck implements CheckInterface
{
    private const SKIP_DIR_FRAGMENTS = [
        '/vendor/',
        '/node_modules/',
        '/.git/',
        '/storage/framework/',
        '/bootstrap/cache/',
    ];

    public function __construct(private readonly ?PhpFunctionCallScanner $scanner = null) {}

    public function run(string $projectRoot): array
    {
        $issues = [];

        echo "[FILE UPLOAD]\n";

        if ($projectRoot === '' || !is_dir($projectRoot)) {
            Output::info('No project root to scan for file uploads.');
            echo "\n";
            return $issues;
        }

        $scanner = $this->scanner ?? new PhpFunctionCallScanner();

        foreach ($this->phpFiles($projectRoot) as $absolute => $relative) {
            $source = @file_get_contents($absolute);
            if ($source === false) {
                continue;
            }

            $allowList = $this->fileHasAllowList($source);

            foreach ($scanner->findCallsWithArguments($source, ['move_uploaded_file']) as $call) {
                if (count($call['arguments']) < 2) {
                    continue;
                }

                $dest = $this->tokensText($call['arguments'][1]);
                $finding = $this->classifyDestination($dest, $allowList);
                if ($finding === null) {
                    continue;
                }

                [$severity, $detail] = $finding;
                $this->add(
                    $issues,
                    $severity,
                    "move_uploaded_file() in {$relative}:{$call['line']} {$detail}"
                );
            }
        }

        if ($issues === []) {
            Output::ok('No unsafe move_uploaded_file() destinations detected.');
        }

        echo "\n";
        return $issues;
    }

    /**
     * @return null|array{0: string, 1: string} severity, message suffix
     */
    private function classifyDestination(string $dest, bool $allowList): ?array
    {
        $public      = $this->looksPublic($dest);
        $clientName  = $this->usesClientFilename($dest);
        $storage     = $this->looksStorage($dest);
        $generated   = $this->looksGenerated($dest);

        if ($public && $clientName) {
            return [
                Issue::CRITICAL,
                'writes the client filename into a web-accessible directory.',
            ];
        }

        if ($public) {
            return [
                Issue::CRITICAL,
                'writes the upload into a web-accessible directory.',
            ];
        }

        if ($clientName) {
            return [
                Issue::CRITICAL,
                'uses the client filename as the destination.',
            ];
        }

        if ($storage && $generated && $allowList) {
            return null;
        }

        if ($generated && $allowList && !$public) {
            return null;
        }

        if (!$allowList) {
            return [
                Issue::WARN,
                'has no extension or MIME allow-list.',
            ];
        }

        return null;
    }

    private function usesClientFilename(string $dest): bool
    {
        return (bool) preg_match(
            '/\$_FILES\s*\[.*?\]\s*\[\s*[\'"]name[\'"]\s*\]/s',
            $dest
        );
    }

    private function looksPublic(string $dest): bool
    {
        $normalized = str_replace('\\', '/', strtolower($dest));

        if (str_contains($normalized, 'public_path(')) {
            return true;
        }

        return (bool) preg_match('/[\'"]public\//', $dest)
            || str_contains($normalized, '/public/');
    }

    private function looksStorage(string $dest): bool
    {
        $normalized = str_replace('\\', '/', strtolower($dest));

        return str_contains($normalized, 'storage_path(')
            || str_contains($normalized, '/storage/')
            || (bool) preg_match('/[\'"]storage\//', $dest);
    }

    private function looksGenerated(string $dest): bool
    {
        return (bool) preg_match(
            '/random_bytes|bin2hex|uniqid|random_int|str::uuid|str::random|\buuid\b|hash\s*\(/i',
            $dest
        );
    }

    private function fileHasAllowList(string $source): bool
    {
        if (preg_match('/mimes\s*:|mimetypes\s*:/i', $source)) {
            return true;
        }

        if (preg_match('/finfo_(open|file)|mime_content_type\s*\(|getimagesize\s*\(/i', $source)) {
            return true;
        }

        if (
            preg_match('/in_array\s*\(/i', $source)
            && preg_match('/[\'"](jpe?g|png|gif|webp|pdf|docx?|xlsx?|csv)[\'"]/i', $source)
        ) {
            return true;
        }

        return (bool) preg_match(
            '/[\'"]file[\'"]\s*=>\s*[\'"][^\'"]*(image|mimes|mimetypes)/i',
            $source
        );
    }

    /**
     * @param list<string|array{0: int, 1: string, 2: int}> $tokens
     */
    private function tokensText(array $tokens): string
    {
        $out = '';
        foreach ($tokens as $token) {
            $out .= is_array($token) ? $token[1] : $token;
        }

        return $out;
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
        $issue = new Issue($severity, $message, 'FileUploadCheck');
        $issues[] = $issue;
        Output::issue($issue);
    }
}
