<?php

namespace Aquilinoflores\PhpSecCheck\Checks;

use Aquilinoflores\PhpSecCheck\Issue;
use Aquilinoflores\PhpSecCheck\Scan\ScanContext;
use Aquilinoflores\PhpSecCheck\Scan\TargetLayout;

/**
 * Apache access rules written in the project's .htaccess files.
 */
class HtaccessCheck implements CheckInterface
{
    public const RULE_INDEXES = 'PSC-WEB-001';
    public const RULE_DENY = 'PSC-WEB-002';
    public const RULE_HEADERS = 'PSC-WEB-003';

    public function run(string $projectRoot): array
    {
        if ($projectRoot === '' || !is_dir($projectRoot)) {
            return [];
        }

        $issues = [];
        $seen = [];
        $rootFile = rtrim($projectRoot, '/\\') . DIRECTORY_SEPARATOR . '.htaccess';
        if (is_file($rootFile)) {
            $this->audit($rootFile, '.htaccess', $issues);
            $seen['.htaccess'] = true;
        }

        foreach (TargetLayout::documentRoots($projectRoot) as $relative => $absolute) {
            $file = $absolute . DIRECTORY_SEPARATOR . '.htaccess';
            if (!is_file($file)) {
                continue;
            }
            $projectRelative = ($relative === '' ? '.htaccess' : $relative . '/.htaccess');
            if (isset($seen[$projectRelative])) {
                continue;
            }
            $seen[$projectRelative] = true;
            $this->audit($file, $projectRelative, $issues);
        }

        return $issues;
    }

    /**
     * @param list<Issue> $issues
     */
    private function audit(string $absolute, string $relative, array &$issues): void
    {
        $contents = (string) file_get_contents($absolute);
        $lines = preg_split('/\r\n|\n|\r/', $contents) ?: [];
        $active = [];
        $number = 0;
        foreach ($lines as $line) {
            $number++;
            $trimmed = trim($line);
            if ($trimmed === '' || str_starts_with($trimmed, '#')) {
                continue;
            }
            $active[] = [$number, $trimmed];
        }

        foreach ($active as [$lineNo, $line]) {
            if (!$this->enablesIndexes($line)) {
                continue;
            }
            $issues[] = new Issue(
                Issue::HIGH,
                "Options Indexes is enabled in {$relative}:{$lineNo}. Directory listings will show file names.",
                'HtaccessCheck',
                self::RULE_INDEXES,
                Issue::CONFIRMED,
                'Set Options -Indexes in this .htaccess file.',
                $relative,
                $lineNo,
            );
            break;
        }

        $body = strtolower(implode("\n", array_column($active, 1)));
        $missing = [];
        foreach (['.env' => '.env', '.git' => '.git', '.sql' => '.sql'] as $needle => $label) {
            if (!str_contains($body, $needle)) {
                $missing[] = $label;
            }
        }
        if ($missing !== []) {
            $severity = ScanContext::strictServer() ? Issue::HIGH : Issue::MEDIUM;
            $issues[] = new Issue(
                $severity,
                "{$relative} does not mention " . implode(', ', $missing) . '. A rewrite or Files rule should deny those names.',
                'HtaccessCheck',
                self::RULE_DENY,
                Issue::HEURISTIC,
                'Add FilesMatch rules that deny .env, .git, and .sql, then confirm the vhost is not serving those paths another way.',
                $relative,
                1,
            );
        }

        $headers = ['x-frame-options', 'x-content-type-options', 'strict-transport-security'];
        $present = 0;
        foreach ($headers as $header) {
            if (str_contains($body, $header)) {
                $present++;
            }
        }
        if ($present === 0) {
            $issues[] = new Issue(
                Issue::INFO,
                "{$relative} does not set X-Frame-Options, X-Content-Type-Options, or Strict-Transport-Security.",
                'HtaccessCheck',
                self::RULE_HEADERS,
                Issue::HEURISTIC,
                'Set the headers the application does not already send from PHP. A missing header is a recommendation, not proof of a vulnerability.',
                $relative,
                1,
            );
        }
    }

    private function enablesIndexes(string $line): bool
    {
        if (!preg_match('/^Options\s+(.+)$/i', $line, $m)) {
            return false;
        }

        $enabled = false;
        foreach (preg_split('/\s+/', trim($m[1])) ?: [] as $option) {
            if (in_array(strtolower($option), ['all', 'indexes', '+indexes'], true)) {
                $enabled = true;
            }
            if (strtolower($option) === '-indexes') {
                $enabled = false;
            }
        }

        return $enabled;
    }
}
