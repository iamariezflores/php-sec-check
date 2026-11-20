<?php

namespace Aquilinoflores\PhpSecCheck\Checks;

use Aquilinoflores\PhpSecCheck\Issue;
use Aquilinoflores\PhpSecCheck\Output;

class ComposerAuditCheck implements CheckInterface
{
    public function run(string $projectRoot): array
    {
        $issues = [];

        echo "[COMPOSER DEPENDENCIES]\n";

        $lockFile = $projectRoot . '/composer.lock';
        if (!file_exists($lockFile)) {
            Output::info('No composer.lock found. Skipping dependency audit.');
            echo "\n";
            return $issues;
        }

        $data = $this->audit($projectRoot);
        $advisories = $data === null ? null : $this->advisories($data);

        if ($advisories === null) {
            $issue = new Issue(
                Issue::WARN,
                'composer audit could not be completed, so dependency vulnerabilities were not checked.',
                'ComposerAuditCheck'
            );
            $issues[] = $issue;
            Output::issue($issue);
            echo "\n";
            return $issues;
        }

        if ($advisories !== []) {
            Output::warn('Vulnerable dependencies found:');
            foreach ($advisories as $package => $packageAdvisories) {
                foreach ($packageAdvisories as $adv) {
                    $title = (string) ($adv['title'] ?? 'Security advisory');
                    $cve   = (string) ($adv['cve'] ?? $adv['advisoryId'] ?? 'unknown');
                    $issue = new Issue(
                        Issue::CRITICAL,
                        "{$package}: {$title} ({$cve})",
                        'ComposerAuditCheck'
                    );
                    $issues[] = $issue;
                    echo "  - {$issue->message}\n";
                }
            }
        } else {
            Output::ok('No known vulnerabilities found in dependencies.');
        }

        echo "\n";
        return $issues;
    }

    /**
     * Audit the lock file in $projectRoot.
     *
     * composer audit writes JSON to stdout and returns a non-zero status when
     * advisories exist, so the status alone is not a failure. A shell redirect
     * such as 2>/dev/null is not used: on Windows it aborts the command and
     * the empty output used to be reported as a clean audit.
     *
     * @return array<string, mixed>|null
     */
    private function audit(string $projectRoot): ?array
    {
        $proc = proc_open(
            'composer audit --locked --format=json --no-interaction',
            [
                1 => ['pipe', 'w'],
                2 => ['pipe', 'w'],
            ],
            $pipes,
            $projectRoot
        );

        if (!is_resource($proc)) {
            return null;
        }

        stream_set_blocking($pipes[1], false);
        stream_set_blocking($pipes[2], false);

        $stdout = '';
        $stderr = '';
        do {
            $stdout .= (string) stream_get_contents($pipes[1]);
            $stderr .= (string) stream_get_contents($pipes[2]);
            $status = proc_get_status($proc);
            if ($status['running']) {
                usleep(10000);
            }
        } while ($status['running']);

        $stdout .= (string) stream_get_contents($pipes[1]);
        $stderr .= (string) stream_get_contents($pipes[2]);
        fclose($pipes[1]);
        fclose($pipes[2]);
        proc_close($proc);

        unset($stderr);

        $stdout = trim($stdout);
        $start  = strpos($stdout, '{');
        if ($start === false) {
            return null;
        }

        $data = json_decode(substr($stdout, $start), true);

        return is_array($data) ? $data : null;
    }

    /**
     * Composer 2.11 returns advisories as a package map. Older releases return
     * a list of {packageName, advisories} objects. Both shapes are accepted.
     *
     * @param array<string, mixed> $data
     * @return array<string, list<array<string, mixed>>>
     */
    private function advisories(array $data): array
    {
        $raw = $data['advisories'] ?? [];
        if (!is_array($raw)) {
            return [];
        }

        $mapped = [];
        $isList = $raw === [] || array_is_list($raw);

        if (!$isList) {
            foreach ($raw as $package => $advisories) {
                if (!is_string($package) || !is_array($advisories)) {
                    continue;
                }
                foreach ($advisories as $adv) {
                    if (is_array($adv)) {
                        $mapped[$package][] = $adv;
                    }
                }
            }

            return $mapped;
        }

        foreach ($raw as $entry) {
            if (!is_array($entry)) {
                continue;
            }

            $nested = $entry['advisories'] ?? null;
            $name   = $entry['packageName'] ?? null;
            if (is_string($name) && is_array($nested)) {
                foreach ($nested as $adv) {
                    if (is_array($adv)) {
                        $mapped[$name][] = $adv;
                    }
                }
                continue;
            }

            if (is_string($name) && isset($entry['title'])) {
                $mapped[$name][] = $entry;
            }
        }

        return $mapped;
    }
}
