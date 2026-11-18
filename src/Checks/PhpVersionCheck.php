<?php

namespace Aquilinoflores\PhpSecCheck\Checks;

use Aquilinoflores\PhpSecCheck\Issue;
use Aquilinoflores\PhpSecCheck\Output;
use Aquilinoflores\PhpSecCheck\Php\PhpSupportCalendar;
use DateTimeImmutable;

class PhpVersionCheck implements CheckInterface
{
    public function __construct(
        private readonly ?string $runtimeVersion = null,
        private readonly ?DateTimeImmutable $today = null,
        private readonly ?PhpSupportCalendar $calendar = null,
    ) {}

    public function run(string $projectRoot): array
    {
        $issues   = [];
        $calendar = $this->calendar ?? new PhpSupportCalendar();
        $today    = $this->today ?? new DateTimeImmutable('today');
        $runtime  = $this->normalize($this->runtimeVersion ?? PHP_VERSION);

        echo "[PHP VERSION]\n";
        echo "Scanner runtime: {$runtime}\n";

        $composer = $this->readComposer($projectRoot);
        $floor    = $composer['floor'];
        $platform = $composer['platform'];
        $constraint = $composer['constraint'];

        if ($constraint !== null) {
            echo "composer.json require.php: {$constraint} (floor {$floor})\n";
        } else {
            echo "composer.json require.php: not set\n";
        }

        echo 'composer.json platform.php: ' . ($platform ?? 'not set') . "\n";

        $pins = $this->detectDeployPins($projectRoot);
        if ($pins === []) {
            echo "Deploy pin: not detected\n";
        } else {
            foreach ($pins as $pin) {
                echo "Deploy pin ({$pin['source']}): {$pin['version']}\n";
            }
        }

        $this->reportSupport($issues, $runtime, 'scanner runtime', $calendar, $today);

        if ($floor !== null) {
            $this->reportSupport($issues, $floor, 'composer.json require.php', $calendar, $today);
        }

        if ($platform !== null) {
            $this->reportSupport($issues, $platform, 'composer.json platform.php', $calendar, $today);
            $this->reportMismatch($issues, $runtime, $platform, 'composer.json platform.php');
        }

        foreach ($pins as $pin) {
            $this->reportSupport($issues, $pin['version'], $pin['source'], $calendar, $today);
            $this->reportMismatch($issues, $runtime, $pin['version'], $pin['source']);
        }

        if (empty($issues)) {
            Output::ok('PHP versions look supported and consistent.');
        }

        echo "\n";
        return $issues;
    }

    /**
     * @return array{constraint: ?string, floor: ?string, platform: ?string}
     */
    private function readComposer(string $projectRoot): array
    {
        $result = ['constraint' => null, 'floor' => null, 'platform' => null];
        $file   = rtrim($projectRoot, '/\\') . '/composer.json';

        if ($projectRoot === '' || !is_file($file)) {
            return $result;
        }

        $data = json_decode((string) file_get_contents($file), true);
        if (!is_array($data)) {
            return $result;
        }

        $constraint = $data['require']['php'] ?? null;
        if (is_string($constraint) && $constraint !== '') {
            $result['constraint'] = $constraint;
            $result['floor']      = $this->lowestVersionInConstraint($constraint);
        }

        $platform = $data['config']['platform']['php'] ?? null;
        if (is_string($platform) && $platform !== '') {
            $result['platform'] = $this->normalize($platform);
        }

        return $result;
    }

    /**
     * @return list<array{source: string, version: string}>
     */
    private function detectDeployPins(string $projectRoot): array
    {
        if ($projectRoot === '' || !is_dir($projectRoot)) {
            return [];
        }

        $root = rtrim(str_replace('\\', '/', $projectRoot), '/');
        $pins = [];

        $phpVersion = $root . '/.php-version';
        if (is_file($phpVersion)) {
            $version = $this->firstVersion((string) file_get_contents($phpVersion));
            if ($version !== null) {
                $pins[] = ['source' => '.php-version', 'version' => $version];
            }
        }

        $toolVersions = $root . '/.tool-versions';
        if (is_file($toolVersions)) {
            foreach (preg_split('/\r\n|\n|\r/', (string) file_get_contents($toolVersions)) as $line) {
                if (preg_match('/^\s*php\s+(\d+\.\d+(?:\.\d+)?)/i', $line, $m)) {
                    $pins[] = ['source' => '.tool-versions', 'version' => $this->normalize($m[1])];
                    break;
                }
            }
        }

        foreach (glob($root . '/Dockerfile*') ?: [] as $dockerFile) {
            if (preg_match('/FROM\s+php:(\d+\.\d+)/i', (string) file_get_contents($dockerFile), $m)) {
                $pins[] = [
                    'source'  => basename($dockerFile),
                    'version' => $this->normalize($m[1]),
                ];
                break;
            }
        }

        return $pins;
    }

    private function lowestVersionInConstraint(string $constraint): ?string
    {
        $lowest = null;
        foreach (preg_split('/\s*\|\|?\s*/', $constraint) as $part) {
            if (preg_match('/(\d+\.\d+(?:\.\d+)?)/', $part, $m)) {
                $version = $this->normalize($m[1]);
                if ($lowest === null || version_compare($version, $lowest, '<')) {
                    $lowest = $version;
                }
            }
        }

        return $lowest;
    }

    private function firstVersion(string $contents): ?string
    {
        if (preg_match('/(\d+\.\d+(?:\.\d+)?)/', $contents, $m)) {
            return $this->normalize($m[1]);
        }

        return null;
    }

    private function normalize(string $version): string
    {
        $version = trim($version);
        if (preg_match('/^\d+\.\d+$/', $version)) {
            return $version . '.0';
        }

        return $version;
    }

    /**
     * @param list<Issue> $issues
     */
    private function reportSupport(
        array &$issues,
        string $version,
        string $source,
        PhpSupportCalendar $calendar,
        DateTimeImmutable $today,
    ): void {
        $status = $calendar->supportStatus($version, $today);
        $branch = $calendar->minorBranch($version);
        $eol    = $calendar->securityEol($version);

        if ($status === 'eol') {
            $ended = $eol ? " (ended {$eol})" : '';
            $this->add(
                $issues,
                Issue::CRITICAL,
                "PHP {$branch} from {$source} is past security support{$ended}."
            );
            return;
        }

        if ($status === 'ending') {
            $until = $eol ? " Security support ends {$eol}." : '';
            $this->add(
                $issues,
                Issue::WARN,
                "PHP {$branch} from {$source} is nearing the end of security support.{$until}"
            );
        }
    }

    /**
     * @param list<Issue> $issues
     */
    private function reportMismatch(array &$issues, string $runtime, string $other, string $source): void
    {
        $calendar = $this->calendar ?? new PhpSupportCalendar();
        if ($calendar->minorBranch($runtime) === $calendar->minorBranch($other)) {
            return;
        }

        $this->add(
            $issues,
            Issue::WARN,
            "Scanner is running PHP {$runtime} but {$source} pins {$other}. Production may differ from this scan."
        );
    }

    /**
     * @param list<Issue> $issues
     */
    private function add(array &$issues, string $severity, string $message): void
    {
        $issue = new Issue($severity, $message, 'PhpVersionCheck');
        $issues[] = $issue;
        Output::issue($issue);
    }
}
