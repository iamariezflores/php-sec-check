<?php

namespace Aquilinoflores\PhpSecCheck\Config;

use Aquilinoflores\PhpSecCheck\Finding;

/**
 * Options for one scan. CLI flags override the project config file.
 */
final class ScanOptions
{
    /**
     * @param list<string> $exclude
     * @param list<string> $disabledRules
     */
    public function __construct(
        public readonly string $profile = 'legacy',
        public readonly string $minSeverity = Finding::HIGH,
        public readonly array $exclude = [],
        public readonly array $disabledRules = [],
    ) {}

    public static function fromProject(string $projectRoot): self
    {
        $file = rtrim($projectRoot, '/\\') . DIRECTORY_SEPARATOR . 'php-sec-check-config.php';
        if (!is_file($file)) {
            return new self();
        }

        $data = include $file;
        if (!is_array($data)) {
            return new self();
        }

        $profile = is_string($data['profile'] ?? null) ? strtolower($data['profile']) : 'legacy';
        if (!in_array($profile, ['legacy', 'production', 'host', 'dependencies', 'laravel'], true)) {
            $profile = 'legacy';
        }

        $min = Finding::HIGH;
        if (is_string($data['min_severity'] ?? null)) {
            $normalized = Finding::normalizeSeverity($data['min_severity']);
            if ($normalized !== null) {
                $min = $normalized;
            }
        }

        return new self(
            $profile,
            $min,
            self::strings($data['exclude'] ?? []),
            self::strings($data['disabled_rules'] ?? []),
        );
    }

    /**
     * @param list<string> $exclude
     * @param list<string> $disabledRules
     */
    public function withOverrides(?string $profile, ?string $minSeverity, array $exclude): self
    {
        return new self(
            $profile ?? $this->profile,
            $minSeverity ?? $this->minSeverity,
            array_values(array_unique(array_merge($this->exclude, $exclude))),
            $this->disabledRules,
        );
    }

    public function hides(Finding $finding): bool
    {
        if (in_array($finding->ruleId, $this->disabledRules, true)) {
            return true;
        }

        $path = str_replace('\\', '/', (string) $finding->path);
        $text = strtolower($path . "\n" . $finding->message);
        foreach ($this->exclude as $pattern) {
            $pattern = strtolower(str_replace('\\', '/', trim($pattern)));
            if ($pattern === '') {
                continue;
            }
            $trimmed = trim($pattern, '/');
            if ($trimmed !== '' && str_contains($text, $trimmed)) {
                return true;
            }
            if ($path !== '' && (fnmatch($pattern, $path) || fnmatch($pattern, basename($path)))) {
                return true;
            }
        }

        return false;
    }

    /**
     * @return list<string>
     */
    private static function strings(mixed $value): array
    {
        if (!is_array($value)) {
            return [];
        }

        $out = [];
        foreach ($value as $item) {
            if (is_string($item) && trim($item) !== '') {
                $out[] = trim($item);
            }
        }

        return $out;
    }
}
