<?php

namespace Aquilinoflores\PhpSecCheck\Checks\Laravel;

use Aquilinoflores\PhpSecCheck\Checks\CheckInterface;
use Aquilinoflores\PhpSecCheck\Issue;
use InvalidArgumentException;

class AppDebugCheck implements CheckInterface
{
    public const RULE_ID = 'PSC-LAR-001';

    public const RECOMMENDATION = 'Set APP_DEBUG=false before the application is reachable in production.';
    public function run(string $projectRoot): array
    {
        if (empty($projectRoot) || !is_dir($projectRoot)) {
            throw new InvalidArgumentException("Invalid project root: '{$projectRoot}'");
        }

        $issues = [];

        $envFile = $projectRoot . '/.env';

        if (!file_exists($envFile)) {
            return $issues;
        }

        $contents = (string) file_get_contents($envFile);

        $debug = $this->envValue($contents, 'APP_DEBUG');
        $env   = $this->envValue($contents, 'APP_ENV');

        if ($debug !== null) {
            $debug = strtolower($debug);
        }
        if ($env !== null) {
            $env = strtolower($env);
        }

        $debugEnabled = in_array($debug, ['true', '1', 'on'], true);

        if ($debugEnabled && $env === 'production') {
            $issues[] = new Issue(
                Issue::CRITICAL,
                'APP_DEBUG is enabled while APP_ENV is set to "production". This exposes stack traces and environment data to end users.',
                'AppDebugCheck',
                self::RULE_ID,
                Issue::LIKELY,
                self::RECOMMENDATION,
            );
        } elseif ($debugEnabled) {
            $envLabel = $env ?? 'unknown';
            $issues[] = new Issue(
                Issue::WARN,
                "APP_DEBUG is enabled (APP_ENV={$envLabel}). Ensure this is disabled before deploying to production.",
                'AppDebugCheck',
                self::RULE_ID,
                Issue::HEURISTIC,
                self::RECOMMENDATION,
            );
        }

        return $issues;
    }

    private function envValue(string $contents, string $key): ?string
    {
        if (!preg_match('/^' . preg_quote($key, '/') . '=(.*)$/m', $contents, $matches)) {
            return null;
        }

        return $this->unquote(trim($matches[1]));
    }

    private function unquote(string $value): string
    {
        $value = trim($value);
        $length = strlen($value);
        if ($length >= 2) {
            $first = $value[0];
            $last  = $value[$length - 1];
            if (($first === '"' && $last === '"') || ($first === "'" && $last === "'")) {
                $value = substr($value, 1, -1);
            }
        }

        return trim($value);
    }
}
