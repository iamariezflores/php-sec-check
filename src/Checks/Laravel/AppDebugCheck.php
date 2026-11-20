<?php

namespace Aquilinoflores\PhpSecCheck\Checks\Laravel;

use Aquilinoflores\PhpSecCheck\Checks\CheckInterface;
use Aquilinoflores\PhpSecCheck\Issue;
use Aquilinoflores\PhpSecCheck\Output;
use InvalidArgumentException;

class AppDebugCheck implements CheckInterface
{
    public function run(string $projectRoot): array
    {
        if (empty($projectRoot) || !is_dir($projectRoot)) {
            throw new InvalidArgumentException("Invalid project root: '{$projectRoot}'");
        }

        $issues = [];

        echo "[APP DEBUG]\n";

        $envFile = $projectRoot . '/.env';

        if (!file_exists($envFile)) {
            Output::info('No .env file found. Skipping APP_DEBUG check.');
            echo "\n";
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
            $issue = new Issue(
                Issue::CRITICAL,
                'APP_DEBUG is enabled while APP_ENV is set to "production". This exposes stack traces and environment data to end users.',
                'AppDebugCheck'
            );
            $issues[] = $issue;
            Output::issue($issue);
        } elseif ($debugEnabled) {
            $envLabel = $env ?? 'unknown';
            $issue = new Issue(
                Issue::WARN,
                "APP_DEBUG is enabled (APP_ENV={$envLabel}). Ensure this is disabled before deploying to production.",
                'AppDebugCheck'
            );
            $issues[] = $issue;
            Output::issue($issue);
        } else {
            Output::ok('APP_DEBUG is not enabled.');
        }

        echo "\n";
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
