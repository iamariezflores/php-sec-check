<?php

namespace Aquilinoflores\PhpSecCheck\Checks\Laravel;

use Aquilinoflores\PhpSecCheck\Checks\CheckInterface;
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

        $contents = file_get_contents($envFile);

        $debug = null;
        $env   = null;

        if (preg_match('/^APP_DEBUG=(.+)/m', $contents, $m)) {
            $debug = strtolower(trim($m[1]));
        }

        if (preg_match('/^APP_ENV=(.+)/m', $contents, $m)) {
            $env = strtolower(trim($m[1]));
        }

        $debugEnabled = in_array($debug, ['true', '1', 'on'], true);

        if ($debugEnabled && $env === 'production') {
            $issues[] = 'APP_DEBUG is enabled while APP_ENV is set to "production". This exposes stack traces and environment data to end users.';
            Output::warn(end($issues));
        } elseif ($debugEnabled) {
            $envLabel = $env ?? 'unknown';
            $issues[] = "APP_DEBUG is enabled (APP_ENV={$envLabel}). Ensure this is disabled before deploying to production.";
            Output::warn(end($issues));
        } else {
            Output::ok('APP_DEBUG is not enabled.');
        }

        echo "\n";
        return $issues;
    }
}
