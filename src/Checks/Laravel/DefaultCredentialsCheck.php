<?php

namespace Aquilinoflores\PhpSecCheck\Checks\Laravel;

use Aquilinoflores\PhpSecCheck\Checks\CheckInterface;
use Aquilinoflores\PhpSecCheck\Output;
use InvalidArgumentException;

class DefaultCredentialsCheck implements CheckInterface
{
    /** Common default/insecure database usernames. */
    private const DEFAULT_USERNAMES = ['root', 'admin', 'postgres', 'sa'];

    public function run(string $projectRoot): array
    {
        if (empty($projectRoot) || !is_dir($projectRoot)) {
            throw new InvalidArgumentException("Invalid project root: '{$projectRoot}'");
        }

        $issues = [];

        echo "[DEFAULT CREDENTIALS]\n";

        $envFile = $projectRoot . '/.env';

        if (!file_exists($envFile)) {
            Output::info('No .env file found. Skipping default credentials check.');
            echo "\n";
            return $issues;
        }

        $contents = file_get_contents($envFile);

        $dbUsername = $this->getValue('DB_USERNAME', $contents);
        $dbPassword = $this->getValue('DB_PASSWORD', $contents);
        $dbHost     = $this->getValue('DB_HOST', $contents);

        // Warn on well-known default usernames
        if ($dbUsername !== null && in_array(strtolower($dbUsername), self::DEFAULT_USERNAMES, true)) {
            $issues[] = "DB_USERNAME is set to '{$dbUsername}'. Using default database usernames is a security risk.";
            Output::warn(end($issues));
        }

        // Warn on empty or null password
        if ($dbPassword !== null && ($dbPassword === '' || strtolower($dbPassword) === 'null')) {
            $issues[] = 'DB_PASSWORD is empty or null. A database without a password is a critical security risk.';
            Output::warn(end($issues));
        }

        // Warn if DB_HOST points to localhost — combined with weak credentials this is common on accidentally exposed servers
        $localHosts = ['localhost', '127.0.0.1', '::1'];
        if ($dbHost !== null && in_array(strtolower($dbHost), $localHosts, true) && !empty($issues)) {
            $issues[] = "DB_HOST is set to '{$dbHost}' with weak credentials. Ensure this is not publicly accessible.";
            Output::warn(end($issues));
        }

        if (empty($issues)) {
            Output::ok('No default or weak database credentials detected.');
        }

        echo "\n";
        return $issues;
    }

    /**
     * Extract the value of a key from .env contents.
     * Returns null if the key is not present.
     */
    private function getValue(string $key, string $contents): ?string
    {
        if (preg_match('/^' . preg_quote($key, '/') . '=(.*)/m', $contents, $matches)) {
            return trim($matches[1]);
        }

        return null;
    }
}
