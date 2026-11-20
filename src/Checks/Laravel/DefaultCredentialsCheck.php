<?php

namespace Aquilinoflores\PhpSecCheck\Checks\Laravel;

use Aquilinoflores\PhpSecCheck\Checks\CheckInterface;
use Aquilinoflores\PhpSecCheck\Issue;
use Aquilinoflores\PhpSecCheck\Output;
use InvalidArgumentException;

class DefaultCredentialsCheck implements CheckInterface
{
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

        if ($dbUsername !== null && in_array(strtolower($dbUsername), self::DEFAULT_USERNAMES, true)) {
            $issue = new Issue(
                Issue::WARN,
                "DB_USERNAME is set to '{$dbUsername}'. Using default database usernames is a security risk.",
                'DefaultCredentialsCheck'
            );
            $issues[] = $issue;
            Output::issue($issue);
        }

        if ($dbPassword !== null && ($dbPassword === '' || strtolower($dbPassword) === 'null')) {
            $issue = new Issue(
                Issue::CRITICAL,
                'DB_PASSWORD is empty or null. A database without a password is a critical security risk.',
                'DefaultCredentialsCheck'
            );
            $issues[] = $issue;
            Output::issue($issue);
        }

        $localHosts = ['localhost', '127.0.0.1', '::1'];
        if ($dbHost !== null && in_array(strtolower($dbHost), $localHosts, true) && !empty($issues)) {
            $issue = new Issue(
                Issue::WARN,
                "DB_HOST is set to '{$dbHost}' with weak credentials. Ensure this is not publicly accessible.",
                'DefaultCredentialsCheck'
            );
            $issues[] = $issue;
            Output::issue($issue);
        }

        if (empty($issues)) {
            Output::ok('No default or weak database credentials detected.');
        }

        echo "\n";
        return $issues;
    }

    private function getValue(string $key, string $contents): ?string
    {
        if (preg_match('/^' . preg_quote($key, '/') . '=(.*)$/m', $contents, $matches)) {
            return $this->unquote(trim($matches[1]));
        }
        return null;
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
