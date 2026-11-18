<?php

namespace Aquilinoflores\PhpSecCheck\Checks\Laravel;

use Aquilinoflores\PhpSecCheck\Checks\CheckInterface;
use Aquilinoflores\PhpSecCheck\Issue;
use Aquilinoflores\PhpSecCheck\Output;
use InvalidArgumentException;

class EnvCredentialsCheck implements CheckInterface
{
    protected array $customKeys;

    public function __construct(array $customKeys = [])
    {
        foreach ($customKeys as $key) {
            if (!is_string($key)) {
                throw new InvalidArgumentException("All custom sensitive keys must be strings. Got: " . gettype($key));
            }
        }
        $this->customKeys = $customKeys;
    }

    public function run(string $projectRoot): array
    {
        if (empty($projectRoot) || !is_dir($projectRoot)) {
            throw new InvalidArgumentException("Invalid project root: '{$projectRoot}'");
        }

        $issues = [];
        $envFile = $projectRoot . '/.env';

        echo "[ENV CREDENTIALS]\n";

        if (!file_exists($envFile)) {
            Output::info('No .env file found. Skipping credentials check.');
            echo "\n";
            return [new Issue(Issue::INFO, 'No .env file found', 'EnvCredentialsCheck')];
        }

        $contents   = file_get_contents($envFile);
        $configFile = $projectRoot . '/php-sec-check-config.php';

        if (file_exists($configFile)) {
            $config = include $configFile;
            $keys   = array_merge($config['sensitive_keys'] ?? [], $this->customKeys);
        } else {
            $keys = array_merge([
                'APP_KEY', 'DB_PASSWORD', 'MAIL_PASSWORD',
                'AWS_SECRET_ACCESS_KEY', 'STRIPE_SECRET_KEY',
            ], $this->customKeys);
        }

        foreach ($keys as $key) {
            if (preg_match("/^{$key}=(.+)/m", $contents, $matches)) {
                $value = trim($matches[1]);

                if ($value === '' || strtolower($value) === 'null') {
                    continue;
                }

                $masked  = substr($value, 0, 4) . str_repeat('*', max(0, strlen($value) - 4));
                $issue   = new Issue(
                    Issue::WARN,
                    "Sensitive key '{$key}' found in .env with value like '{$masked}'",
                    'EnvCredentialsCheck'
                );
                $issues[] = $issue;
                Output::issue($issue);
            }
        }

        if (empty($issues)) {
            Output::ok('No sensitive keys with values found in .env.');
        }

        echo "\n";
        return $issues;
    }
}
