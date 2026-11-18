<?php

namespace Aquilinoflores\PhpSecCheck\Checks\Laravel;

use Aquilinoflores\PhpSecCheck\Checks\CheckInterface;
use Aquilinoflores\PhpSecCheck\Git\GitStatus;
use Aquilinoflores\PhpSecCheck\Git\GitWorkingTree;
use Aquilinoflores\PhpSecCheck\Issue;
use Aquilinoflores\PhpSecCheck\Output;
use InvalidArgumentException;

class EnvCredentialsCheck implements CheckInterface
{
    private const SECRET_FILES = [
        '.env',
        '.env.local',
        '.env.production',
        '.env.staging',
        '.env.backup',
        '.env.testing',
    ];

    private const TEMPLATE_FILES = [
        '.env.example',
        '.env.sample',
        '.env.template',
    ];

    private const DEFAULT_SENSITIVE_KEYS = [
        'APP_KEY',
        'DB_PASSWORD',
        'MAIL_PASSWORD',
        'AWS_SECRET_ACCESS_KEY',
        'STRIPE_SECRET_KEY',
    ];

    private const WEAK_VALUES = [
        'password', 'secret', 'secret123', 'password123', '123456', '12345678',
        'admin', 'root', 'pass', 'test', 'qwerty', 'letmein', 'changeme',
        'admin123', 'passw0rd', 'toor', 'mysql', 'pass123',
    ];

    private const PLACEHOLDERS = [
        '', 'null', 'your-key-here', 'your_key_here', 'your-password',
        'your_password', 'changeme', 'todo', 'xxx', 'xxxxx', 'placeholder',
        'example', 'base64:', '...', '********', 'change-me', 'changemeplease',
    ];

    protected array $customKeys;

    public function __construct(
        array $customKeys = [],
        private readonly ?GitStatus $git = null,
    ) {
        foreach ($customKeys as $key) {
            if (!is_string($key)) {
                throw new InvalidArgumentException('All custom sensitive keys must be strings. Got: ' . gettype($key));
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
        $git    = $this->git ?? new GitWorkingTree($projectRoot);
        $keys   = $this->sensitiveKeys($projectRoot);

        echo "[ENV CREDENTIALS]\n";

        $this->checkPublicCopies($projectRoot, $issues);
        $this->checkGitExposure($projectRoot, $git, $issues);
        $this->checkEnvContents($projectRoot, $keys, $issues);
        $this->checkTemplateSecrets($projectRoot, $keys, $issues);

        if (empty($issues)) {
            if (is_file($projectRoot . '/.env')) {
                Output::ok('Sensitive values in .env look like normal local configuration. No leaked or tracked env files detected.');
            } else {
                Output::info('No .env file found. No leaked templates or tracked env files detected.');
            }
        }

        echo "\n";
        return $issues;
    }

    /**
     * @param list<Issue> $issues
     */
    private function checkPublicCopies(string $projectRoot, array &$issues): void
    {
        $publicCopies = [
            'public/.env',
            'public/.env.local',
            'storage/app/public/.env',
        ];

        foreach ($publicCopies as $relative) {
            if (is_file($projectRoot . '/' . $relative)) {
                $this->add(
                    $issues,
                    Issue::CRITICAL,
                    "{$relative} exists and is inside a web-accessible directory. Move secrets out of the document root."
                );
            }
        }

        $envAtRoot      = is_file($projectRoot . '/.env');
        $indexAtRoot    = is_file($projectRoot . '/index.php');
        $indexInPublic  = is_file($projectRoot . '/public/index.php');

        if ($envAtRoot && $indexAtRoot && !$indexInPublic) {
            $this->add(
                $issues,
                Issue::CRITICAL,
                '.env sits next to index.php in the project root, so it may be downloadable if the document root is the project root.'
            );
        }
    }

    /**
     * @param list<Issue> $issues
     */
    private function checkGitExposure(string $projectRoot, GitStatus $git, array &$issues): void
    {
        if (!$git->isRepository()) {
            return;
        }

        foreach (self::SECRET_FILES as $file) {
            $tracked = $git->isTracked($file);
            $ignored = $git->isIgnoredByRules($file);
            $exists  = is_file($projectRoot . '/' . $file);

            if ($tracked) {
                $message = $ignored
                    ? "{$file} is listed in ignore rules but is still tracked by git. Remove it from the index with `git rm --cached {$file}`."
                    : "{$file} is tracked by git. Secrets in this file will be committed to version control.";
                $this->add($issues, Issue::CRITICAL, $message);
                continue;
            }

            if ($exists && !$ignored) {
                $this->add(
                    $issues,
                    Issue::WARN,
                    "{$file} is not excluded from git tracking. Add it to .gitignore so it cannot be committed accidentally."
                );
            }
        }
    }

    /**
     * @param list<string> $keys
     * @param list<Issue> $issues
     */
    private function checkEnvContents(string $projectRoot, array $keys, array &$issues): void
    {
        $envFile = $projectRoot . '/.env';
        if (!is_file($envFile)) {
            return;
        }

        $values = $this->parseEnv((string) file_get_contents($envFile));

        foreach ($keys as $key) {
            if (!array_key_exists($key, $values)) {
                continue;
            }

            $value = $values[$key];

            if ($key === 'APP_KEY' && $this->isEmptyValue($value)) {
                $this->add(
                    $issues,
                    Issue::WARN,
                    'APP_KEY is empty. Generate one with `php artisan key:generate` before deploying.'
                );
                continue;
            }

            if ($this->isEmptyValue($value)) {
                continue;
            }

            if ($this->isWeakValue($value)) {
                $this->add(
                    $issues,
                    Issue::WARN,
                    "Sensitive key '{$key}' in .env uses a weak or default value."
                );
            }
        }
    }

    /**
     * @param list<string> $keys
     * @param list<Issue> $issues
     */
    private function checkTemplateSecrets(string $projectRoot, array $keys, array &$issues): void
    {
        foreach (self::TEMPLATE_FILES as $file) {
            $path = $projectRoot . '/' . $file;
            if (!is_file($path)) {
                continue;
            }

            $values = $this->parseEnv((string) file_get_contents($path));

            foreach ($keys as $key) {
                if (!array_key_exists($key, $values)) {
                    continue;
                }

                $value = $values[$key];
                if (!$this->looksLikeRealSecret($value)) {
                    continue;
                }

                $masked = $this->mask($value);
                $this->add(
                    $issues,
                    Issue::CRITICAL,
                    "{$file} contains what looks like a real secret for '{$key}' (value like '{$masked}'). Template files must not include live credentials."
                );
            }
        }
    }

    /**
     * @return list<string>
     */
    private function sensitiveKeys(string $projectRoot): array
    {
        $configFile = $projectRoot . '/php-sec-check-config.php';

        if (is_file($configFile)) {
            $config = include $configFile;
            $keys   = $config['sensitive_keys'] ?? [];
        } else {
            $keys = self::DEFAULT_SENSITIVE_KEYS;
        }

        return array_values(array_unique(array_merge($keys, $this->customKeys)));
    }

    /**
     * @return array<string, string>
     */
    private function parseEnv(string $contents): array
    {
        $pairs = [];

        foreach (preg_split('/\r\n|\n|\r/', $contents) as $line) {
            $line = trim($line);
            if ($line === '' || str_starts_with($line, '#')) {
                continue;
            }
            if (!str_contains($line, '=')) {
                continue;
            }

            [$key, $value] = explode('=', $line, 2);
            $key   = trim($key);
            $value = trim($value);

            if (
                (str_starts_with($value, '"') && str_ends_with($value, '"'))
                || (str_starts_with($value, "'") && str_ends_with($value, "'"))
            ) {
                $value = substr($value, 1, -1);
            }

            $pairs[$key] = $value;
        }

        return $pairs;
    }

    private function isEmptyValue(string $value): bool
    {
        $value = trim($value);

        return $value === '' || strcasecmp($value, 'null') === 0;
    }

    private function isWeakValue(string $value): bool
    {
        return in_array(strtolower(trim($value)), self::WEAK_VALUES, true);
    }

    private function isPlaceholder(string $value): bool
    {
        $normalized = strtolower(trim($value));

        if (in_array($normalized, self::PLACEHOLDERS, true)) {
            return true;
        }

        return (bool) preg_match('/^(your[-_].+|change.?me|x{3,}|placeholder|example.*)$/i', $value);
    }

    private function looksLikeRealSecret(string $value): bool
    {
        $value = trim($value);

        if ($this->isPlaceholder($value) || $this->isEmptyValue($value) || $this->isWeakValue($value)) {
            return false;
        }

        if (preg_match('/^base64:[A-Za-z0-9+\/=]{16,}$/', $value)) {
            return true;
        }
        if (preg_match('/^sk_(live|test)_[A-Za-z0-9]+/', $value)) {
            return true;
        }
        if (preg_match('/^AKIA[0-9A-Z]{16}$/', $value)) {
            return true;
        }
        if (strlen($value) >= 20 && preg_match('/[A-Za-z]/', $value) && preg_match('/[0-9]/', $value)) {
            return true;
        }

        return false;
    }

    private function mask(string $value): string
    {
        return substr($value, 0, 4) . str_repeat('*', max(0, strlen($value) - 4));
    }

    /**
     * @param list<Issue> $issues
     */
    private function add(array &$issues, string $severity, string $message): void
    {
        $issue = new Issue($severity, $message, 'EnvCredentialsCheck');
        $issues[] = $issue;
        Output::issue($issue);
    }
}
