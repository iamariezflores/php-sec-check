<?php

namespace Aquilinoflores\PhpSecCheck\Checks;

use Aquilinoflores\PhpSecCheck\Issue;
use Aquilinoflores\PhpSecCheck\Php\ProjectPhpSettings;
use Aquilinoflores\PhpSecCheck\Scan\TargetLayout;

/**
 * Session configuration: php.ini hardening, plus Laravel session.php when
 * a Laravel app is detected. Cookie flags (Secure / HttpOnly / SameSite)
 * are a separate check.
 */
class SessionSecurityCheck implements CheckInterface
{
    public const RULE_ID = 'PSC-RUN-030';

    public const RECOMMENDATION = 'Set session.use_strict_mode=1, session.use_only_cookies=1, and session.use_trans_sid=0 in the deployed PHP configuration. Keep the session save path outside the document root.';
    /**
     * Hardened PHP 8.2+ session settings used as the clean baseline in tests.
     *
     * @var array<string, string>
     */
    public const HARDENED_INI = [
        'session.use_strict_mode'          => '1',
        'session.use_only_cookies'         => '1',
        'session.use_trans_sid'            => '0',
        'session.sid_length'               => '32',
        'session.sid_bits_per_character'   => '5',
        'session.save_path'                => '',
    ];

    public const MIN_SID_LENGTH = 22;
    public const MIN_SID_BITS   = 4;
    public const MIN_ENTROPY    = 128;

    /**
     * @param array<string, string>|null $sessionIni  injected map for tests; null reads the project files
     */
    public function __construct(
        private readonly ?array $sessionIni = null,
        private readonly bool $frameworkExtras = true,
    ) {}

    public function run(string $projectRoot): array
    {
        $issues = [];

        if ($this->sessionIni !== null) {
            $this->checkIni($projectRoot, $issues);
        } else {
            $this->checkProject($projectRoot, $issues);
        }

        if ($this->frameworkExtras && $this->isLaravel($projectRoot)) {
            $this->checkLaravel($projectRoot, $issues);
        }

        return $issues;
    }

    /**
     * @param list<Issue> $issues
     */
    private function checkIni(string $projectRoot, array &$issues): void
    {
        if ($this->boolIni('session.use_trans_sid')) {
            $this->add(
                $issues,
                Issue::CRITICAL,
                'session.use_trans_sid is enabled. Session IDs will leak in URLs and Referer headers. Set session.use_trans_sid=0.'
            );
        }

        if (!$this->boolIni('session.use_only_cookies')) {
            $this->add(
                $issues,
                Issue::CRITICAL,
                'session.use_only_cookies is disabled. Session IDs can be passed in URLs. Set session.use_only_cookies=1.'
            );
        }

        if (!$this->boolIni('session.use_strict_mode')) {
            $this->add(
                $issues,
                Issue::WARN,
                'session.use_strict_mode is disabled. Enable it so PHP rejects uninitialized session IDs (session fixation).'
            );
        }

        $length = $this->intIni('session.sid_length', 32);
        $bits   = $this->intIni('session.sid_bits_per_character', 4);
        $entropy = $length * $bits;

        if ($length < self::MIN_SID_LENGTH) {
            $this->add(
                $issues,
                Issue::CRITICAL,
                "session.sid_length is {$length}, below PHP's minimum of " . self::MIN_SID_LENGTH . '.'
            );
        } elseif ($bits < self::MIN_SID_BITS) {
            $this->add(
                $issues,
                Issue::WARN,
                "session.sid_bits_per_character is {$bits}, below PHP's minimum of " . self::MIN_SID_BITS . '.'
            );
        } elseif ($entropy < self::MIN_ENTROPY) {
            $this->add(
                $issues,
                Issue::WARN,
                "session.sid_length {$length} with {$bits} bits/character is only {$entropy} bits of entropy. Use at least " . self::MIN_ENTROPY . ' (for example length 32 with 4 bits/character).'
            );
        }

        $savePath = $this->savePathDirectory($this->ini('session.save_path'));
        if ($savePath !== '' && $projectRoot !== '' && is_dir($projectRoot) && $this->isWebAccessiblePath($projectRoot, $savePath)) {
            $this->add(
                $issues,
                Issue::CRITICAL,
                "session.save_path '{$savePath}' is inside the document root. Session files must not be web-accessible."
            );
        }
    }

    /**
     * @param list<Issue> $issues
     */
    private function checkLaravel(string $projectRoot, array &$issues): void
    {
        $env    = $this->parseEnv($projectRoot);
        $config = $this->readLaravelSessionConfig($projectRoot);

        $driver  = $this->laravelValue($env, 'SESSION_DRIVER', $config['driver'] ?? null) ?? '';
        $encrypt = $this->laravelValue($env, 'SESSION_ENCRYPT', $config['encrypt'] ?? null);
        $files   = $this->laravelValue($env, 'SESSION_FILES', $config['files'] ?? null) ?? ($config['files'] ?? '');

        $driver = strtolower(trim($driver, "\"'"));

        if ($driver === 'cookie' && $this->isFalsey($encrypt)) {
            $this->add(
                $issues,
                Issue::WARN,
                'Laravel session driver "cookie" has encryption disabled. Set SESSION_ENCRYPT=true or config/session.php encrypt => true.'
            );
        }

        if ($driver === 'file' && $files !== '' && $this->laravelFilesPathIsPublic($files, $projectRoot)) {
            $this->add(
                $issues,
                Issue::CRITICAL,
                'Laravel file session path is inside the document root. Keep sessions under storage/framework/sessions, not public/.'
            );
        }
    }

    private function isLaravel(string $projectRoot): bool
    {
        return $projectRoot !== ''
            && is_file($projectRoot . '/artisan')
            && is_file($projectRoot . '/bootstrap/app.php');
    }

    /**
     * @return array{driver: ?string, encrypt: ?string, files: ?string}
     */
    private function readLaravelSessionConfig(string $projectRoot): array
    {
        $path = $projectRoot . '/config/session.php';
        $empty = ['driver' => null, 'encrypt' => null, 'files' => null];
        if (!is_file($path)) {
            return $empty;
        }

        $source = (string) file_get_contents($path);

        return [
            'driver'  => $this->configEnvOrLiteral($source, 'SESSION_DRIVER', 'driver'),
            'encrypt' => $this->configEnvOrLiteral($source, 'SESSION_ENCRYPT', 'encrypt'),
            'files'   => $this->configFiles($source),
        ];
    }

    private function configEnvOrLiteral(string $source, string $envKey, string $configKey): ?string
    {
        $envKeyQuoted = preg_quote($envKey, '/');
        $configQuoted = preg_quote($configKey, '/');

        if (preg_match("/env\(\s*['\"]{$envKeyQuoted}['\"]\s*,\s*['\"]([^'\"]*)['\"]/i", $source, $m)) {
            return $m[1];
        }
        if (preg_match("/env\(\s*['\"]{$envKeyQuoted}['\"]\s*,\s*(true|false)/i", $source, $m)) {
            return strtolower($m[1]);
        }
        if (preg_match("/['\"]{$configQuoted}['\"]\s*=>\s*['\"]([^'\"]+)['\"]/", $source, $m)) {
            return $m[1];
        }
        if (preg_match("/['\"]{$configQuoted}['\"]\s*=>\s*(true|false)/i", $source, $m)) {
            return strtolower($m[1]);
        }

        return null;
    }

    private function configFiles(string $source): ?string
    {
        if (preg_match("/['\"]files['\"]\s*=>\s*storage_path\s*\(/i", $source)) {
            return 'storage_path';
        }
        if (preg_match("/['\"]files['\"]\s*=>\s*public_path\s*\(/i", $source)) {
            return 'public_path';
        }
        if (preg_match("/['\"]files['\"]\s*=>\s*['\"]([^'\"]+)['\"]/", $source, $m)) {
            return $m[1];
        }

        return null;
    }

    /**
     * @return array<string, string>
     */
    private function parseEnv(string $projectRoot): array
    {
        $path = $projectRoot . '/.env';
        if (!is_file($path)) {
            return [];
        }

        $pairs = [];
        foreach (preg_split('/\r\n|\n|\r/', (string) file_get_contents($path)) as $line) {
            $line = trim($line);
            if ($line === '' || str_starts_with($line, '#') || !str_contains($line, '=')) {
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

    /**
     * @param array<string, string> $env
     */
    private function laravelValue(array $env, string $envKey, ?string $configDefault): ?string
    {
        if (array_key_exists($envKey, $env) && $env[$envKey] !== '') {
            return $env[$envKey];
        }

        return $configDefault;
    }

    private function laravelFilesPathIsPublic(string $files, string $projectRoot): bool
    {
        $normalized = str_replace('\\', '/', strtolower($files));
        if ($normalized === 'storage_path') {
            return false;
        }
        if ($normalized === 'public_path' || str_contains($normalized, 'public_path(')) {
            return true;
        }
        if (str_contains($normalized, '/public/') || str_starts_with($normalized, 'public/')) {
            return true;
        }

        return $this->isWebAccessiblePath($projectRoot, $files);
    }

    private function isFalsey(?string $value): bool
    {
        if ($value === null || $value === '') {
            return true;
        }

        return !filter_var($value, FILTER_VALIDATE_BOOLEAN);
    }

    private function isWebAccessiblePath(string $projectRoot, string $path): bool
    {
        $resolved = $this->resolvePath($projectRoot, $path);
        if ($resolved === '') {
            return false;
        }

        foreach (TargetLayout::documentRoots($projectRoot) as $absolute) {
            if ($this->isUnder($resolved, $this->normalizePath($absolute))) {
                return true;
            }
        }

        return false;
    }

    private function resolvePath(string $projectRoot, string $path): string
    {
        $path = trim($path);
        if ($path === '') {
            return '';
        }

        $normalized = $this->normalizePath($path);
        if ($this->isAbsolutePath($normalized)) {
            return $normalized;
        }

        return rtrim($this->normalizePath($projectRoot), '/') . '/' . ltrim($normalized, '/');
    }

    private function isAbsolutePath(string $path): bool
    {
        return str_starts_with($path, '/') || (bool) preg_match('/^[A-Za-z]:\//', $path);
    }

    private function isUnder(string $path, string $directory): bool
    {
        $path = rtrim($path, '/');
        $directory = rtrim($directory, '/');

        return $path === $directory || str_starts_with($path, $directory . '/');
    }

    private function normalizePath(string $path): string
    {
        return str_replace('\\', '/', $path);
    }

    private function savePathDirectory(string $raw): string
    {
        $raw = trim($raw);
        if ($raw === '') {
            return '';
        }
        if (preg_match('/^\d+;(?:\d+;)?(.*)$/', $raw, $m)) {
            return trim($m[1]);
        }

        return $raw;
    }

    private function ini(string $key): string
    {
        if ($this->sessionIni !== null) {
            return (string) ($this->sessionIni[$key] ?? '');
        }

        $value = ini_get($key);

        return $value === false ? '' : (string) $value;
    }

    private function boolIni(string $key): bool
    {
        return filter_var($this->ini($key), FILTER_VALIDATE_BOOLEAN);
    }

    private function intIni(string $key, int $default): int
    {
        $raw = $this->ini($key);
        if ($raw === '' || !is_numeric($raw)) {
            return $default;
        }

        return (int) $raw;
    }

    /**
     * @param list<Issue> $issues
     */
    /**
     * @param list<Issue> $issues
     */
    private function checkProject(string $projectRoot, array &$issues): void
    {
        if ($projectRoot === '' || !is_dir($projectRoot)) {
            return;
        }

        $settings = ProjectPhpSettings::load($projectRoot);
        foreach ($settings->directives('session.use_trans_sid') as $directive) {
            if ($directive->isEnabled()) {
                $this->add($issues, Issue::CRITICAL, "session.use_trans_sid is enabled in {$directive->path}:{$directive->line}. Session IDs will leak in URLs and Referer headers. Set session.use_trans_sid=0.", Issue::CONFIRMED, $directive->path, $directive->line);
            }
        }
        foreach ($settings->directives('session.use_only_cookies') as $directive) {
            if ($directive->isDisabled()) {
                $this->add($issues, Issue::CRITICAL, "session.use_only_cookies is disabled in {$directive->path}:{$directive->line}. Session IDs can be passed in URLs. Set session.use_only_cookies=1.", Issue::CONFIRMED, $directive->path, $directive->line);
            }
        }
        foreach ($settings->directives('session.use_strict_mode') as $directive) {
            if ($directive->isDisabled()) {
                $this->add($issues, Issue::WARN, "session.use_strict_mode is disabled in {$directive->path}:{$directive->line}. Enable it so PHP rejects uninitialized session IDs (session fixation).", Issue::CONFIRMED, $directive->path, $directive->line);
            }
        }
        foreach ($settings->directives('session.save_path') as $directive) {
            $savePath = $this->savePathDirectory($directive->value);
            if ($savePath !== '' && $this->isWebAccessiblePath($projectRoot, $savePath)) {
                $this->add($issues, Issue::CRITICAL, "session.save_path '{$savePath}' in {$directive->path}:{$directive->line} is inside the document root. Session files must not be web-accessible.", Issue::CONFIRMED, $directive->path, $directive->line);
            }
        }
    }

    /**
     * @param list<Issue> $issues
     */
    private function add(
        array &$issues,
        string $severity,
        string $message,
        string $confidence = Issue::HEURISTIC,
        ?string $path = null,
        ?int $line = null,
    ): void {
        $issues[] = new Issue(
            $severity,
            $message,
            'SessionSecurityCheck',
            self::RULE_ID,
            $confidence,
            self::RECOMMENDATION,
            $path,
            $line,
        );
    }
}
