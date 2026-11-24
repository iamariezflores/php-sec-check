<?php

namespace Aquilinoflores\PhpSecCheck\Checks\Laravel;

use Aquilinoflores\PhpSecCheck\Checks\CheckInterface;
use Aquilinoflores\PhpSecCheck\Git\GitStatus;
use Aquilinoflores\PhpSecCheck\Git\GitWorkingTree;
use Aquilinoflores\PhpSecCheck\Issue;
use FilesystemIterator;
use InvalidArgumentException;
use RecursiveDirectoryIterator;
use RecursiveIteratorIterator;
use SplFileInfo;

/**
 * Reports exposed secrets.
 *
 * A filled APP_KEY, database password, or other real credential inside .env
 * is normal configuration and is not a finding. Laravel needs APP_KEY to run.
 * The check asks whether that file, or a copy of its contents, has been exposed:
 * committed, left on a public web path, copied into a template, hardcoded in
 * configuration, or present as a private key or recognizable provider token
 * outside .env.
 */
class EnvCredentialsCheck implements CheckInterface
{
    public const RULE_ID = 'PSC-SEC-001';

    public const RECOMMENDATION = 'Rotate the exposed secret. Keep live values in an untracked env file outside the document root, and keep templates and committed source free of real credentials.';
    private const RUNTIME_ENV_FILES = [
        '.env',
        '.env.local',
        '.env.production',
        '.env.staging',
        '.env.backup',
        '.env.testing',
        '.env.bak',
        '.env.old',
        '.env.save',
        '.env.swp',
        '.env.prod',
        '.env.dev',
    ];

    private const TEMPLATE_FILES = [
        '.env.example',
        '.env.sample',
        '.env.template',
        '.env.dist',
    ];

    private const PUBLIC_PREFIXES = [
        'public/',
        'public_html/',
        'www/',
        'web/',
        'html/',
        'htdocs/',
        'httpdocs/',
        'webroot/',
        'storage/app/public/',
    ];

    private const CONFIG_FILENAMES = [
        'wp-config.php',
        'config.php',
        'configuration.php',
        'settings.php',
        'parameters.yml',
        'parameters.yaml',
        'secrets.yml',
        'secrets.yaml',
        'application.yml',
        'application.yaml',
        'appsettings.json',
    ];

    private const READABLE_EXTENSIONS = [
        'php', 'inc', 'phtml', 'json', 'yml', 'yaml', 'ini', 'xml',
        'env', 'js', 'config', 'conf', 'txt', 'pem', 'key', 'htaccess',
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

    private const MAX_BYTES = 524288;

    /** @var list<string> */
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

        $this->checkProjectRootDocumentRoot($projectRoot, $issues);
        $this->checkEnvContents($projectRoot, $keys, $issues);
        $this->scanTree($projectRoot, $git, $keys, $issues);

        return $issues;
    }

    /**
     * @param list<Issue> $issues
     */
    private function checkProjectRootDocumentRoot(string $projectRoot, array &$issues): void
    {
        $envAtRoot     = is_file($projectRoot . '/.env');
        $indexAtRoot   = is_file($projectRoot . '/index.php');
        $indexInPublic = is_file($projectRoot . '/public/index.php');

        if ($envAtRoot && $indexAtRoot && !$indexInPublic) {
            $this->add(
                $issues,
                Issue::CRITICAL,
                '.env sits next to index.php in the project root, so it may be downloadable if the document root is the project root.'
            );
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
    private function scanTree(string $projectRoot, GitStatus $git, array $keys, array &$issues): void
    {
        $inRepository = $git->isRepository();
        $trackedSet   = [];

        if ($inRepository) {
            foreach ($git->trackedFiles() as $path) {
                $trackedSet[str_replace('\\', '/', $path)] = true;
            }
        }

        $handled = [];

        foreach (array_keys($trackedSet) as $relative) {
            if ($this->shouldSkip($relative)) {
                continue;
            }
            if ($this->isRuntimeEnv($relative)) {
                $this->reportRuntimeEnv($relative, true, true, $git->isIgnoredByRules($relative), $this->isPublicPath($relative), $issues);
                $handled[$relative] = true;
            } elseif ($this->isPrivateKeyFilename($relative)) {
                $this->reportPrivateKeyFile($relative, true, true, false, $this->isPublicPath($relative), $this->isUnderConfigDir($relative), $issues);
                $handled[$relative] = true;
            }
        }

        foreach ($this->relativeFiles($projectRoot) as $relative => $absolute) {
            if (isset($handled[$relative]) || $this->shouldSkip($relative)) {
                continue;
            }

            $tracked = isset($trackedSet[$relative]);

            if ($this->isRuntimeEnv($relative)) {
                $ignored = $inRepository && $git->isIgnoredByRules($relative);
                $this->reportRuntimeEnv($relative, $inRepository, $tracked, $ignored, $this->isPublicPath($relative), $issues);
                continue;
            }

            if ($this->isPrivateKeyFilename($relative)) {
                $ignored = $inRepository && $git->isIgnoredByRules($relative);
                $this->reportPrivateKeyFile($relative, $inRepository, $tracked, $ignored, $this->isPublicPath($relative), $this->isUnderConfigDir($relative), $issues);
                continue;
            }

            $this->inspectContents($relative, $absolute, $trackedSet, $inRepository, $git, $keys, $issues);
        }
    }

    /**
     * @param list<Issue> $issues
     */
    private function reportRuntimeEnv(
        string $relative,
        bool $inRepository,
        bool $tracked,
        bool $ignored,
        bool $public,
        array &$issues,
    ): void {
        if ($public) {
            $this->add(
                $issues,
                Issue::CRITICAL,
                "{$relative} exists and is inside a web-accessible directory. Move secrets out of the document root."
            );
        }

        if (!$inRepository) {
            return;
        }

        if ($tracked) {
            $message = $ignored
                ? "{$relative} is listed in ignore rules but is still tracked by git. Remove it from the index with `git rm --cached {$relative}`."
                : "{$relative} is tracked by git. Secrets in this file will be committed to version control.";
            $this->add($issues, Issue::CRITICAL, $message);
            return;
        }

        if (!$ignored && !$public) {
            $this->add(
                $issues,
                Issue::WARN,
                "{$relative} is not excluded from git tracking. Add it to .gitignore so it cannot be committed accidentally."
            );
        }
    }

    /**
     * @param list<Issue> $issues
     */
    private function reportPrivateKeyFile(
        string $relative,
        bool $inRepository,
        bool $tracked,
        bool $ignored,
        bool $public,
        bool $underConfig,
        array &$issues,
    ): void {
        if ($public) {
            $this->add(
                $issues,
                Issue::CRITICAL,
                "{$relative} exists and is inside a web-accessible directory. Private keys must not be downloadable."
            );
            return;
        }

        if ($underConfig) {
            $this->add(
                $issues,
                Issue::CRITICAL,
                "{$relative} is a private key inside a configuration directory. It is exposed with the application."
            );
            return;
        }

        if (!$inRepository) {
            return;
        }

        if ($tracked) {
            $this->add(
                $issues,
                Issue::CRITICAL,
                "{$relative} is tracked by git. Private keys must not be committed."
            );
            return;
        }

        if (!$ignored) {
            $this->add(
                $issues,
                Issue::WARN,
                "{$relative} is not excluded from git tracking. Add it to .gitignore so the private key cannot be committed accidentally."
            );
        }
    }

    /**
     * @param array<string, true> $trackedSet
     * @param list<string> $keys
     * @param list<Issue> $issues
     */
    private function inspectContents(
        string $relative,
        string $absolute,
        array $trackedSet,
        bool $inRepository,
        GitStatus $git,
        array $keys,
        array &$issues,
    ): void {
        $template = $this->isTemplateEnv($relative);
        $config   = $this->isConfigurationFile($relative);
        $public   = $this->isPublicPath($relative);

        if (!$this->shouldRead($relative, $template, $config)) {
            return;
        }

        $contents = $this->readText($absolute);
        if ($contents === null) {
            return;
        }

        $stripped = $this->stripComments($contents);
        $found    = ($template || $config)
            ? $this->sensitiveLiterals($stripped, $keys, $template)
            : [];

        foreach ($this->recognizedSecrets($stripped, $template || $config) as $hit) {
            if ($this->alreadyFound($found, $hit['value'])) {
                continue;
            }
            $found[] = $hit;
        }

        $hasPrivateKey = $this->containsPrivateKey($stripped);
        if ($found === [] && !$hasPrivateKey) {
            return;
        }

        $kind = $this->exposureKind(
            $template,
            $config,
            $public,
            isset($trackedSet[$relative]),
            $inRepository,
            $git,
            $relative,
        );
        if ($kind === null) {
            return;
        }

        $severity = $kind === 'untracked' ? Issue::WARN : Issue::CRITICAL;

        if ($hasPrivateKey) {
            $this->add($issues, $severity, $this->privateKeyMessage($relative, $kind));
        }

        foreach ($found as $hit) {
            $this->add($issues, $severity, $this->secretMessage($relative, $hit, $kind));
        }
    }

    /**
     * @return iterable<string, string> relative path => absolute path
     */
    private function relativeFiles(string $projectRoot): iterable
    {
        $root = rtrim(str_replace('\\', '/', $projectRoot), '/');
        $iterator = new RecursiveIteratorIterator(
            new RecursiveDirectoryIterator($projectRoot, FilesystemIterator::SKIP_DOTS)
        );

        /** @var SplFileInfo $file */
        foreach ($iterator as $file) {
            if (!$file->isFile() || $file->isLink()) {
                continue;
            }

            $absolute = str_replace('\\', '/', $file->getPathname());
            if (!str_starts_with($absolute, $root)) {
                continue;
            }

            $relative = ltrim(substr($absolute, strlen($root)), '/');
            if ($relative === '' || $this->shouldSkip($relative)) {
                continue;
            }

            yield $relative => $absolute;
        }
    }

    private function shouldSkip(string $relative): bool
    {
        $path     = str_replace('\\', '/', $relative);
        $haystack = '/' . $path;

        foreach (['/vendor/', '/node_modules/', '/.git/', '/storage/framework/', '/storage/logs/', '/bootstrap/cache/'] as $fragment) {
            if (str_contains($haystack, $fragment) || str_starts_with($path, ltrim($fragment, '/'))) {
                return true;
            }
        }

        return false;
    }

    private function isRuntimeEnv(string $relative): bool
    {
        return in_array(strtolower(basename($relative)), self::RUNTIME_ENV_FILES, true);
    }

    private function isTemplateEnv(string $relative): bool
    {
        return in_array(strtolower(basename($relative)), self::TEMPLATE_FILES, true);
    }

    private function isPublicPath(string $relative): bool
    {
        $relative = strtolower(str_replace('\\', '/', $relative));

        foreach (self::PUBLIC_PREFIXES as $prefix) {
            if (str_starts_with($relative, $prefix)) {
                return true;
            }
        }

        return false;
    }

    private function isUnderConfigDir(string $relative): bool
    {
        return (bool) preg_match('#(^|/)config/#i', str_replace('\\', '/', $relative));
    }

    private function isConfigurationFile(string $relative): bool
    {
        $base = strtolower(basename($relative));
        if (in_array($base, self::CONFIG_FILENAMES, true)) {
            return true;
        }

        return (bool) preg_match('#(^|/)config/.+\.(php|inc|json|ya?ml|ini|xml|env)$#i', str_replace('\\', '/', $relative));
    }

    private function isPrivateKeyFilename(string $relative): bool
    {
        $base = strtolower(basename($relative));
        if (str_ends_with($base, '.pub')) {
            return false;
        }
        if (in_array($base, ['id_rsa', 'id_dsa', 'id_ecdsa', 'id_ed25519'], true)) {
            return true;
        }
        if (preg_match('/\.(p12|pfx)$/', $base)) {
            return true;
        }

        return str_contains($base, 'private') && (bool) preg_match('/\.(pem|key)$/', $base);
    }

    private function shouldRead(string $relative, bool $template, bool $config): bool
    {
        if ($template || $config) {
            return true;
        }

        $base = strtolower(basename($relative));
        $ext  = strtolower(pathinfo($base, PATHINFO_EXTENSION));

        return in_array($ext, self::READABLE_EXTENSIONS, true);
    }

    private function readText(string $absolute): ?string
    {
        if (!is_file($absolute) || filesize($absolute) > self::MAX_BYTES) {
            return null;
        }

        $contents = file_get_contents($absolute);
        if ($contents === false || str_contains($contents, "\0")) {
            return null;
        }

        return $contents;
    }

    private function stripComments(string $contents): string
    {
        $kept = [];
        foreach (preg_split('/\r\n|\n|\r/', $contents) as $line) {
            $trim = ltrim($line);
            if (
                $trim === ''
                || str_starts_with($trim, '//')
                || str_starts_with($trim, '#')
                || str_starts_with($trim, '*')
                || str_starts_with($trim, '/*')
            ) {
                continue;
            }
            $kept[] = $line;
        }

        return implode("\n", $kept);
    }

    /**
     * @param list<string> $keys
     * @return list<array{key: ?string, value: string, label: ?string}>
     */
    private function sensitiveLiterals(string $contents, array $keys, bool $template): array
    {
        $hits = [];

        if ($template) {
            foreach ($this->parseEnv($contents) as $key => $value) {
                if (!in_array($key, $keys, true) || !$this->looksLikeRealSecret($value)) {
                    continue;
                }
                $hits[] = ['key' => $key, 'value' => $value, 'label' => null];
            }

            return $hits;
        }

        foreach (preg_split('/\r\n|\n|\r/', $contents) as $line) {
            foreach ($keys as $key) {
                if (!preg_match('/(^|[^A-Za-z0-9_])' . preg_quote($key, '/') . '([^A-Za-z0-9_]|$)/i', $line)) {
                    continue;
                }
                foreach ($this->literalValues($line) as $value) {
                    if (strcasecmp($value, $key) === 0 || !$this->looksLikeRealSecret($value) || $this->alreadyFound($hits, $value)) {
                        continue;
                    }
                    $hits[] = ['key' => $key, 'value' => $value, 'label' => null];
                }
            }
        }

        return $hits;
    }

    /**
     * @return list<string>
     */
    private function literalValues(string $line): array
    {
        $values = [];

        if (preg_match_all("/(['\"])([^'\"]+)\\1/", $line, $matches)) {
            foreach ($matches[2] as $value) {
                $values[] = $value;
            }
        }

        if (preg_match('/:\s*([A-Za-z0-9+\/=_:.\-]{8,})\s*(?:#.*)?$/', $line, $matches)) {
            $values[] = $matches[1];
        }

        return $values;
    }

    /**
     * @return list<array{key: ?string, value: string, label: ?string}>
     */
    private function recognizedSecrets(string $contents, bool $includeAppKey): array
    {
        $patterns = [
            'Stripe secret key'    => '/(?<![A-Za-z0-9])(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{8,}/',
            'Stripe webhook secret'=> '/(?<![A-Za-z0-9])whsec_[A-Za-z0-9]{8,}/',
            'AWS access key ID'    => '/(?<![A-Za-z0-9])(?:AKIA|ASIA)[0-9A-Z]{16}(?![A-Za-z0-9])/',
            'GitHub token'         => '/(?<![A-Za-z0-9])(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36}(?![A-Za-z0-9])|(?<![A-Za-z0-9])github_pat_[A-Za-z0-9_]{22,}/',
            'Slack token'          => '/(?<![A-Za-z0-9])xox[baprs]-[A-Za-z0-9-]{10,}/',
            'Google API key'       => '/(?<![A-Za-z0-9])AIza[0-9A-Za-z\-_]{35}(?![A-Za-z0-9])/',
            'SendGrid API key'     => '/(?<![A-Za-z0-9])SG\.[A-Za-z0-9_\-]{16,}\.[A-Za-z0-9_\-]{16,}/',
        ];

        if ($includeAppKey) {
            $patterns['Laravel application key'] = '/(?<![A-Za-z0-9])base64:[A-Za-z0-9+\/=]{16,}/';
        }

        $hits = [];
        foreach ($patterns as $label => $pattern) {
            if (!preg_match_all($pattern, $contents, $matches)) {
                continue;
            }
            foreach ($matches[0] as $value) {
                if ($this->isPlaceholder($value) || $this->isWeakValue($value) || $this->alreadyFound($hits, $value)) {
                    continue;
                }
                $hits[] = ['key' => null, 'value' => $value, 'label' => $label];
            }
        }

        foreach (preg_split('/\r\n|\n|\r/', $contents) as $line) {
            if (!preg_match('/secret[._ -]?access[._ -]?key|aws[._ -]?secret/i', $line)) {
                continue;
            }
            if (!preg_match('/(?<![A-Za-z0-9])[A-Za-z0-9\/+=]{40}(?![A-Za-z0-9])/', $line, $matches)) {
                continue;
            }
            if (str_starts_with($matches[0], 'AKIA') || str_starts_with($matches[0], 'ASIA') || $this->alreadyFound($hits, $matches[0])) {
                continue;
            }
            $hits[] = ['key' => null, 'value' => $matches[0], 'label' => 'AWS secret access key'];
        }

        return $hits;
    }

    private function containsPrivateKey(string $contents): bool
    {
        return (bool) preg_match('/-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----/', $contents);
    }

    private function exposureKind(
        bool $template,
        bool $config,
        bool $public,
        bool $tracked,
        bool $inRepository,
        GitStatus $git,
        string $relative,
    ): ?string {
        if ($template) {
            return 'template';
        }
        if ($config) {
            return 'config';
        }
        if ($public) {
            return 'public';
        }
        if ($tracked) {
            return 'tracked';
        }
        if ($inRepository && !$git->isIgnoredByRules($relative)) {
            return 'untracked';
        }

        return null;
    }

    /**
     * @param array{key: ?string, value: string, label: ?string} $hit
     */
    private function secretMessage(string $relative, array $hit, string $kind): string
    {
        $masked = $this->mask($hit['value']);

        if ($hit['key'] !== null && $kind === 'template') {
            return "{$relative} contains what looks like a real secret for '{$hit['key']}' (value like '{$masked}'). Template files must not include live credentials.";
        }

        if ($hit['key'] !== null && $kind === 'config') {
            return "{$relative} hardcodes sensitive key '{$hit['key']}' (value like '{$masked}'). A value in .env is expected; this copy is exposed with the application.";
        }

        $label = $hit['label'] ?? ($hit['key'] ?? 'secret');

        return match ($kind) {
            'template' => "{$relative} contains {$label} (value like '{$masked}'). Template files must not include live credentials.",
            'config'   => "{$relative} contains a hardcoded {$label} (value like '{$masked}'). A secret in .env is expected; this copy is exposed with the application.",
            'public'   => "{$relative} contains {$label} (value like '{$masked}') and is inside a web-accessible directory.",
            'tracked'  => "{$relative} is tracked by git and contains {$label} (value like '{$masked}').",
            default    => "{$relative} contains {$label} (value like '{$masked}') and is not excluded from git tracking.",
        };
    }

    private function privateKeyMessage(string $relative, string $kind): string
    {
        return match ($kind) {
            'template' => "{$relative} contains a private key. Template files must not include live credentials.",
            'config'   => "{$relative} contains a private key. Private key material here is exposed with the application.",
            'public'   => "{$relative} contains a private key and is inside a web-accessible directory.",
            'tracked'  => "{$relative} is tracked by git and contains a private key.",
            default    => "{$relative} contains a private key and is not excluded from git tracking.",
        };
    }

    /**
     * @param list<array{key: ?string, value: string, label: ?string}> $found
     */
    private function alreadyFound(array $found, string $value): bool
    {
        foreach ($found as $hit) {
            if ($hit['value'] === $value || str_contains($hit['value'], $value) || str_contains($value, $hit['value'])) {
                return true;
            }
        }

        return false;
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
        $issues[] = new Issue(
            $severity,
            $message,
            'EnvCredentialsCheck',
            self::RULE_ID,
            $severity === Issue::CRITICAL ? Issue::CONFIRMED : Issue::HEURISTIC,
            self::RECOMMENDATION,
        );
    }
}
