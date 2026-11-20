<?php

namespace Aquilinoflores\PhpSecCheck\Checks;

use Aquilinoflores\PhpSecCheck\Issue;
use Aquilinoflores\PhpSecCheck\Output;
use Aquilinoflores\PhpSecCheck\Scan\PhpFunctionCallScanner;
use RecursiveDirectoryIterator;
use RecursiveIteratorIterator;
use SplFileInfo;

/**
 * Cookie flags: Secure, HttpOnly, SameSite.
 *
 * Covers setcookie()/setrawcookie() in application source, php.ini
 * session.cookie_* settings, and Laravel session.php when Laravel is
 * detected. Session mechanics (trans-sid, strict mode, SID entropy)
 * stay on SessionSecurityCheck.
 */
class CookieFlagsCheck implements CheckInterface
{
    /**
     * @var array<string, string>
     */
    public const HARDENED_INI = [
        'session.cookie_secure'   => '1',
        'session.cookie_httponly' => '1',
        'session.cookie_samesite' => 'Lax',
    ];

    private const SKIP_DIR_FRAGMENTS = [
        '/vendor/',
        '/node_modules/',
        '/.git/',
        '/storage/framework/',
        '/bootstrap/cache/',
    ];

    /**
     * @param array<string, string>|null $cookieIni
     */
    public function __construct(
        private readonly ?array $cookieIni = null,
        private readonly ?PhpFunctionCallScanner $scanner = null,
    ) {}

    public function run(string $projectRoot): array
    {
        $issues = [];

        echo "[COOKIE FLAGS]\n";

        $this->checkIni($issues);

        if ($projectRoot !== '' && is_dir($projectRoot)) {
            $this->checkSource($projectRoot, $issues);
            if ($this->isLaravel($projectRoot)) {
                $this->checkLaravel($projectRoot, $issues);
            }
        }

        if ($issues === []) {
            Output::ok('Cookie flags look locked down.');
        }

        echo "\n";
        return $issues;
    }

    /**
     * @param list<Issue> $issues
     */
    private function checkIni(array &$issues): void
    {
        if (!$this->boolIni('session.cookie_httponly')) {
            $this->add(
                $issues,
                Issue::CRITICAL,
                'session.cookie_httponly is disabled. JavaScript can read the session cookie. Set session.cookie_httponly=1.'
            );
        }

        if (!$this->boolIni('session.cookie_secure')) {
            $this->add(
                $issues,
                Issue::WARN,
                'session.cookie_secure is disabled. The session cookie can be sent over HTTP. Set session.cookie_secure=1.'
            );
        }

        $sameSite = strtolower(trim($this->ini('session.cookie_samesite'), "\"'"));
        if ($sameSite === '') {
            $this->add(
                $issues,
                Issue::WARN,
                'session.cookie_samesite is not set. Set it to Lax or Strict to reduce CSRF risk.'
            );
        } elseif ($sameSite === 'none' && !$this->boolIni('session.cookie_secure')) {
            $this->add(
                $issues,
                Issue::CRITICAL,
                'session.cookie_samesite=None requires session.cookie_secure=1. Browsers will reject the cookie otherwise.'
            );
        }
    }

    /**
     * @param list<Issue> $issues
     */
    private function checkSource(string $projectRoot, array &$issues): void
    {
        $scanner = $this->scanner ?? new PhpFunctionCallScanner();

        foreach ($this->phpFiles($projectRoot) as $absolute => $relative) {
            $source = @file_get_contents($absolute);
            if ($source === false) {
                continue;
            }

            foreach ($scanner->findCallsWithArguments($source, ['setcookie', 'setrawcookie']) as $call) {
                $flags = $this->flagsFromArguments($call['arguments']);
                if ($flags === null) {
                    continue;
                }

                $missing = [];
                if ($flags['secure'] !== true) {
                    $missing[] = 'Secure';
                }
                if ($flags['httponly'] !== true) {
                    $missing[] = 'HttpOnly';
                }
                if (!$this->isSafeSameSite($flags['samesite'], $flags['secure'] === true)) {
                    $missing[] = 'SameSite';
                }

                if ($missing === []) {
                    continue;
                }

                $list = $this->missingList($missing);
                $this->add(
                    $issues,
                    Issue::WARN,
                    "{$call['function']}() in {$relative}:{$call['line']} is missing {$list}."
                );
            }
        }
    }

    /**
     * @param list<Issue> $issues
     */
    private function checkLaravel(string $projectRoot, array &$issues): void
    {
        $env    = $this->parseEnv($projectRoot);
        $config = $this->readLaravelCookieConfig($projectRoot);

        $httpOnly = $this->laravelValue($env, 'SESSION_HTTP_ONLY', $config['http_only']);
        $sameSite = $this->laravelValue($env, 'SESSION_SAME_SITE', $config['same_site']);
        $secure   = $this->laravelValue($env, 'SESSION_SECURE_COOKIE', $config['secure']);

        if ($httpOnly !== null && $this->isFalsey($httpOnly)) {
            $this->add(
                $issues,
                Issue::WARN,
                'Laravel session http_only is false. Set SESSION_HTTP_ONLY=true or config/session.php http_only => true.'
            );
        }

        if ($this->isMissingSameSite($sameSite)) {
            $this->add(
                $issues,
                Issue::WARN,
                'Laravel session same_site is empty or null. Set it to lax or strict in config/session.php or SESSION_SAME_SITE.'
            );
        }

        if ($secure !== null && $secure !== '' && $this->isFalsey($secure)) {
            $this->add(
                $issues,
                Issue::WARN,
                'Laravel session secure is false. Set SESSION_SECURE_COOKIE=true so the session cookie is HTTPS-only.'
            );
        }
    }

    /**
     * @param list<list<string|array{0: int, 1: string, 2: int}>> $arguments
     * @return null|array{secure: ?bool, httponly: ?bool, samesite: ?string}
     */
    private function flagsFromArguments(array $arguments): ?array
    {
        if (count($arguments) <= 2) {
            return ['secure' => null, 'httponly' => null, 'samesite' => null];
        }

        $third = $this->significantTokens($arguments[2]);
        if ($third === []) {
            return ['secure' => null, 'httponly' => null, 'samesite' => null];
        }

        $first = $third[0];
        if (is_array($first) && $first[0] === T_VARIABLE) {
            return null;
        }

        if ($this->isArrayLiteral($first)) {
            return $this->flagsFromOptionsArray($arguments[2]);
        }

        $secure   = isset($arguments[5]) ? $this->boolFromTokens($arguments[5]) : null;
        $httponly = isset($arguments[6]) ? $this->boolFromTokens($arguments[6]) : null;

        return [
            'secure'   => $secure,
            'httponly' => $httponly,
            'samesite' => null,
        ];
    }

    /**
     * @param list<string|array{0: int, 1: string, 2: int}> $tokens
     * @return array{secure: ?bool, httponly: ?bool, samesite: ?string}
     */
    private function flagsFromOptionsArray(array $tokens): array
    {
        $flags = ['secure' => null, 'httponly' => null, 'samesite' => null];
        $count = count($tokens);

        for ($i = 0; $i < $count; $i++) {
            $token = $tokens[$i];
            if (!is_array($token) || $token[0] !== T_CONSTANT_ENCAPSED_STRING) {
                continue;
            }

            $key = strtolower(trim($token[1], "\"'"));
            if (!in_array($key, ['secure', 'httponly', 'samesite'], true)) {
                continue;
            }

            $valueTokens = [];
            for ($j = $i + 1; $j < $count; $j++) {
                $next = $tokens[$j];
                if (is_array($next) && in_array($next[0], [T_WHITESPACE, T_COMMENT, T_DOC_COMMENT, T_DOUBLE_ARROW], true)) {
                    continue;
                }
                if ($next === ',') {
                    break;
                }
                $valueTokens[] = $next;
                if ($next === ']' || (is_array($next) && $next[0] !== T_WHITESPACE)) {
                    if ($next === ']') {
                        array_pop($valueTokens);
                    }
                    break;
                }
            }

            if ($key === 'samesite') {
                $flags['samesite'] = $this->stringFromTokens($valueTokens);
            } else {
                $flags[$key] = $this->boolFromTokens($valueTokens);
            }
        }

        return $flags;
    }

    private function isArrayLiteral(mixed $token): bool
    {
        if ($token === '[') {
            return true;
        }

        return is_array($token) && $token[0] === T_ARRAY;
    }

    /**
     * @param list<string|array{0: int, 1: string, 2: int}> $tokens
     * @return list<string|array{0: int, 1: string, 2: int}>
     */
    private function significantTokens(array $tokens): array
    {
        $out = [];
        foreach ($tokens as $token) {
            if (is_array($token) && in_array($token[0], [T_WHITESPACE, T_COMMENT, T_DOC_COMMENT], true)) {
                continue;
            }
            $out[] = $token;
        }

        return $out;
    }

    /**
     * @param list<string|array{0: int, 1: string, 2: int}> $tokens
     */
    private function boolFromTokens(array $tokens): ?bool
    {
        foreach ($this->significantTokens($tokens) as $token) {
            if (!is_array($token)) {
                if ($token === '1') {
                    return true;
                }
                if ($token === '0') {
                    return false;
                }
                continue;
            }

            $text = strtolower($token[1]);
            if (in_array($text, ['true', '1'], true)) {
                return true;
            }
            if (in_array($text, ['false', '0', 'null'], true)) {
                return false;
            }
        }

        return null;
    }

    /**
     * @param list<string|array{0: int, 1: string, 2: int}> $tokens
     */
    private function stringFromTokens(array $tokens): ?string
    {
        foreach ($this->significantTokens($tokens) as $token) {
            if (is_array($token) && $token[0] === T_CONSTANT_ENCAPSED_STRING) {
                return trim($token[1], "\"'");
            }
            if (is_array($token) && $token[0] === T_STRING && strtolower($token[1]) === 'null') {
                return null;
            }
        }

        return null;
    }

    private function isSafeSameSite(?string $sameSite, bool $secure): bool
    {
        if ($sameSite === null || trim($sameSite) === '') {
            return false;
        }

        $normalized = strtolower($sameSite);
        if (in_array($normalized, ['lax', 'strict'], true)) {
            return true;
        }

        return $normalized === 'none' && $secure;
    }

    private function isMissingSameSite(?string $value): bool
    {
        if ($value === null) {
            return false;
        }

        $normalized = strtolower(trim($value, "\"'"));

        return $normalized === '' || $normalized === 'null';
    }

    private function isLaravel(string $projectRoot): bool
    {
        return is_file($projectRoot . '/artisan') && is_file($projectRoot . '/bootstrap/app.php');
    }

    /**
     * @return array{secure: ?string, http_only: ?string, same_site: ?string}
     */
    private function readLaravelCookieConfig(string $projectRoot): array
    {
        $path = $projectRoot . '/config/session.php';
        $empty = ['secure' => null, 'http_only' => null, 'same_site' => null];
        if (!is_file($path)) {
            return $empty;
        }

        $source = (string) file_get_contents($path);

        return [
            'secure'    => $this->configEnvOrLiteral($source, 'SESSION_SECURE_COOKIE', 'secure'),
            'http_only' => $this->configEnvOrLiteral($source, 'SESSION_HTTP_ONLY', 'http_only'),
            'same_site' => $this->configEnvOrLiteral($source, 'SESSION_SAME_SITE', 'same_site'),
        ];
    }

    private function configEnvOrLiteral(string $source, string $envKey, string $configKey): ?string
    {
        $envKeyQuoted = preg_quote($envKey, '/');
        $configQuoted = preg_quote($configKey, '/');

        if (preg_match("/env\(\s*['\"]{$envKeyQuoted}['\"]\s*,\s*['\"]([^'\"]*)['\"]/i", $source, $m)) {
            return $m[1];
        }
        if (preg_match("/env\(\s*['\"]{$envKeyQuoted}['\"]\s*,\s*(true|false|null)/i", $source, $m)) {
            return strtolower($m[1]);
        }
        if (preg_match("/['\"]{$configQuoted}['\"]\s*=>\s*['\"]([^'\"]*)['\"]/", $source, $m)) {
            return $m[1];
        }
        if (preg_match("/['\"]{$configQuoted}['\"]\s*=>\s*(true|false|null)/i", $source, $m)) {
            return strtolower($m[1]);
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
        if (array_key_exists($envKey, $env)) {
            return $env[$envKey];
        }

        return $configDefault;
    }

    private function isFalsey(?string $value): bool
    {
        if ($value === null || $value === '') {
            return true;
        }

        return !filter_var($value, FILTER_VALIDATE_BOOLEAN);
    }

    /**
     * @return iterable<string, string>
     */
    private function phpFiles(string $projectRoot): iterable
    {
        $root = rtrim(str_replace('\\', '/', $projectRoot), '/');
        $iterator = new RecursiveIteratorIterator(
            new RecursiveDirectoryIterator($projectRoot, RecursiveDirectoryIterator::SKIP_DOTS)
        );

        /** @var SplFileInfo $file */
        foreach ($iterator as $file) {
            if (!$file->isFile() || strtolower($file->getExtension()) !== 'php') {
                continue;
            }

            $absolute = $file->getPathname();
            $relative = ltrim(str_replace('\\', '/', substr(str_replace('\\', '/', $absolute), strlen($root))), '/');
            if ($this->shouldSkip($relative)) {
                continue;
            }

            yield $absolute => $relative;
        }
    }

    private function shouldSkip(string $relative): bool
    {
        $haystack = '/' . $relative;
        foreach (self::SKIP_DIR_FRAGMENTS as $fragment) {
            if (str_contains($haystack, $fragment) || str_starts_with($relative, ltrim($fragment, '/'))) {
                return true;
            }
        }

        return false;
    }

    private function ini(string $key): string
    {
        if ($this->cookieIni !== null) {
            return (string) ($this->cookieIni[$key] ?? '');
        }

        $value = ini_get($key);

        return $value === false ? '' : (string) $value;
    }

    private function boolIni(string $key): bool
    {
        return filter_var($this->ini($key), FILTER_VALIDATE_BOOLEAN);
    }

    /**
     * @param list<string> $missing
     */
    private function missingList(array $missing): string
    {
        if (count($missing) <= 1) {
            return $missing[0] ?? '';
        }

        if (count($missing) === 2) {
            return $missing[0] . ' and ' . $missing[1];
        }

        $last = array_pop($missing);

        return implode(', ', $missing) . ', and ' . $last;
    }

    /**
     * @param list<Issue> $issues
     */
    private function add(array &$issues, string $severity, string $message): void
    {
        $issue = new Issue($severity, $message, 'CookieFlagsCheck');
        $issues[] = $issue;
        Output::issue($issue);
    }
}
