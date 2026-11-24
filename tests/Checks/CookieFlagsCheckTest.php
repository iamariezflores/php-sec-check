<?php

namespace Aquilinoflores\PhpSecCheck\Tests\Checks;

use Aquilinoflores\PhpSecCheck\Checks\CookieFlagsCheck;
use Aquilinoflores\PhpSecCheck\Issue;
use PHPUnit\Framework\TestCase;

class CookieFlagsCheckTest extends TestCase
{
    private string $tempDir;

    protected function setUp(): void
    {
        $this->tempDir = sys_get_temp_dir() . '/php-sec-check-cookie-' . uniqid();
        mkdir($this->tempDir, 0777, true);
    }

    protected function tearDown(): void
    {
        $this->removeDir($this->tempDir);
    }

    private function removeDir(string $dir): void
    {
        if (!is_dir($dir)) {
            return;
        }
        foreach (array_diff(scandir($dir), ['.', '..']) as $item) {
            $path = $dir . DIRECTORY_SEPARATOR . $item;
            if (is_dir($path)) {
                $this->removeDir($path);
            } else {
                @chmod($path, 0666);
                @unlink($path);
            }
        }
        @rmdir($dir);
    }

    /**
     * @param array<string, string> $overrides
     * @return array<string, string>
     */
    private function ini(array $overrides = []): array
    {
        return array_merge(CookieFlagsCheck::HARDENED_INI, $overrides);
    }

    /**
     * @param array<string, string>|null $cookieIni
     * @return list<Issue>
     */
    private function runCheck(?array $cookieIni = null): array
    {
        ob_start();
        $result = (new CookieFlagsCheck($cookieIni ?? $this->ini()))->run($this->tempDir);
        ob_end_clean();
        return $result;
    }

    /**
     * @param list<Issue> $issues
     */
    private function assertFinding(array $issues, string $needle, string $severity): Issue
    {
        foreach ($issues as $issue) {
            if (str_contains($issue->message, $needle)) {
                $this->assertSame($severity, $issue->severity, $issue->message);
                $this->assertSame('CookieFlagsCheck', $issue->check);
                return $issue;
            }
        }

        $this->fail("Expected a finding mentioning '{$needle}', got: " . json_encode(
            array_map(fn(Issue $i) => $i->message, $issues)
        ));
    }

    private function makeLaravel(): void
    {
        mkdir($this->tempDir . '/bootstrap', 0777, true);
        mkdir($this->tempDir . '/config', 0777, true);
        file_put_contents($this->tempDir . '/artisan', "<?php\n");
        file_put_contents($this->tempDir . '/bootstrap/app.php', "<?php\n");
    }

    public function test_hardened_ini_without_setcookie_is_clean(): void
    {
        $this->assertEmpty($this->runCheck($this->ini()));
    }

    public function test_httponly_disabled_is_critical(): void
    {
        $issues = $this->runCheck($this->ini(['session.cookie_httponly' => '0']));

        $this->assertCount(1, $issues);
        $this->assertFinding($issues, 'session.cookie_httponly', Issue::CRITICAL);
    }

    public function test_secure_disabled_is_warn(): void
    {
        $issues = $this->runCheck($this->ini(['session.cookie_secure' => '0']));

        $this->assertCount(1, $issues);
        $this->assertFinding($issues, 'session.cookie_secure', Issue::WARN);
    }

    public function test_samesite_unset_is_warn(): void
    {
        $issues = $this->runCheck($this->ini(['session.cookie_samesite' => '']));

        $this->assertCount(1, $issues);
        $this->assertFinding($issues, 'session.cookie_samesite', Issue::WARN);
    }

    public function test_samesite_none_without_secure_is_critical(): void
    {
        $issues = $this->runCheck($this->ini([
            'session.cookie_secure'   => '0',
            'session.cookie_samesite' => 'None',
        ]));

        $this->assertFinding($issues, 'session.cookie_samesite=None', Issue::CRITICAL);
        $this->assertFinding($issues, 'session.cookie_secure', Issue::WARN);
    }

    public function test_bare_setcookie_is_warn(): void
    {
        file_put_contents($this->tempDir . '/login.php', "<?php setcookie('sid', \$id);\n");

        $issues = $this->runCheck($this->ini());

        $this->assertCount(1, $issues);
        $issue = $this->assertFinding($issues, 'setcookie()', Issue::WARN);
        $this->assertStringContainsString('login.php:1', $issue->message);
        $this->assertStringContainsString('Secure', $issue->message);
        $this->assertStringContainsString('HttpOnly', $issue->message);
        $this->assertStringContainsString('SameSite', $issue->message);
    }

    public function test_locked_down_options_array_is_clean(): void
    {
        file_put_contents(
            $this->tempDir . '/login.php',
            "<?php setcookie('sid', \$id, ['secure' => true, 'httponly' => true, 'samesite' => 'Lax']);\n"
        );

        $this->assertEmpty($this->runCheck($this->ini()));
    }

    public function test_setrawcookie_bare_is_warn(): void
    {
        file_put_contents($this->tempDir . '/login.php', "<?php setrawcookie('sid', \$id);\n");

        $issues = $this->runCheck($this->ini());

        $this->assertCount(1, $issues);
        $this->assertFinding($issues, 'setrawcookie()', Issue::WARN);
    }

    public function test_legacy_setcookie_with_secure_httponly_still_missing_samesite(): void
    {
        file_put_contents(
            $this->tempDir . '/login.php',
            "<?php setcookie('sid', \$id, time() + 3600, '/', '', true, true);\n"
        );

        $issues = $this->runCheck($this->ini());

        $this->assertCount(1, $issues);
        $issue = $this->assertFinding($issues, 'setcookie()', Issue::WARN);
        $this->assertStringContainsString('SameSite', $issue->message);
        $this->assertStringNotContainsString('Secure', $issue->message);
        $this->assertStringNotContainsString('HttpOnly', $issue->message);
    }

    public function test_skips_setcookie_in_vendor(): void
    {
        mkdir($this->tempDir . '/vendor/pkg', 0777, true);
        file_put_contents($this->tempDir . '/vendor/pkg/lib.php', "<?php setcookie('sid', \$id);\n");

        $this->assertEmpty($this->runCheck($this->ini()));
    }

    public function test_laravel_http_only_false_is_warn(): void
    {
        $this->makeLaravel();
        file_put_contents($this->tempDir . '/config/session.php', <<<'PHP'
<?php
return [
    'secure' => true,
    'http_only' => false,
    'same_site' => 'lax',
];
PHP);

        $issues = $this->runCheck($this->ini());

        $this->assertCount(1, $issues);
        $this->assertFinding($issues, 'http_only', Issue::WARN);
    }

    public function test_laravel_same_site_null_is_warn(): void
    {
        $this->makeLaravel();
        file_put_contents($this->tempDir . '/config/session.php', <<<'PHP'
<?php
return [
    'secure' => true,
    'http_only' => true,
    'same_site' => null,
];
PHP);

        $issues = $this->runCheck($this->ini());

        $this->assertCount(1, $issues);
        $this->assertFinding($issues, 'same_site', Issue::WARN);
    }

    public function test_laravel_locked_down_session_cookies_are_clean(): void
    {
        $this->makeLaravel();
        file_put_contents($this->tempDir . '/config/session.php', <<<'PHP'
<?php
return [
    'secure' => env('SESSION_SECURE_COOKIE', true),
    'http_only' => true,
    'same_site' => 'lax',
];
PHP);

        $this->assertEmpty($this->runCheck($this->ini()));
    }

    public function test_laravel_findings_skipped_without_artisan(): void
    {
        mkdir($this->tempDir . '/config', 0777, true);
        file_put_contents($this->tempDir . '/config/session.php', <<<'PHP'
<?php
return [
    'http_only' => false,
    'same_site' => null,
];
PHP);

        $this->assertEmpty($this->runCheck($this->ini()));
    }

    public function test_does_not_report_session_mechanics(): void
    {
        $issues = $this->runCheck($this->ini([
            'session.use_trans_sid'    => '1',
            'session.use_only_cookies' => '0',
            'session.use_strict_mode'  => '0',
        ]));

        $this->assertEmpty($issues, 'trans-sid / strict mode belong to SessionSecurityCheck.');
    }

    public function test_runtime_constructor_returns_array(): void
    {
        ob_start();
        $result = (new CookieFlagsCheck())->run($this->tempDir);
        ob_end_clean();

        $this->assertIsArray($result);
        foreach ($result as $issue) {
            $this->assertInstanceOf(Issue::class, $issue);
            $this->assertSame('CookieFlagsCheck', $issue->check);
        }
    }

    public function test_htaccess_cookie_httponly_off_is_critical(): void
    {
        file_put_contents($this->tempDir . '/.htaccess', "php_flag session.cookie_httponly off\n");

        ob_start();
        $result = (new CookieFlagsCheck())->run($this->tempDir);
        ob_end_clean();

        $this->assertCount(1, $result);
        $this->assertSame(Issue::CRITICAL, $result[0]->severity);
        $this->assertSame(Issue::CONFIRMED, $result[0]->confidence);
        $this->assertStringContainsString('session.cookie_httponly is disabled', $result[0]->message);
        $this->assertSame('.htaccess', $result[0]->path);
    }
}
