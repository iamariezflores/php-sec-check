<?php

namespace Aquilinoflores\PhpSecCheck\Tests\Checks;

use Aquilinoflores\PhpSecCheck\Checks\SessionSecurityCheck;
use Aquilinoflores\PhpSecCheck\Issue;
use PHPUnit\Framework\TestCase;

class SessionSecurityCheckTest extends TestCase
{
    private string $tempDir;

    protected function setUp(): void
    {
        $this->tempDir = sys_get_temp_dir() . '/php-sec-check-session-' . uniqid();
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
        return array_merge(SessionSecurityCheck::HARDENED_INI, $overrides);
    }

    /**
     * @param array<string, string>|null $sessionIni
     * @return list<Issue>
     */
    private function runCheck(?array $sessionIni = null, ?string $root = null): array
    {
        ob_start();
        $result = (new SessionSecurityCheck($sessionIni ?? $this->ini()))->run($root ?? $this->tempDir);
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
                $this->assertSame('SessionSecurityCheck', $issue->check);
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
        file_put_contents($this->tempDir . '/artisan', "<?php\n");
        file_put_contents($this->tempDir . '/bootstrap/app.php', "<?php\n");
    }

    public function test_hardened_php_82_settings_are_clean(): void
    {
        $this->assertEmpty($this->runCheck($this->ini()), 'Hardened PHP 8.2+ session settings must be clean.');
    }

    public function test_php_ini_production_26_by_5_entropy_is_clean(): void
    {
        $this->assertEmpty($this->runCheck($this->ini([
            'session.sid_length'             => '26',
            'session.sid_bits_per_character' => '5',
        ])));
    }

    public function test_trans_sid_enabled_is_critical(): void
    {
        $issues = $this->runCheck($this->ini(['session.use_trans_sid' => '1']));

        $this->assertCount(1, $issues);
        $this->assertFinding($issues, 'session.use_trans_sid', Issue::CRITICAL);
    }

    public function test_use_only_cookies_disabled_is_critical(): void
    {
        $issues = $this->runCheck($this->ini(['session.use_only_cookies' => '0']));

        $this->assertCount(1, $issues);
        $this->assertFinding($issues, 'session.use_only_cookies', Issue::CRITICAL);
    }

    public function test_strict_mode_disabled_is_warn(): void
    {
        $issues = $this->runCheck($this->ini(['session.use_strict_mode' => '0']));

        $this->assertCount(1, $issues);
        $this->assertFinding($issues, 'session.use_strict_mode', Issue::WARN);
    }

    public function test_sid_length_below_php_minimum_is_critical(): void
    {
        $issues = $this->runCheck($this->ini(['session.sid_length' => '16']));

        $this->assertNotEmpty($issues);
        $this->assertFinding($issues, 'session.sid_length', Issue::CRITICAL);
    }

    public function test_low_entropy_sid_is_warn(): void
    {
        $issues = $this->runCheck($this->ini([
            'session.sid_length'             => '24',
            'session.sid_bits_per_character' => '4',
        ]));

        $this->assertCount(1, $issues);
        $this->assertFinding($issues, 'entropy', Issue::WARN);
    }

    public function test_weak_fixture_reports_trans_sid_and_only_cookies(): void
    {
        $issues = $this->runCheck([
            'session.use_strict_mode'        => '0',
            'session.use_only_cookies'       => '0',
            'session.use_trans_sid'          => '1',
            'session.sid_length'             => '16',
            'session.sid_bits_per_character' => '4',
            'session.save_path'              => '',
        ]);

        $this->assertFinding($issues, 'session.use_trans_sid', Issue::CRITICAL);
        $this->assertFinding($issues, 'session.use_only_cookies', Issue::CRITICAL);
        $this->assertFinding($issues, 'session.use_strict_mode', Issue::WARN);
        $this->assertFinding($issues, 'session.sid_length', Issue::CRITICAL);
    }

    public function test_save_path_inside_public_is_critical(): void
    {
        mkdir($this->tempDir . '/public', 0777, true);
        file_put_contents($this->tempDir . '/public/index.php', "<?php\n");
        mkdir($this->tempDir . '/public/sessions', 0777, true);

        $issues = $this->runCheck($this->ini([
            'session.save_path' => $this->tempDir . '/public/sessions',
        ]));

        $this->assertCount(1, $issues);
        $this->assertFinding($issues, 'session.save_path', Issue::CRITICAL);
    }

    public function test_save_path_with_n_prefix_inside_public_is_critical(): void
    {
        mkdir($this->tempDir . '/public/sessions', 0777, true);

        $issues = $this->runCheck($this->ini([
            'session.save_path' => '2;600;' . $this->tempDir . '/public/sessions',
        ]));

        $this->assertCount(1, $issues);
        $this->assertFinding($issues, 'session.save_path', Issue::CRITICAL);
    }

    public function test_system_temp_save_path_is_clean(): void
    {
        $this->assertEmpty($this->runCheck($this->ini([
            'session.save_path' => sys_get_temp_dir(),
        ])));
    }

    public function test_laravel_findings_skipped_without_artisan(): void
    {
        mkdir($this->tempDir . '/config', 0777, true);
        file_put_contents($this->tempDir . '/config/session.php', <<<'PHP'
<?php
return [
    'driver' => 'cookie',
    'encrypt' => false,
];
PHP);

        $this->assertEmpty($this->runCheck($this->ini()), 'Laravel findings must not run without artisan + bootstrap/app.php.');
    }

    public function test_laravel_cookie_driver_without_encrypt_is_warn(): void
    {
        $this->makeLaravel();
        mkdir($this->tempDir . '/config', 0777, true);
        file_put_contents($this->tempDir . '/config/session.php', <<<'PHP'
<?php
return [
    'driver' => env('SESSION_DRIVER', 'cookie'),
    'encrypt' => env('SESSION_ENCRYPT', false),
    'files' => storage_path('framework/sessions'),
];
PHP);

        $issues = $this->runCheck($this->ini());

        $this->assertCount(1, $issues);
        $this->assertFinding($issues, 'cookie', Issue::WARN);
        $this->assertStringContainsString('encrypt', $issues[0]->message);
    }

    public function test_laravel_cookie_driver_with_encrypt_is_clean(): void
    {
        $this->makeLaravel();
        mkdir($this->tempDir . '/config', 0777, true);
        file_put_contents($this->tempDir . '/config/session.php', <<<'PHP'
<?php
return [
    'driver' => env('SESSION_DRIVER', 'cookie'),
    'encrypt' => env('SESSION_ENCRYPT', false),
    'files' => storage_path('framework/sessions'),
];
PHP);
        file_put_contents($this->tempDir . '/.env', "SESSION_DRIVER=cookie\nSESSION_ENCRYPT=true\n");

        $this->assertEmpty($this->runCheck($this->ini()));
    }

    public function test_laravel_file_driver_storage_path_is_clean(): void
    {
        $this->makeLaravel();
        mkdir($this->tempDir . '/config', 0777, true);
        file_put_contents($this->tempDir . '/config/session.php', <<<'PHP'
<?php
return [
    'driver' => env('SESSION_DRIVER', 'file'),
    'encrypt' => false,
    'files' => storage_path('framework/sessions'),
];
PHP);

        $this->assertEmpty($this->runCheck($this->ini()), 'Normal Laravel file sessions under storage/ are not a finding.');
    }

    public function test_laravel_file_driver_public_path_is_critical(): void
    {
        $this->makeLaravel();
        mkdir($this->tempDir . '/config', 0777, true);
        file_put_contents($this->tempDir . '/config/session.php', <<<'PHP'
<?php
return [
    'driver' => env('SESSION_DRIVER', 'file'),
    'encrypt' => false,
    'files' => public_path('sessions'),
];
PHP);

        $issues = $this->runCheck($this->ini());

        $this->assertCount(1, $issues);
        $this->assertFinding($issues, 'file session path', Issue::CRITICAL);
    }

    public function test_laravel_env_overrides_cookie_encrypt_false(): void
    {
        $this->makeLaravel();
        mkdir($this->tempDir . '/config', 0777, true);
        file_put_contents($this->tempDir . '/config/session.php', <<<'PHP'
<?php
return [
    'driver' => env('SESSION_DRIVER', 'file'),
    'encrypt' => env('SESSION_ENCRYPT', true),
    'files' => storage_path('framework/sessions'),
];
PHP);
        file_put_contents($this->tempDir . '/.env', "SESSION_DRIVER=cookie\nSESSION_ENCRYPT=false\n");

        $issues = $this->runCheck($this->ini());

        $this->assertCount(1, $issues);
        $this->assertFinding($issues, 'cookie', Issue::WARN);
    }

    public function test_does_not_report_cookie_flags(): void
    {
        $issues = $this->runCheck($this->ini([
            'session.cookie_secure'   => '0',
            'session.cookie_httponly' => '0',
            'session.cookie_samesite' => '',
        ]));

        $this->assertEmpty($issues, 'Secure / HttpOnly / SameSite belong to the cookie-flags check.');
    }

    public function test_runtime_constructor_returns_array(): void
    {
        ob_start();
        $result = (new SessionSecurityCheck())->run($this->tempDir);
        ob_end_clean();

        $this->assertIsArray($result);
        foreach ($result as $issue) {
            $this->assertInstanceOf(Issue::class, $issue);
            $this->assertSame('SessionSecurityCheck', $issue->check);
        }
    }

    public function test_user_ini_use_trans_sid_is_critical(): void
    {
        file_put_contents($this->tempDir . '/.user.ini', "session.use_trans_sid = 1\n");

        ob_start();
        $result = (new SessionSecurityCheck())->run($this->tempDir);
        ob_end_clean();

        $this->assertCount(1, $result);
        $this->assertSame(Issue::CRITICAL, $result[0]->severity);
        $this->assertSame(Issue::CONFIRMED, $result[0]->confidence);
        $this->assertStringContainsString('session.use_trans_sid is enabled', $result[0]->message);
        $this->assertSame('.user.ini', $result[0]->path);
    }

    public function test_scanner_process_ini_is_not_a_session_finding(): void
    {
        $previous = ini_get('session.use_trans_sid');
        ini_set('session.use_trans_sid', '1');

        ob_start();
        $result = (new SessionSecurityCheck())->run($this->tempDir);
        ob_end_clean();

        ini_set('session.use_trans_sid', $previous);

        $this->assertSame([], $result);
    }
}
