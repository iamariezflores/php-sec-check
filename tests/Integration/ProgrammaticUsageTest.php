<?php

namespace Aquilinoflores\PhpSecCheck\Tests\Integration;

use Aquilinoflores\PhpSecCheck\Checks\CheckInterface;
use Aquilinoflores\PhpSecCheck\Checks\ComposerAuditCheck;
use Aquilinoflores\PhpSecCheck\Checks\DangerousFunctionsCheck;
use Aquilinoflores\PhpSecCheck\Checks\DisplayErrorsCheck;
use Aquilinoflores\PhpSecCheck\Checks\PhpVersionCheck;
use Aquilinoflores\PhpSecCheck\Checks\Laravel\EnvCredentialsCheck;
use Aquilinoflores\PhpSecCheck\Checks\Laravel\VendorCheck;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * Programmatic Usage Tests
 *
 * These tests verify the public API surface of all checks as a downstream
 * developer would use them — instantiating checks directly, injecting
 * configuration, and collecting results without the CLI runner.
 */
class ProgrammaticUsageTest extends TestCase
{
    private string $tempDir;

    protected function setUp(): void
    {
        $this->tempDir = sys_get_temp_dir() . '/php-sec-check-integration-' . uniqid();
        mkdir($this->tempDir, 0777, true);
    }

    protected function tearDown(): void
    {
        $this->removeTempDir($this->tempDir);
    }

    private function removeTempDir(string $dir): void
    {
        if (!is_dir($dir)) {
            return;
        }
        foreach (array_diff(scandir($dir), ['.', '..']) as $item) {
            $path = $dir . DIRECTORY_SEPARATOR . $item;
            is_dir($path) ? $this->removeTempDir($path) : unlink($path);
        }
        rmdir($dir);
    }

    private function runSilently(CheckInterface $check, string $root): array
    {
        ob_start();
        $result = $check->run($root);
        ob_end_clean();
        return $result;
    }

    // -------------------------------------------------------------------------
    // CheckInterface contract
    // -------------------------------------------------------------------------

    #[DataProvider('allChecksProvider')]
    public function test_every_check_implements_check_interface(CheckInterface $check): void
    {
        $this->assertInstanceOf(CheckInterface::class, $check);
    }

    #[DataProvider('allChecksProvider')]
    public function test_every_check_returns_an_array(CheckInterface $check): void
    {
        $result = $this->runSilently($check, $this->tempDir);
        $this->assertIsArray($result);
    }

    public static function allChecksProvider(): array
    {
        return [
            'PhpVersionCheck'       => [new PhpVersionCheck()],
            'DisplayErrorsCheck'    => [new DisplayErrorsCheck()],
            'ComposerAuditCheck'    => [new ComposerAuditCheck()],
            'DangerousFunctionsCheck' => [new DangerousFunctionsCheck()],
            'EnvCredentialsCheck'   => [new EnvCredentialsCheck()],
            'VendorCheck'           => [new VendorCheck()],
        ];
    }

    // -------------------------------------------------------------------------
    // Running all checks together and merging results
    // -------------------------------------------------------------------------

    public function test_all_checks_can_run_together_and_results_merged(): void
    {
        // This mirrors the pattern shown in the programmatic usage docs.
        $checks = [
            new PhpVersionCheck(),
            new DisplayErrorsCheck(),
            new ComposerAuditCheck(),
            new DangerousFunctionsCheck(),
            new EnvCredentialsCheck(),
            new VendorCheck(),
        ];

        $allIssues = [];

        ob_start();
        foreach ($checks as $check) {
            $allIssues = array_merge($allIssues, $check->run($this->tempDir));
        }
        ob_end_clean();

        $this->assertIsArray($allIssues);
    }

    public function test_merged_results_only_contain_strings(): void
    {
        $checks = [
            new PhpVersionCheck(),
            new DisplayErrorsCheck(),
            new DangerousFunctionsCheck(''),
            new EnvCredentialsCheck(),
            new VendorCheck(),
        ];

        $allIssues = [];

        ob_start();
        foreach ($checks as $check) {
            $allIssues = array_merge($allIssues, $check->run($this->tempDir));
        }
        ob_end_clean();

        foreach ($allIssues as $issue) {
            $this->assertIsString($issue, 'Every issue in merged results must be a string.');
        }
    }

    // -------------------------------------------------------------------------
    // EnvCredentialsCheck — custom key injection
    // -------------------------------------------------------------------------

    public function test_env_check_with_custom_keys_injected(): void
    {
        file_put_contents($this->tempDir . '/.env', "MY_API_TOKEN=supersecrettoken\n");

        $check = new EnvCredentialsCheck(['MY_API_TOKEN']);
        $results = $this->runSilently($check, $this->tempDir);

        $this->assertCount(1, $results);
        $this->assertStringContainsString("'MY_API_TOKEN'", $results[0]);
    }

    public function test_env_check_custom_keys_merged_with_config_keys(): void
    {
        file_put_contents($this->tempDir . '/.env',
            "STRIPE_SECRET_KEY=sk_live_abc\nMY_CUSTOM_KEY=somevalue\n"
        );
        file_put_contents($this->tempDir . '/php-sec-check-config.php', <<<'PHP'
<?php
return ['sensitive_keys' => ['STRIPE_SECRET_KEY']];
PHP);

        $check = new EnvCredentialsCheck(['MY_CUSTOM_KEY']);
        $results = $this->runSilently($check, $this->tempDir);

        $this->assertCount(2, $results);

        $keys = array_map(fn($r) => preg_match("/'([^']+)'/", $r, $m) ? $m[1] : '', $results);
        $this->assertContains('STRIPE_SECRET_KEY', $keys);
        $this->assertContains('MY_CUSTOM_KEY', $keys);
    }

    public function test_env_check_returns_empty_array_when_no_sensitive_values_set(): void
    {
        file_put_contents($this->tempDir . '/.env',
            "APP_KEY=null\nDB_PASSWORD=\n"
        );

        $check = new EnvCredentialsCheck(['APP_KEY', 'DB_PASSWORD']);
        $results = $this->runSilently($check, $this->tempDir);

        $this->assertEmpty($results);
    }

    // -------------------------------------------------------------------------
    // DangerousFunctionsCheck — explicit disable_functions injection
    // -------------------------------------------------------------------------

    public function test_dangerous_functions_check_with_injected_config(): void
    {
        // Simulates reading disable_functions from a staging server config
        // rather than the runtime php.ini.
        $check = new DangerousFunctionsCheck('exec,shell_exec,system');
        $results = $this->runSilently($check, $this->tempDir);

        $reported = array_map(
            fn($issue) => str_replace('Dangerous function enabled: ', '', $issue),
            $results
        );

        $this->assertNotContains('exec', $reported);
        $this->assertNotContains('shell_exec', $reported);
        $this->assertNotContains('system', $reported);

        // Functions not in the injected list should still be flagged.
        $this->assertContains('eval', $reported);
        $this->assertContains('proc_open', $reported);
    }

    public function test_dangerous_functions_check_with_all_functions_disabled(): void
    {
        $allDisabled = implode(',', DangerousFunctionsCheck::DANGEROUS_FUNCTIONS);

        $check = new DangerousFunctionsCheck($allDisabled);
        $results = $this->runSilently($check, $this->tempDir);

        $this->assertEmpty($results, 'No issues should be reported when all dangerous functions are disabled.');
    }

    public function test_dangerous_functions_check_default_reads_runtime_ini(): void
    {
        // No injection — falls back to php.ini at runtime.
        $check = new DangerousFunctionsCheck();
        $results = $this->runSilently($check, $this->tempDir);

        $this->assertIsArray($results);
    }

    // -------------------------------------------------------------------------
    // VendorCheck — programmatic usage
    // -------------------------------------------------------------------------

    public function test_vendor_check_clean_project_returns_empty(): void
    {
        // No vendor/ directory present — no issues.
        $check = new VendorCheck();
        $results = $this->runSilently($check, $this->tempDir);

        $this->assertEmpty($results);
    }

    public function test_vendor_check_flags_uncommitted_vendor_dir(): void
    {
        mkdir($this->tempDir . '/vendor', 0777, true);
        // No .gitignore — vendor/ is untracked.

        $check = new VendorCheck();
        $results = $this->runSilently($check, $this->tempDir);

        $this->assertCount(1, $results);
        $this->assertStringContainsString('vendor/', $results[0]);
    }

    public function test_vendor_check_passes_when_vendor_in_gitignore(): void
    {
        mkdir($this->tempDir . '/vendor', 0777, true);
        file_put_contents($this->tempDir . '/.gitignore', "vendor/\n");

        $check = new VendorCheck();
        $results = $this->runSilently($check, $this->tempDir);

        $this->assertEmpty($results);
    }

    // -------------------------------------------------------------------------
    // ComposerAuditCheck — programmatic usage
    // -------------------------------------------------------------------------

    public function test_composer_audit_returns_empty_without_lock_file(): void
    {
        $check = new ComposerAuditCheck();
        $results = $this->runSilently($check, $this->tempDir);

        $this->assertEmpty($results);
    }

    public function test_composer_audit_returns_array_with_lock_file_present(): void
    {
        file_put_contents($this->tempDir . '/composer.lock', json_encode([
            'packages' => [],
            'packages-dev' => [],
        ]));

        $check = new ComposerAuditCheck();
        $results = $this->runSilently($check, $this->tempDir);

        $this->assertIsArray($results);
    }
}
