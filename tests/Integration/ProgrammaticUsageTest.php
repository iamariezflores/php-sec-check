<?php

namespace Aquilinoflores\PhpSecCheck\Tests\Integration;

use Aquilinoflores\PhpSecCheck\Checks\CheckInterface;
use Aquilinoflores\PhpSecCheck\Checks\ComposerAuditCheck;
use Aquilinoflores\PhpSecCheck\Checks\DangerousFunctionsCheck;
use Aquilinoflores\PhpSecCheck\Checks\DisplayErrorsCheck;
use Aquilinoflores\PhpSecCheck\Checks\PhpVersionCheck;
use Aquilinoflores\PhpSecCheck\Checks\Laravel\AppDebugCheck;
use Aquilinoflores\PhpSecCheck\Checks\Laravel\DefaultCredentialsCheck;
use Aquilinoflores\PhpSecCheck\Checks\Laravel\EnvCredentialsCheck;
use Aquilinoflores\PhpSecCheck\Checks\Laravel\VendorCheck;
use Aquilinoflores\PhpSecCheck\Issue;
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
            'PhpVersionCheck'         => [new PhpVersionCheck()],
            'DisplayErrorsCheck'      => [new DisplayErrorsCheck()],
            'ComposerAuditCheck'      => [new ComposerAuditCheck()],
            'DangerousFunctionsCheck' => [new DangerousFunctionsCheck()],
            'EnvCredentialsCheck'     => [new EnvCredentialsCheck()],
            'VendorCheck'             => [new VendorCheck()],
            'AppDebugCheck'           => [new AppDebugCheck()],
            'DefaultCredentialsCheck' => [new DefaultCredentialsCheck()],
        ];
    }

    // -------------------------------------------------------------------------
    // Running all checks together and merging results
    // -------------------------------------------------------------------------

    public function test_all_checks_can_run_together_and_results_merged(): void
    {
        $checks = [
            new PhpVersionCheck(),
            new DisplayErrorsCheck(),
            new ComposerAuditCheck(),
            new DangerousFunctionsCheck(),
            new EnvCredentialsCheck(),
            new VendorCheck(),
            new AppDebugCheck(),
            new DefaultCredentialsCheck(),
        ];

        $allIssues = [];

        ob_start();
        foreach ($checks as $check) {
            $allIssues = array_merge($allIssues, $check->run($this->tempDir));
        }
        ob_end_clean();

        $this->assertIsArray($allIssues);
    }

    public function test_merged_results_only_contain_issue_objects(): void
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
            $this->assertInstanceOf(Issue::class, $issue, 'Every item in merged results must be an Issue object.');
        }
    }

    public function test_issue_severity_is_one_of_the_known_constants(): void
    {
        $checks = [
            new PhpVersionCheck(),
            new DisplayErrorsCheck(),
            new DangerousFunctionsCheck(''),
        ];

        $allIssues = [];

        ob_start();
        foreach ($checks as $check) {
            $allIssues = array_merge($allIssues, $check->run($this->tempDir));
        }
        ob_end_clean();

        $validSeverities = [Issue::CRITICAL, Issue::WARN, Issue::INFO];

        foreach ($allIssues as $issue) {
            $this->assertContains(
                $issue->severity,
                $validSeverities,
                "Issue severity '{$issue->severity}' is not a known constant."
            );
        }
    }

    public function test_issue_toArray_contains_required_keys(): void
    {
        file_put_contents($this->tempDir . '/.env', "MY_TOKEN=secret\n");

        $issues = $this->runSilently(new EnvCredentialsCheck(['MY_TOKEN']), $this->tempDir);

        $this->assertNotEmpty($issues);
        $arr = $issues[0]->toArray();

        $this->assertArrayHasKey('severity', $arr);
        $this->assertArrayHasKey('message', $arr);
        $this->assertArrayHasKey('check', $arr);
    }

    public function test_issue_to_string_returns_message(): void
    {
        file_put_contents($this->tempDir . '/.env', "MY_TOKEN=secret\n");

        $issues = $this->runSilently(new EnvCredentialsCheck(['MY_TOKEN']), $this->tempDir);

        $this->assertNotEmpty($issues);
        $this->assertSame($issues[0]->message, (string) $issues[0]);
    }

    // -------------------------------------------------------------------------
    // EnvCredentialsCheck — custom key injection
    // -------------------------------------------------------------------------

    public function test_env_check_does_not_flag_normal_custom_secrets(): void
    {
        file_put_contents($this->tempDir . '/.env', "MY_API_TOKEN=supersecrettoken\nAPP_KEY=base64:SomeSuperSecretKeyHere=\n");

        $results = $this->runSilently(new EnvCredentialsCheck(['MY_API_TOKEN']), $this->tempDir);

        $this->assertEmpty($results, 'A configured custom secret in .env is expected, not a finding.');
    }

    public function test_env_check_custom_keys_used_for_example_leaks_and_weak_values(): void
    {
        file_put_contents($this->tempDir . '/.env', "MY_CUSTOM_KEY=password\n");
        file_put_contents(
            $this->tempDir . '/.env.example',
            "STRIPE_SECRET_KEY=sk_live_51ABCDEFGH1234567890\n"
        );
        file_put_contents($this->tempDir . '/php-sec-check-config.php', <<<'PHP'
<?php
return ['sensitive_keys' => ['STRIPE_SECRET_KEY']];
PHP);

        $results = $this->runSilently(new EnvCredentialsCheck(['MY_CUSTOM_KEY']), $this->tempDir);

        $this->assertCount(2, $results);

        $messages = array_map(fn(Issue $r) => $r->message, $results);
        $this->assertTrue((bool) array_filter($messages, fn($m) => str_contains($m, 'MY_CUSTOM_KEY')));
        $this->assertTrue((bool) array_filter($messages, fn($m) => str_contains($m, 'STRIPE_SECRET_KEY')));
    }

    public function test_env_check_returns_empty_when_secrets_are_normally_configured(): void
    {
        file_put_contents($this->tempDir . '/.env', "APP_KEY=base64:SomeSuperSecretKeyHere=\nDB_PASSWORD=correct-horse-battery\n");

        $results = $this->runSilently(new EnvCredentialsCheck(['APP_KEY', 'DB_PASSWORD']), $this->tempDir);

        $this->assertEmpty($results);
    }

    // -------------------------------------------------------------------------
    // DangerousFunctionsCheck — explicit disable_functions injection
    // -------------------------------------------------------------------------

    public function test_dangerous_functions_check_with_injected_config(): void
    {
        $results = $this->runSilently(
            new DangerousFunctionsCheck('exec,shell_exec,system'),
            $this->tempDir
        );

        $reported = array_map(
            fn(Issue $issue) => str_replace('Dangerous function enabled: ', '', $issue->message),
            $results
        );

        $this->assertNotContains('exec', $reported);
        $this->assertNotContains('shell_exec', $reported);
        $this->assertNotContains('system', $reported);
        $this->assertContains('eval', $reported);
        $this->assertContains('proc_open', $reported);
    }

    public function test_dangerous_functions_check_with_all_functions_disabled(): void
    {
        $allDisabled = implode(',', DangerousFunctionsCheck::DANGEROUS_FUNCTIONS);

        $results = $this->runSilently(new DangerousFunctionsCheck($allDisabled), $this->tempDir);

        $this->assertEmpty($results, 'No issues should be reported when all dangerous functions are disabled.');
    }

    public function test_dangerous_functions_check_default_reads_runtime_ini(): void
    {
        $results = $this->runSilently(new DangerousFunctionsCheck(), $this->tempDir);
        $this->assertIsArray($results);
    }

    // -------------------------------------------------------------------------
    // VendorCheck — programmatic usage
    // -------------------------------------------------------------------------

    public function test_vendor_check_clean_project_returns_empty(): void
    {
        $results = $this->runSilently(new VendorCheck(), $this->tempDir);
        $this->assertEmpty($results);
    }

    public function test_vendor_check_flags_uncommitted_vendor_dir(): void
    {
        mkdir($this->tempDir . '/vendor', 0777, true);

        $results = $this->runSilently(new VendorCheck(), $this->tempDir);

        $this->assertCount(1, $results);
        $this->assertInstanceOf(Issue::class, $results[0]);
        $this->assertStringContainsString('vendor/', $results[0]->message);
    }

    public function test_vendor_check_passes_when_vendor_in_gitignore(): void
    {
        mkdir($this->tempDir . '/vendor', 0777, true);
        file_put_contents($this->tempDir . '/.gitignore', "vendor/\n");

        $results = $this->runSilently(new VendorCheck(), $this->tempDir);
        $this->assertEmpty($results);
    }

    // -------------------------------------------------------------------------
    // AppDebugCheck — programmatic usage
    // -------------------------------------------------------------------------

    public function test_app_debug_check_critical_when_production_debug_on(): void
    {
        file_put_contents($this->tempDir . '/.env', "APP_ENV=production\nAPP_DEBUG=true\n");

        $results = $this->runSilently(new AppDebugCheck(), $this->tempDir);

        $this->assertCount(1, $results);
        $this->assertSame(Issue::CRITICAL, $results[0]->severity);
        $this->assertSame('AppDebugCheck', $results[0]->check);
    }

    public function test_app_debug_check_returns_empty_when_debug_off(): void
    {
        file_put_contents($this->tempDir . '/.env', "APP_ENV=production\nAPP_DEBUG=false\n");

        $results = $this->runSilently(new AppDebugCheck(), $this->tempDir);
        $this->assertEmpty($results);
    }

    // -------------------------------------------------------------------------
    // DefaultCredentialsCheck — programmatic usage
    // -------------------------------------------------------------------------

    public function test_default_credentials_check_critical_on_empty_password(): void
    {
        file_put_contents($this->tempDir . '/.env',
            "DB_USERNAME=myapp\nDB_PASSWORD=\nDB_HOST=localhost\n"
        );

        $results = $this->runSilently(new DefaultCredentialsCheck(), $this->tempDir);

        $passIssues = array_filter($results, fn($i) => str_contains($i->message, 'DB_PASSWORD'));
        $this->assertNotEmpty($passIssues);
        $this->assertSame(Issue::CRITICAL, array_values($passIssues)[0]->severity);
    }

    public function test_default_credentials_check_clean_project(): void
    {
        file_put_contents($this->tempDir . '/.env',
            "DB_USERNAME=appuser\nDB_PASSWORD=str0ngP@ss\nDB_HOST=db.example.com\n"
        );

        $results = $this->runSilently(new DefaultCredentialsCheck(), $this->tempDir);
        $this->assertEmpty($results);
    }

    // -------------------------------------------------------------------------
    // ComposerAuditCheck — programmatic usage
    // -------------------------------------------------------------------------

    public function test_composer_audit_returns_empty_without_lock_file(): void
    {
        $results = $this->runSilently(new ComposerAuditCheck(), $this->tempDir);
        $this->assertEmpty($results);
    }

    public function test_composer_audit_returns_array_with_lock_file_present(): void
    {
        file_put_contents($this->tempDir . '/composer.lock', json_encode([
            'packages'     => [],
            'packages-dev' => [],
        ]));

        $results = $this->runSilently(new ComposerAuditCheck(), $this->tempDir);
        $this->assertIsArray($results);
    }
}
