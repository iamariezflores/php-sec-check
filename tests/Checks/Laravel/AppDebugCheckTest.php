<?php

namespace Aquilinoflores\PhpSecCheck\Tests\Checks\Laravel;

use Aquilinoflores\PhpSecCheck\Checks\Laravel\AppDebugCheck;
use InvalidArgumentException;
use PHPUnit\Framework\TestCase;

class AppDebugCheckTest extends TestCase
{
    private AppDebugCheck $check;
    private string $tempDir;

    protected function setUp(): void
    {
        $this->check = new AppDebugCheck();
        $this->tempDir = sys_get_temp_dir() . '/php-sec-check-debug-test-' . uniqid();
        mkdir($this->tempDir, 0777, true);
    }

    protected function tearDown(): void
    {
        foreach (array_diff(scandir($this->tempDir), ['.', '..']) as $item) {
            unlink($this->tempDir . DIRECTORY_SEPARATOR . $item);
        }
        rmdir($this->tempDir);
    }

    private function runSilently(string $projectRoot): array
    {
        ob_start();
        $result = $this->check->run($projectRoot);
        ob_end_clean();
        return $result;
    }

    private function writeEnv(string $contents): void
    {
        file_put_contents($this->tempDir . '/.env', $contents);
    }

    // -------------------------------------------------------------------------
    // Validation
    // -------------------------------------------------------------------------

    public function test_throws_on_empty_project_root(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->check->run('');
    }

    public function test_throws_on_non_existent_project_root(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->check->run('/this/does/not/exist');
    }

    // -------------------------------------------------------------------------
    // No .env file
    // -------------------------------------------------------------------------

    public function test_returns_empty_when_no_env_file(): void
    {
        $result = $this->runSilently($this->tempDir);
        $this->assertEmpty($result);
    }

    public function test_output_contains_header(): void
    {
        ob_start();
        $this->check->run($this->tempDir);
        $output = ob_get_clean();

        $this->assertStringContainsString('[APP DEBUG]', $output);
    }

    // -------------------------------------------------------------------------
    // Critical: APP_DEBUG=true + APP_ENV=production
    // -------------------------------------------------------------------------

    public function test_critical_when_debug_true_and_env_production(): void
    {
        $this->writeEnv("APP_ENV=production\nAPP_DEBUG=true\n");

        $result = $this->runSilently($this->tempDir);

        $this->assertCount(1, $result);
        $this->assertStringContainsString('APP_DEBUG is enabled', $result[0]);
        $this->assertStringContainsString('production', $result[0]);
        $this->assertStringContainsString('stack traces', $result[0]);
    }

    public function test_critical_with_debug_set_to_1_and_env_production(): void
    {
        $this->writeEnv("APP_ENV=production\nAPP_DEBUG=1\n");

        $result = $this->runSilently($this->tempDir);

        $this->assertCount(1, $result);
        $this->assertStringContainsString('production', $result[0]);
    }

    public function test_critical_with_debug_set_to_on_and_env_production(): void
    {
        $this->writeEnv("APP_ENV=production\nAPP_DEBUG=on\n");

        $result = $this->runSilently($this->tempDir);

        $this->assertCount(1, $result);
        $this->assertStringContainsString('production', $result[0]);
    }

    // -------------------------------------------------------------------------
    // Warning: APP_DEBUG=true but not production
    // -------------------------------------------------------------------------

    public function test_warns_when_debug_true_in_local_env(): void
    {
        $this->writeEnv("APP_ENV=local\nAPP_DEBUG=true\n");

        $result = $this->runSilently($this->tempDir);

        $this->assertCount(1, $result);
        $this->assertStringContainsString('APP_DEBUG is enabled', $result[0]);
        $this->assertStringContainsString('local', $result[0]);
        $this->assertStringNotContainsString('stack traces', $result[0]);
    }

    public function test_warns_when_debug_true_with_no_app_env(): void
    {
        $this->writeEnv("APP_DEBUG=true\n");

        $result = $this->runSilently($this->tempDir);

        $this->assertCount(1, $result);
        $this->assertStringContainsString('APP_DEBUG is enabled', $result[0]);
        $this->assertStringContainsString('unknown', $result[0]);
    }

    public function test_warns_when_debug_true_in_staging_env(): void
    {
        $this->writeEnv("APP_ENV=staging\nAPP_DEBUG=true\n");

        $result = $this->runSilently($this->tempDir);

        $this->assertCount(1, $result);
        $this->assertStringContainsString('staging', $result[0]);
    }

    // -------------------------------------------------------------------------
    // Clean: APP_DEBUG=false or not set
    // -------------------------------------------------------------------------

    public function test_no_issue_when_debug_false(): void
    {
        $this->writeEnv("APP_ENV=production\nAPP_DEBUG=false\n");

        $result = $this->runSilently($this->tempDir);

        $this->assertEmpty($result);
    }

    public function test_no_issue_when_debug_set_to_zero(): void
    {
        $this->writeEnv("APP_ENV=production\nAPP_DEBUG=0\n");

        $result = $this->runSilently($this->tempDir);

        $this->assertEmpty($result);
    }

    public function test_no_issue_when_app_debug_not_present(): void
    {
        $this->writeEnv("APP_ENV=production\nAPP_NAME=MyApp\n");

        $result = $this->runSilently($this->tempDir);

        $this->assertEmpty($result);
    }

    // -------------------------------------------------------------------------
    // Return type
    // -------------------------------------------------------------------------

    public function test_always_returns_array(): void
    {
        $this->writeEnv("APP_DEBUG=false\n");

        $result = $this->runSilently($this->tempDir);

        $this->assertIsArray($result);
    }
}
