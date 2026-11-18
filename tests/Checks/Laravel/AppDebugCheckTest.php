<?php

namespace Aquilinoflores\PhpSecCheck\Tests\Checks\Laravel;

use Aquilinoflores\PhpSecCheck\Checks\Laravel\AppDebugCheck;
use Aquilinoflores\PhpSecCheck\Issue;
use InvalidArgumentException;
use PHPUnit\Framework\TestCase;

class AppDebugCheckTest extends TestCase
{
    private AppDebugCheck $check;
    private string $tempDir;

    protected function setUp(): void
    {
        $this->check   = new AppDebugCheck();
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

    public function test_critical_when_debug_true_and_env_production(): void
    {
        $this->writeEnv("APP_ENV=production\nAPP_DEBUG=true\n");

        $result = $this->runSilently($this->tempDir);

        $this->assertCount(1, $result);
        $this->assertInstanceOf(Issue::class, $result[0]);
        $this->assertSame(Issue::CRITICAL, $result[0]->severity);
        $this->assertStringContainsString('production', $result[0]->message);
        $this->assertStringContainsString('stack traces', $result[0]->message);
    }

    public function test_critical_with_debug_set_to_1_and_env_production(): void
    {
        $this->writeEnv("APP_ENV=production\nAPP_DEBUG=1\n");

        $result = $this->runSilently($this->tempDir);

        $this->assertCount(1, $result);
        $this->assertSame(Issue::CRITICAL, $result[0]->severity);
    }

    public function test_critical_with_debug_set_to_on_and_env_production(): void
    {
        $this->writeEnv("APP_ENV=production\nAPP_DEBUG=on\n");

        $result = $this->runSilently($this->tempDir);

        $this->assertCount(1, $result);
        $this->assertSame(Issue::CRITICAL, $result[0]->severity);
    }

    public function test_warn_severity_when_debug_true_in_local_env(): void
    {
        $this->writeEnv("APP_ENV=local\nAPP_DEBUG=true\n");

        $result = $this->runSilently($this->tempDir);

        $this->assertCount(1, $result);
        $this->assertSame(Issue::WARN, $result[0]->severity);
        $this->assertStringContainsString('local', $result[0]->message);
        $this->assertStringNotContainsString('stack traces', $result[0]->message);
    }

    public function test_warns_when_debug_true_with_no_app_env(): void
    {
        $this->writeEnv("APP_DEBUG=true\n");

        $result = $this->runSilently($this->tempDir);

        $this->assertCount(1, $result);
        $this->assertSame(Issue::WARN, $result[0]->severity);
        $this->assertStringContainsString('unknown', $result[0]->message);
    }

    public function test_warns_when_debug_true_in_staging_env(): void
    {
        $this->writeEnv("APP_ENV=staging\nAPP_DEBUG=true\n");

        $result = $this->runSilently($this->tempDir);

        $this->assertCount(1, $result);
        $this->assertSame(Issue::WARN, $result[0]->severity);
        $this->assertStringContainsString('staging', $result[0]->message);
    }

    public function test_no_issue_when_debug_false(): void
    {
        $this->writeEnv("APP_ENV=production\nAPP_DEBUG=false\n");
        $this->assertEmpty($this->runSilently($this->tempDir));
    }

    public function test_no_issue_when_debug_set_to_zero(): void
    {
        $this->writeEnv("APP_ENV=production\nAPP_DEBUG=0\n");
        $this->assertEmpty($this->runSilently($this->tempDir));
    }

    public function test_no_issue_when_app_debug_not_present(): void
    {
        $this->writeEnv("APP_ENV=production\nAPP_NAME=MyApp\n");
        $this->assertEmpty($this->runSilently($this->tempDir));
    }

    public function test_always_returns_array(): void
    {
        $this->writeEnv("APP_DEBUG=false\n");
        $this->assertIsArray($this->runSilently($this->tempDir));
    }
}
