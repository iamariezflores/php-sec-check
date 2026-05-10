<?php

namespace Aquilinoflores\PhpSecCheck\Tests\Checks\Laravel;

use Aquilinoflores\PhpSecCheck\Checks\Laravel\DefaultCredentialsCheck;
use InvalidArgumentException;
use PHPUnit\Framework\TestCase;

class DefaultCredentialsCheckTest extends TestCase
{
    private DefaultCredentialsCheck $check;
    private string $tempDir;

    protected function setUp(): void
    {
        $this->check = new DefaultCredentialsCheck();
        $this->tempDir = sys_get_temp_dir() . '/php-sec-check-creds-test-' . uniqid();
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

        $this->assertStringContainsString('[DEFAULT CREDENTIALS]', $output);
    }

    // -------------------------------------------------------------------------
    // Default username detection
    // -------------------------------------------------------------------------

    public function test_warns_when_db_username_is_root(): void
    {
        $this->writeEnv("DB_USERNAME=root\nDB_PASSWORD=strongpassword\n");

        $result = $this->runSilently($this->tempDir);

        $this->assertCount(1, $result);
        $this->assertStringContainsString('DB_USERNAME', $result[0]);
        $this->assertStringContainsString('root', $result[0]);
    }

    public function test_warns_when_db_username_is_admin(): void
    {
        $this->writeEnv("DB_USERNAME=admin\nDB_PASSWORD=strongpassword\n");

        $result = $this->runSilently($this->tempDir);

        $this->assertCount(1, $result);
        $this->assertStringContainsString('admin', $result[0]);
    }

    public function test_warns_when_db_username_is_postgres(): void
    {
        $this->writeEnv("DB_USERNAME=postgres\nDB_PASSWORD=strongpassword\n");

        $result = $this->runSilently($this->tempDir);

        $this->assertCount(1, $result);
        $this->assertStringContainsString('postgres', $result[0]);
    }

    public function test_warns_when_db_username_is_sa(): void
    {
        $this->writeEnv("DB_USERNAME=sa\nDB_PASSWORD=strongpassword\n");

        $result = $this->runSilently($this->tempDir);

        $this->assertCount(1, $result);
        $this->assertStringContainsString('sa', $result[0]);
    }

    public function test_no_warning_for_custom_username(): void
    {
        $this->writeEnv("DB_USERNAME=myapp_user\nDB_PASSWORD=strongpassword\n");

        $result = $this->runSilently($this->tempDir);

        $this->assertEmpty($result);
    }

    // -------------------------------------------------------------------------
    // Empty password detection
    // -------------------------------------------------------------------------

    public function test_warns_when_db_password_is_empty(): void
    {
        $this->writeEnv("DB_USERNAME=myapp_user\nDB_PASSWORD=\n");

        $result = $this->runSilently($this->tempDir);

        $this->assertCount(1, $result);
        $this->assertStringContainsString('DB_PASSWORD', $result[0]);
        $this->assertStringContainsString('empty', $result[0]);
    }

    public function test_warns_when_db_password_is_null(): void
    {
        $this->writeEnv("DB_USERNAME=myapp_user\nDB_PASSWORD=null\n");

        $result = $this->runSilently($this->tempDir);

        $this->assertCount(1, $result);
        $this->assertStringContainsString('DB_PASSWORD', $result[0]);
    }

    public function test_no_warning_when_db_password_is_set(): void
    {
        $this->writeEnv("DB_USERNAME=myapp_user\nDB_PASSWORD=Str0ng@Pass!\n");

        $result = $this->runSilently($this->tempDir);

        $this->assertEmpty($result);
    }

    // -------------------------------------------------------------------------
    // localhost + weak credentials combined warning
    // -------------------------------------------------------------------------

    public function test_warns_on_localhost_combined_with_weak_credentials(): void
    {
        $this->writeEnv("DB_HOST=localhost\nDB_USERNAME=root\nDB_PASSWORD=\n");

        $result = $this->runSilently($this->tempDir);

        // Expects: username warn + password warn + localhost compound warn
        $this->assertCount(3, $result);
        $messages = implode(' ', $result);
        $this->assertStringContainsString('localhost', $messages);
    }

    public function test_warns_on_127_0_0_1_combined_with_weak_credentials(): void
    {
        $this->writeEnv("DB_HOST=127.0.0.1\nDB_USERNAME=root\nDB_PASSWORD=\n");

        $result = $this->runSilently($this->tempDir);

        $this->assertCount(3, $result);
    }

    public function test_no_localhost_warning_when_credentials_are_strong(): void
    {
        // localhost alone is fine — only flagged when combined with weak credentials
        $this->writeEnv("DB_HOST=localhost\nDB_USERNAME=myapp_user\nDB_PASSWORD=Str0ng@Pass!\n");

        $result = $this->runSilently($this->tempDir);

        $this->assertEmpty($result);
    }

    // -------------------------------------------------------------------------
    // Multiple issues
    // -------------------------------------------------------------------------

    public function test_reports_both_username_and_password_issues(): void
    {
        $this->writeEnv("DB_USERNAME=root\nDB_PASSWORD=\n");

        $result = $this->runSilently($this->tempDir);

        $this->assertCount(2, $result);
    }

    // -------------------------------------------------------------------------
    // Return type
    // -------------------------------------------------------------------------

    public function test_always_returns_array(): void
    {
        $this->writeEnv("DB_USERNAME=myapp_user\nDB_PASSWORD=secure\n");

        $result = $this->runSilently($this->tempDir);

        $this->assertIsArray($result);
    }
}
