<?php

namespace Aquilinoflores\PhpSecCheck\Tests\Checks\Laravel;

use Aquilinoflores\PhpSecCheck\Checks\Laravel\DefaultCredentialsCheck;
use Aquilinoflores\PhpSecCheck\Issue;
use InvalidArgumentException;
use PHPUnit\Framework\TestCase;

class DefaultCredentialsCheckTest extends TestCase
{
    private DefaultCredentialsCheck $check;
    private string $tempDir;

    protected function setUp(): void
    {
        $this->check   = new DefaultCredentialsCheck();
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
        $this->assertStringContainsString('[DEFAULT CREDENTIALS]', $output);
    }

    public function test_always_returns_array(): void
    {
        $this->writeEnv('');
        $this->assertIsArray($this->runSilently($this->tempDir));
    }

    public function test_no_issue_when_credentials_are_safe(): void
    {
        $this->writeEnv("DB_USERNAME=myapp_user\nDB_PASSWORD=str0ngpassword!\nDB_HOST=127.0.0.1\n");
        $this->assertEmpty($this->runSilently($this->tempDir));
    }

    public function test_warn_on_root_username(): void
    {
        $this->writeEnv("DB_USERNAME=root\nDB_PASSWORD=str0ngpassword!\nDB_HOST=127.0.0.1\n");

        $result = $this->runSilently($this->tempDir);

        $userIssues = array_filter(
            $result,
            fn($i) => str_contains($i->message, 'DB_USERNAME')
        );

        $this->assertNotEmpty($userIssues);
        $issue = array_values($userIssues)[0];
        $this->assertSame(Issue::WARN, $issue->severity);
        $this->assertStringContainsString('root', $issue->message);
    }

    public function test_warn_on_admin_username(): void
    {
        $this->writeEnv("DB_USERNAME=admin\nDB_PASSWORD=secret\nDB_HOST=localhost\n");

        $result = $this->runSilently($this->tempDir);

        $userIssues = array_filter($result, fn($i) => str_contains($i->message, 'DB_USERNAME'));
        $this->assertNotEmpty($userIssues);
        $this->assertSame(Issue::WARN, array_values($userIssues)[0]->severity);
    }

    public function test_warn_on_postgres_username(): void
    {
        $this->writeEnv("DB_USERNAME=postgres\nDB_PASSWORD=str0ng\nDB_HOST=localhost\n");

        $result = $this->runSilently($this->tempDir);

        $userIssues = array_filter($result, fn($i) => str_contains($i->message, 'DB_USERNAME'));
        $this->assertNotEmpty($userIssues);
    }

    public function test_critical_on_empty_password(): void
    {
        $this->writeEnv("DB_USERNAME=myapp_user\nDB_PASSWORD=\nDB_HOST=localhost\n");

        $result = $this->runSilently($this->tempDir);

        $passIssues = array_filter($result, fn($i) => str_contains($i->message, 'DB_PASSWORD'));
        $this->assertNotEmpty($passIssues);
        $this->assertSame(Issue::CRITICAL, array_values($passIssues)[0]->severity);
    }

    public function test_critical_on_null_password(): void
    {
        $this->writeEnv("DB_USERNAME=myapp_user\nDB_PASSWORD=null\nDB_HOST=localhost\n");

        $result = $this->runSilently($this->tempDir);

        $passIssues = array_filter($result, fn($i) => str_contains($i->message, 'DB_PASSWORD'));
        $this->assertNotEmpty($passIssues);
        $this->assertSame(Issue::CRITICAL, array_values($passIssues)[0]->severity);
    }

    public function test_localhost_compound_warning_when_already_has_issues(): void
    {
        $this->writeEnv("DB_USERNAME=root\nDB_PASSWORD=\nDB_HOST=localhost\n");

        $result = $this->runSilently($this->tempDir);

        $localhostIssues = array_filter($result, fn($i) => str_contains($i->message, 'localhost'));
        $this->assertNotEmpty($localhostIssues);
        $this->assertSame(Issue::WARN, array_values($localhostIssues)[0]->severity);
    }

    public function test_no_localhost_warning_when_credentials_are_safe(): void
    {
        $this->writeEnv("DB_USERNAME=myapp\nDB_PASSWORD=str0ng!\nDB_HOST=localhost\n");

        $result = $this->runSilently($this->tempDir);

        $localhostIssues = array_filter($result, fn($i) => str_contains($i->message, 'localhost'));
        $this->assertEmpty($localhostIssues);
    }

    public function test_issue_objects_all_have_correct_check_name(): void
    {
        $this->writeEnv("DB_USERNAME=root\nDB_PASSWORD=\nDB_HOST=localhost\n");

        $result = $this->runSilently($this->tempDir);

        foreach ($result as $issue) {
            $this->assertSame('DefaultCredentialsCheck', $issue->check);
        }
    }
}
