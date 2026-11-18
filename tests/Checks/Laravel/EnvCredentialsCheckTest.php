<?php

namespace Aquilinoflores\PhpSecCheck\Tests\Checks\Laravel;

use Aquilinoflores\PhpSecCheck\Checks\Laravel\EnvCredentialsCheck;
use Aquilinoflores\PhpSecCheck\Issue;
use Aquilinoflores\PhpSecCheck\Tests\Support\FakeGitStatus;
use InvalidArgumentException;
use PHPUnit\Framework\TestCase;

class EnvCredentialsCheckTest extends TestCase
{
    private string $tempDir;

    protected function setUp(): void
    {
        $this->tempDir = sys_get_temp_dir() . '/php-sec-check-env-test-' . uniqid();
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
     * @return list<Issue>
     */
    private function runCheck(?FakeGitStatus $git = null, array $customKeys = []): array
    {
        ob_start();
        $result = (new EnvCredentialsCheck($customKeys, $git))->run($this->tempDir);
        ob_end_clean();
        return $result;
    }

    private function writeEnv(string $contents): void
    {
        file_put_contents($this->tempDir . '/.env', $contents);
    }

    public function test_throws_when_custom_key_is_not_a_string(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageMatches('/must be strings/');
        new EnvCredentialsCheck([123]);
    }

    public function test_accepts_empty_custom_keys(): void
    {
        $this->assertInstanceOf(EnvCredentialsCheck::class, new EnvCredentialsCheck([]));
    }

    public function test_accepts_valid_string_custom_keys(): void
    {
        $this->assertInstanceOf(EnvCredentialsCheck::class, new EnvCredentialsCheck(['MY_SECRET']));
    }

    public function test_throws_on_empty_project_root(): void
    {
        $this->expectException(InvalidArgumentException::class);
        (new EnvCredentialsCheck())->run('');
    }

    public function test_throws_on_non_existent_project_root(): void
    {
        $this->expectException(InvalidArgumentException::class);
        (new EnvCredentialsCheck())->run('/this/does/not/exist');
    }

    public function test_returns_empty_when_no_env_file_and_nothing_leaked(): void
    {
        $result = $this->runCheck(new FakeGitStatus(repository: false));

        $this->assertEmpty($result);
    }

    public function test_normal_configured_secrets_are_not_findings(): void
    {
        $this->writeEnv("APP_KEY=base64:SomeSuperSecretKeyHere=\nDB_PASSWORD=correct-horse-battery\n");

        $result = $this->runCheck(new FakeGitStatus(
            repository: true,
            tracked: [],
            ignored: ['.env', '.env.local', '.env.production', '.env.staging', '.env.backup', '.env.testing'],
        ));

        $this->assertEmpty($result, 'A normal Laravel .env should not be treated as a leak.');
    }

    public function test_tracked_env_is_critical_even_when_gitignore_lists_it(): void
    {
        $this->writeEnv("APP_KEY=base64:SomeSuperSecretKeyHere=\n");

        $result = $this->runCheck(new FakeGitStatus(
            repository: true,
            tracked: ['.env'],
            ignored: ['.env'],
        ));

        $this->assertCount(1, $result);
        $this->assertSame(Issue::CRITICAL, $result[0]->severity);
        $this->assertStringContainsString('tracked by git', $result[0]->message);
        $this->assertStringContainsString('still tracked', $result[0]->message);
        $this->assertStringContainsString('git rm --cached', $result[0]->message);
    }

    public function test_tracked_env_without_ignore_rule_is_critical(): void
    {
        $this->writeEnv("APP_KEY=base64:SomeSuperSecretKeyHere=\n");

        $result = $this->runCheck(new FakeGitStatus(
            repository: true,
            tracked: ['.env'],
            ignored: [],
        ));

        $this->assertCount(1, $result);
        $this->assertSame(Issue::CRITICAL, $result[0]->severity);
        $this->assertStringContainsString('tracked by git', $result[0]->message);
        $this->assertStringNotContainsString('gitignore', strtolower($result[0]->message));
    }

    public function test_untracked_env_not_ignored_warns(): void
    {
        $this->writeEnv("APP_KEY=base64:SomeSuperSecretKeyHere=\n");

        $result = $this->runCheck(new FakeGitStatus(
            repository: true,
            tracked: [],
            ignored: [],
        ));

        $this->assertCount(1, $result);
        $this->assertSame(Issue::WARN, $result[0]->severity);
        $this->assertStringContainsString('not excluded from git tracking', $result[0]->message);
    }

    public function test_gitignore_listing_alone_is_not_enough_without_tracking_check(): void
    {
        $this->writeEnv("APP_KEY=base64:SomeSuperSecretKeyHere=\n");
        file_put_contents($this->tempDir . '/.gitignore', ".env\n");

        $result = $this->runCheck(new FakeGitStatus(
            repository: true,
            tracked: ['.env'],
            ignored: ['.env'],
        ));

        $this->assertNotEmpty($result);
        $this->assertSame(Issue::CRITICAL, $result[0]->severity);
        $this->assertStringContainsString('tracked', $result[0]->message);
    }

    public function test_public_env_copy_is_critical(): void
    {
        mkdir($this->tempDir . '/public', 0777, true);
        file_put_contents($this->tempDir . '/public/.env', "APP_KEY=base64:leaked=\n");

        $result = $this->runCheck(new FakeGitStatus(repository: false));

        $this->assertNotEmpty($result);
        $this->assertSame(Issue::CRITICAL, $result[0]->severity);
        $this->assertStringContainsString('public/.env', $result[0]->message);
        $this->assertStringContainsString('web-accessible', $result[0]->message);
    }

    public function test_env_next_to_root_index_php_is_critical(): void
    {
        $this->writeEnv("APP_KEY=base64:SomeSuperSecretKeyHere=\n");
        file_put_contents($this->tempDir . '/index.php', '<?php');

        $result = $this->runCheck(new FakeGitStatus(repository: false));

        $this->assertNotEmpty($result);
        $this->assertSame(Issue::CRITICAL, $result[0]->severity);
        $this->assertStringContainsString('index.php', $result[0]->message);
    }

    public function test_standard_laravel_layout_is_not_treated_as_public(): void
    {
        $this->writeEnv("APP_KEY=base64:SomeSuperSecretKeyHere=\n");
        mkdir($this->tempDir . '/public', 0777, true);
        file_put_contents($this->tempDir . '/public/index.php', '<?php');

        $result = $this->runCheck(new FakeGitStatus(repository: false));

        $this->assertEmpty($result);
    }

    public function test_empty_app_key_is_a_warning(): void
    {
        $this->writeEnv("APP_KEY=\nDB_PASSWORD=correct-horse-battery\n");

        $result = $this->runCheck(new FakeGitStatus(repository: false));

        $this->assertCount(1, $result);
        $this->assertSame(Issue::WARN, $result[0]->severity);
        $this->assertStringContainsString('APP_KEY is empty', $result[0]->message);
    }

    public function test_weak_password_is_a_warning(): void
    {
        $this->writeEnv("APP_KEY=base64:SomeSuperSecretKeyHere=\nDB_PASSWORD=password\n");

        $result = $this->runCheck(new FakeGitStatus(repository: false));

        $this->assertCount(1, $result);
        $this->assertSame(Issue::WARN, $result[0]->severity);
        $this->assertStringContainsString("'DB_PASSWORD'", $result[0]->message);
        $this->assertStringContainsString('weak', $result[0]->message);
    }

    public function test_empty_db_password_is_left_to_default_credentials_check(): void
    {
        $this->writeEnv("APP_KEY=base64:SomeSuperSecretKeyHere=\nDB_PASSWORD=\n");

        $result = $this->runCheck(new FakeGitStatus(repository: false));

        $this->assertEmpty($result);
    }

    public function test_env_example_with_placeholders_is_clean(): void
    {
        file_put_contents(
            $this->tempDir . '/.env.example',
            "APP_KEY=\nDB_PASSWORD=\nMAIL_PASSWORD=null\nSTRIPE_SECRET_KEY=\n"
        );

        $result = $this->runCheck(new FakeGitStatus(repository: false));

        $this->assertEmpty($result);
    }

    public function test_env_example_with_real_app_key_is_critical(): void
    {
        file_put_contents(
            $this->tempDir . '/.env.example',
            "APP_KEY=base64:ThisIsARealLookingApplicationKey=\nDB_PASSWORD=\n"
        );

        $result = $this->runCheck(new FakeGitStatus(repository: false));

        $this->assertCount(1, $result);
        $this->assertSame(Issue::CRITICAL, $result[0]->severity);
        $this->assertStringContainsString('.env.example', $result[0]->message);
        $this->assertStringContainsString('APP_KEY', $result[0]->message);
        $this->assertStringNotContainsString('ThisIsARealLookingApplicationKey', $result[0]->message);
    }

    public function test_env_example_with_stripe_live_key_is_critical(): void
    {
        file_put_contents(
            $this->tempDir . '/.env.example',
            "STRIPE_SECRET_KEY=sk_live_51ABCDEFGH1234567890\n"
        );

        $result = $this->runCheck(new FakeGitStatus(repository: false));

        $this->assertCount(1, $result);
        $this->assertSame(Issue::CRITICAL, $result[0]->severity);
        $this->assertStringContainsString('STRIPE_SECRET_KEY', $result[0]->message);
    }

    public function test_custom_keys_are_used_for_example_and_weak_scans(): void
    {
        $this->writeEnv("MY_SECRET_TOKEN=password\n");
        file_put_contents(
            $this->tempDir . '/.env.example',
            "CUSTOM_API_KEY=sk_live_customExampleKey99\n"
        );
        file_put_contents(
            $this->tempDir . '/php-sec-check-config.php',
            "<?php return ['sensitive_keys' => ['CUSTOM_API_KEY']];"
        );

        $result = $this->runCheck(new FakeGitStatus(repository: false), ['MY_SECRET_TOKEN']);

        $this->assertCount(2, $result);
        $messages = array_map(fn(Issue $i) => $i->message, $result);
        $this->assertTrue((bool) array_filter($messages, fn($m) => str_contains($m, 'MY_SECRET_TOKEN')));
        $this->assertTrue((bool) array_filter($messages, fn($m) => str_contains($m, 'CUSTOM_API_KEY')));
    }

    public function test_always_returns_array(): void
    {
        $this->writeEnv("APP_NAME=MyApp\n");
        $result = $this->runCheck(new FakeGitStatus(repository: false));
        $this->assertIsArray($result);
    }

    public function test_real_git_index_is_checked_not_just_gitignore(): void
    {
        if (!$this->gitAvailable()) {
            $this->markTestSkipped('git is not available');
        }

        $this->writeEnv("APP_KEY=base64:SomeSuperSecretKeyHere=\n");
        file_put_contents($this->tempDir . '/.gitignore', ".env\n");

        $this->git(['init']);
        $this->git(['add', '-f', '.env']);

        ob_start();
        $result = (new EnvCredentialsCheck())->run($this->tempDir);
        ob_end_clean();

        $this->assertNotEmpty($result);
        $this->assertSame(Issue::CRITICAL, $result[0]->severity);
        $this->assertStringContainsString('tracked by git', $result[0]->message);
        $this->assertStringContainsString('still tracked', $result[0]->message);
    }

    private function gitAvailable(): bool
    {
        exec('git --version', $output, $code);

        return $code === 0;
    }

    /**
     * @param list<string> $args
     */
    private function git(array $args): void
    {
        $cmd  = array_merge(['git', '-C', $this->tempDir], $args);
        $proc = proc_open(
            $cmd,
            [0 => ['pipe', 'r'], 1 => ['pipe', 'w'], 2 => ['pipe', 'w']],
            $pipes
        );
        $this->assertIsResource($proc);
        fclose($pipes[0]);
        $stdout = stream_get_contents($pipes[1]) ?: '';
        $stderr = stream_get_contents($pipes[2]) ?: '';
        fclose($pipes[1]);
        fclose($pipes[2]);
        $exit = proc_close($proc);
        $this->assertSame(0, $exit, 'git ' . implode(' ', $args) . " failed: {$stdout} {$stderr}");
    }
}
