<?php

namespace Aquilinoflores\PhpSecCheck\Tests\Checks;

use Aquilinoflores\PhpSecCheck\Checks\DirectoryExposureCheck;
use Aquilinoflores\PhpSecCheck\Issue;
use Aquilinoflores\PhpSecCheck\Tests\Support\FakeGitStatus;
use PHPUnit\Framework\TestCase;

class DirectoryExposureCheckTest extends TestCase
{
    private string $tempDir;

    protected function setUp(): void
    {
        $this->tempDir = sys_get_temp_dir() . '/php-sec-check-dir-exp-' . uniqid();
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
            if (is_link($path)) {
                @unlink($path);
                continue;
            }
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
    private function runCheck(?FakeGitStatus $git = null): array
    {
        ob_start();
        $result = (new DirectoryExposureCheck($git ?? new FakeGitStatus(repository: false)))->run($this->tempDir);
        ob_end_clean();
        return $result;
    }

    private function laravelPublic(): void
    {
        mkdir($this->tempDir . '/public', 0777, true);
        file_put_contents($this->tempDir . '/public/index.php', "<?php\n");
    }

    /**
     * @param list<Issue> $issues
     */
    private function assertFinding(array $issues, string $pathFragment, string $severity): Issue
    {
        foreach ($issues as $issue) {
            if (str_contains($issue->message, $pathFragment)) {
                $this->assertSame($severity, $issue->severity, $issue->message);
                $this->assertSame('DirectoryExposureCheck', $issue->check);
                return $issue;
            }
        }

        $this->fail("Expected a finding mentioning '{$pathFragment}', got: " . json_encode(
            array_map(fn(Issue $i) => $i->message, $issues)
        ));
    }

    public function test_returns_empty_when_no_document_root(): void
    {
        $this->assertEmpty($this->runCheck());
    }

    public function test_normal_laravel_public_index_is_clean(): void
    {
        $this->laravelPublic();

        $this->assertEmpty($this->runCheck(), 'A normal Laravel public/index.php must not be a finding.');
    }

    public function test_public_git_is_critical(): void
    {
        $this->laravelPublic();
        mkdir($this->tempDir . '/public/.git', 0777, true);
        file_put_contents($this->tempDir . '/public/.git/HEAD', "ref: refs/heads/main\n");

        $issues = $this->runCheck();

        $this->assertCount(1, $issues);
        $this->assertFinding($issues, 'public/.git', Issue::CRITICAL);
    }

    public function test_public_vendor_is_critical(): void
    {
        $this->laravelPublic();
        mkdir($this->tempDir . '/public/vendor', 0777, true);
        file_put_contents($this->tempDir . '/public/vendor/autoload.php', "<?php\n");

        $issues = $this->runCheck();

        $this->assertCount(1, $issues);
        $this->assertFinding($issues, 'public/vendor', Issue::CRITICAL);
    }

    public function test_root_vendor_is_not_a_directory_exposure_finding(): void
    {
        $this->laravelPublic();
        mkdir($this->tempDir . '/vendor', 0777, true);
        file_put_contents($this->tempDir . '/vendor/autoload.php', "<?php\n");
        file_put_contents($this->tempDir . '/.gitignore', "vendor/\n");

        $issues = $this->runCheck(new FakeGitStatus(
            repository: true,
            tracked: [],
            ignored: ['vendor', 'vendor/'],
        ));

        $this->assertEmpty($issues, 'Project-root vendor/ belongs to VendorCheck, not directory exposure.');
    }

    public function test_public_env_is_not_double_counted(): void
    {
        $this->laravelPublic();
        file_put_contents($this->tempDir . '/public/.env', "APP_KEY=base64:SomeSuperSecretKeyHere=\n");
        file_put_contents($this->tempDir . '/public/.env.local', "APP_KEY=base64:SomeSuperSecretKeyHere=\n");

        $issues = $this->runCheck();

        $this->assertEmpty($issues, 'public/.env stays an EnvCredentialsCheck finding.');
    }

    public function test_phpinfo_in_public_is_critical(): void
    {
        $this->laravelPublic();
        file_put_contents($this->tempDir . '/public/phpinfo.php', "<?php phpinfo();\n");

        $issues = $this->runCheck();

        $this->assertCount(1, $issues);
        $this->assertFinding($issues, 'public/phpinfo.php', Issue::CRITICAL);
    }

    public function test_sql_dump_in_public_is_critical(): void
    {
        $this->laravelPublic();
        file_put_contents($this->tempDir . '/public/dump.sql', "CREATE TABLE users;\n");

        $issues = $this->runCheck();

        $this->assertCount(1, $issues);
        $this->assertFinding($issues, 'public/dump.sql', Issue::CRITICAL);
    }

    public function test_log_file_in_public_is_warn(): void
    {
        $this->laravelPublic();
        file_put_contents($this->tempDir . '/public/app.log', "error\n");

        $issues = $this->runCheck();

        $this->assertCount(1, $issues);
        $this->assertFinding($issues, 'public/app.log', Issue::WARN);
    }

    public function test_composer_json_in_public_is_warn(): void
    {
        $this->laravelPublic();
        file_put_contents($this->tempDir . '/public/composer.json', "{}\n");

        $issues = $this->runCheck();

        $this->assertCount(1, $issues);
        $this->assertFinding($issues, 'public/composer.json', Issue::WARN);
    }

    public function test_htaccess_backup_in_public_is_warn(): void
    {
        $this->laravelPublic();
        file_put_contents($this->tempDir . '/public/.htaccess.bak', "Deny from all\n");

        $issues = $this->runCheck();

        $this->assertCount(1, $issues);
        $this->assertFinding($issues, 'public/.htaccess.bak', Issue::WARN);
    }

    public function test_backup_directory_in_public_is_critical(): void
    {
        $this->laravelPublic();
        mkdir($this->tempDir . '/public/backup', 0777, true);
        file_put_contents($this->tempDir . '/public/backup/site.sql', "CREATE TABLE x;\n");

        $issues = $this->runCheck();

        $this->assertCount(1, $issues);
        $this->assertFinding($issues, 'public/backup', Issue::CRITICAL);
    }

    public function test_laravel_storage_link_is_not_a_finding(): void
    {
        $this->laravelPublic();
        mkdir($this->tempDir . '/storage/app/public', 0777, true);
        file_put_contents($this->tempDir . '/storage/app/public/photo.jpg', 'img');

        $link = $this->tempDir . '/public/storage';
        if (!@symlink($this->tempDir . '/storage/app/public', $link)) {
            $this->markTestSkipped('Cannot create symlinks on this system.');
        }

        $this->assertEmpty($this->runCheck(), 'Laravel public/storage symlink must not be flagged.');
    }

    public function test_real_storage_directory_in_document_root_is_critical(): void
    {
        $this->laravelPublic();
        mkdir($this->tempDir . '/public/storage/logs', 0777, true);
        file_put_contents($this->tempDir . '/public/storage/logs/laravel.log', "error\n");

        $issues = $this->runCheck();

        $this->assertNotEmpty($issues);
        $this->assertFinding($issues, 'public/storage', Issue::CRITICAL);
    }

    public function test_gitignore_does_not_hide_a_public_vendor_directory(): void
    {
        $this->laravelPublic();
        mkdir($this->tempDir . '/public/vendor', 0777, true);
        file_put_contents($this->tempDir . '/.gitignore', "public/vendor\n");

        $issues = $this->runCheck(new FakeGitStatus(
            repository: true,
            tracked: [],
            ignored: ['public/vendor'],
        ));

        $this->assertCount(1, $issues);
        $issue = $this->assertFinding($issues, 'public/vendor', Issue::CRITICAL);
        $this->assertStringContainsString('ignore rules', $issue->message);
        $this->assertStringContainsString('web server', $issue->message);
    }

    public function test_tracked_public_vendor_mentions_git(): void
    {
        $this->laravelPublic();
        mkdir($this->tempDir . '/public/vendor', 0777, true);

        $issues = $this->runCheck(new FakeGitStatus(
            repository: true,
            tracked: ['public/vendor'],
            ignored: [],
        ));

        $this->assertCount(1, $issues);
        $issue = $this->assertFinding($issues, 'public/vendor', Issue::CRITICAL);
        $this->assertStringContainsString('tracked by git', $issue->message);
    }

    public function test_tracked_composer_json_is_promoted_to_critical(): void
    {
        $this->laravelPublic();
        file_put_contents($this->tempDir . '/public/composer.json', "{}\n");

        $issues = $this->runCheck(new FakeGitStatus(
            repository: true,
            tracked: ['public/composer.json'],
        ));

        $this->assertCount(1, $issues);
        $this->assertFinding($issues, 'public/composer.json', Issue::CRITICAL);
    }

    public function test_generic_php_root_index_flags_adjacent_git(): void
    {
        file_put_contents($this->tempDir . '/index.php', "<?php\n");
        mkdir($this->tempDir . '/.git', 0777, true);
        file_put_contents($this->tempDir . '/.git/HEAD', "ref: refs/heads/main\n");

        $issues = $this->runCheck();

        $this->assertNotEmpty($issues);
        $this->assertFinding($issues, '.git', Issue::CRITICAL);
        foreach ($issues as $issue) {
            $this->assertStringNotContainsString('public/.git', $issue->message);
        }
    }

    public function test_generic_php_root_index_flags_root_vendor(): void
    {
        file_put_contents($this->tempDir . '/index.php', "<?php\n");
        mkdir($this->tempDir . '/vendor', 0777, true);

        $issues = $this->runCheck();

        $this->assertCount(1, $issues);
        $this->assertFinding($issues, 'vendor', Issue::CRITICAL);
    }

    public function test_empty_project_root_returns_empty_array(): void
    {
        ob_start();
        $result = (new DirectoryExposureCheck(new FakeGitStatus(repository: false)))->run('');
        ob_end_clean();

        $this->assertSame([], $result);
    }

    public function test_does_not_read_gitignore_as_a_substring(): void
    {
        $this->laravelPublic();
        mkdir($this->tempDir . '/public/vendor', 0777, true);
        file_put_contents($this->tempDir . '/.gitignore', "public/vendor\n");

        $issues = $this->runCheck(new FakeGitStatus(
            repository: true,
            tracked: [],
            ignored: [],
        ));

        $this->assertCount(1, $issues);
        $this->assertFinding($issues, 'public/vendor', Issue::CRITICAL);
        $this->assertStringNotContainsString('ignore rules', $issues[0]->message);
    }

    public function test_public_html_with_index_and_git_is_critical(): void
    {
        mkdir($this->tempDir . '/public_html', 0777, true);
        file_put_contents($this->tempDir . '/public_html/index.php', "<?php\n");
        mkdir($this->tempDir . '/public_html/.git', 0777, true);
        file_put_contents($this->tempDir . '/public_html/.git/HEAD', "ref: refs/heads/main\n");

        $issues = $this->runCheck();

        $this->assertNotEmpty($issues);
        $this->assertFinding($issues, 'public_html/.git', Issue::CRITICAL);
    }
}
