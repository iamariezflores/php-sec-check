<?php

namespace Aquilinoflores\PhpSecCheck\Tests\Checks;

use Aquilinoflores\PhpSecCheck\Checks\FilePermissionCheck;
use Aquilinoflores\PhpSecCheck\Issue;
use Aquilinoflores\PhpSecCheck\Scan\ScanContext;
use PHPUnit\Framework\TestCase;

class FilePermissionCheckTest extends TestCase
{
    private string $tempDir;

    protected function setUp(): void
    {
        $this->tempDir = sys_get_temp_dir() . '/php-sec-check-perm-' . uniqid();
        mkdir($this->tempDir, 0777, true);
        ScanContext::reset();
    }

    protected function tearDown(): void
    {
        ScanContext::reset();
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
                unlink($path);
            }
        }
        rmdir($dir);
    }

    public function test_windows_and_non_host_profiles_are_quiet(): void
    {
        mkdir($this->tempDir . '/public');
        file_put_contents($this->tempDir . '/public/index.php', "<?php\n");

        ob_start();
        $legacy = (new FilePermissionCheck())->run($this->tempDir);
        ob_end_clean();
        $this->assertSame([], $legacy);

        if (PHP_OS_FAMILY === 'Windows') {
            ScanContext::set('host');
            ob_start();
            $host = (new FilePermissionCheck())->run($this->tempDir);
            ob_end_clean();
            $this->assertSame([], $host);
        }
    }

    public function test_world_writable_file_on_unix_host_profile(): void
    {
        if (PHP_OS_FAMILY === 'Windows') {
            $this->assertTrue(true);
            return;
        }

        mkdir($this->tempDir . '/public');
        $file = $this->tempDir . '/public/upload.php';
        file_put_contents($file, "<?php\n");
        chmod($file, 0666);

        ScanContext::set('host');
        ob_start();
        $issues = (new FilePermissionCheck())->run($this->tempDir);
        ob_end_clean();

        $this->assertNotEmpty($issues);
        $this->assertSame(Issue::HIGH, $issues[0]->severity);
        $this->assertSame(FilePermissionCheck::RULE_ID, $issues[0]->ruleId);
        $this->assertStringContainsString('upload.php', $issues[0]->message);
    }
}
