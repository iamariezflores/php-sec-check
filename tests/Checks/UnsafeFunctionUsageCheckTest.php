<?php

namespace Aquilinoflores\PhpSecCheck\Tests\Checks;

use Aquilinoflores\PhpSecCheck\Checks\UnsafeFunctionUsageCheck;
use Aquilinoflores\PhpSecCheck\Issue;
use PHPUnit\Framework\TestCase;

class UnsafeFunctionUsageCheckTest extends TestCase
{
    private string $tempDir;

    protected function setUp(): void
    {
        $this->tempDir = sys_get_temp_dir() . '/php-sec-check-unsafe-' . uniqid();
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
    private function runCheck(): array
    {
        ob_start();
        $result = (new UnsafeFunctionUsageCheck())->run($this->tempDir);
        ob_end_clean();
        return $result;
    }

    public function test_returns_empty_when_no_risky_calls(): void
    {
        file_put_contents($this->tempDir . '/app.php', "<?php echo 'hello';\n");

        $this->assertEmpty($this->runCheck());
    }

    public function test_warns_when_exec_is_used_with_a_literal(): void
    {
        file_put_contents($this->tempDir . '/job.php', "<?php exec('ls');\n");

        $result = $this->runCheck();

        $this->assertCount(1, $result);
        $this->assertSame(Issue::WARN, $result[0]->severity);
        $this->assertStringContainsString('exec()', $result[0]->message);
        $this->assertStringContainsString('job.php:1', $result[0]->message);
        $this->assertSame('UnsafeFunctionUsageCheck', $result[0]->check);
    }

    public function test_critical_when_exec_receives_untrusted_input(): void
    {
        file_put_contents($this->tempDir . '/job.php', "<?php exec(\$_GET['cmd']);\n");

        $result = $this->runCheck();

        $this->assertCount(1, $result);
        $this->assertSame(Issue::CRITICAL, $result[0]->severity);
        $this->assertStringContainsString('untrusted input', $result[0]->message);
    }

    public function test_does_not_flag_curl_exec_without_untrusted_input(): void
    {
        file_put_contents($this->tempDir . '/http.php', "<?php curl_exec(\$ch);\n");

        $this->assertEmpty($this->runCheck());
    }

    public function test_flags_curl_exec_when_it_receives_untrusted_input(): void
    {
        file_put_contents(
            $this->tempDir . '/http.php',
            "<?php curl_exec(\$_POST['handle']);\n"
        );

        $result = $this->runCheck();

        $this->assertCount(1, $result);
        $this->assertSame(Issue::CRITICAL, $result[0]->severity);
        $this->assertStringContainsString('curl_exec()', $result[0]->message);
    }

    public function test_skips_vendor_directory(): void
    {
        mkdir($this->tempDir . '/vendor/pkg', 0777, true);
        file_put_contents($this->tempDir . '/vendor/pkg/run.php', "<?php exec('ls');\n");
        file_put_contents($this->tempDir . '/app.php', "<?php echo 1;\n");

        $this->assertEmpty($this->runCheck());
    }

    public function test_skips_method_named_exec(): void
    {
        file_put_contents($this->tempDir . '/db.php', "<?php \$pdo->exec('SELECT 1');\n");

        $this->assertEmpty($this->runCheck());
    }

    public function test_empty_project_root_returns_empty(): void
    {
        ob_start();
        $result = (new UnsafeFunctionUsageCheck())->run('');
        ob_end_clean();

        $this->assertEmpty($result);
    }
}
