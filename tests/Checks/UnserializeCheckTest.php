<?php

namespace Aquilinoflores\PhpSecCheck\Tests\Checks;

use Aquilinoflores\PhpSecCheck\Checks\UnserializeCheck;
use Aquilinoflores\PhpSecCheck\Issue;
use PHPUnit\Framework\TestCase;

class UnserializeCheckTest extends TestCase
{
    private string $tempDir;

    protected function setUp(): void
    {
        $this->tempDir = sys_get_temp_dir() . '/php-sec-check-unserialize-' . uniqid();
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
        $result = (new UnserializeCheck())->run($this->tempDir);
        ob_end_clean();
        return $result;
    }

    /**
     * @param list<Issue> $issues
     */
    private function assertFinding(array $issues, string $needle, string $severity): Issue
    {
        foreach ($issues as $issue) {
            if (str_contains($issue->message, $needle)) {
                $this->assertSame($severity, $issue->severity, $issue->message);
                $this->assertSame('UnserializeCheck', $issue->check);
                return $issue;
            }
        }

        $this->fail("Expected a finding mentioning '{$needle}', got: " . json_encode(
            array_map(fn(Issue $i) => $i->message, $issues)
        ));
    }

    public function test_empty_project_returns_no_issues(): void
    {
        $this->assertSame([], $this->runCheck());
    }

    public function test_unserialize_of_post_is_critical(): void
    {
        file_put_contents(
            $this->tempDir . '/cache.php',
            "<?php unserialize(\$_POST['data']);\n"
        );

        $issues = $this->runCheck();

        $this->assertCount(1, $issues);
        $this->assertFinding($issues, 'unserialize()', Issue::CRITICAL);
        $this->assertStringContainsString('untrusted input', $issues[0]->message);
        $this->assertStringContainsString('cache.php:', $issues[0]->message);
    }

    public function test_local_cache_with_allowed_classes_false_is_warn_at_most(): void
    {
        file_put_contents(
            $this->tempDir . '/cache.php',
            <<<'PHP'
<?php
$cached = file_get_contents(storage_path('app/cache.ser'));
unserialize($cached, ['allowed_classes' => false]);
PHP
        );

        $issues = $this->runCheck();

        $this->assertCount(1, $issues);
        $this->assertSame('UnserializeCheck', $issues[0]->check);
        $this->assertNotSame(Issue::CRITICAL, $issues[0]->severity);
        $this->assertContains($issues[0]->severity, [Issue::WARN, Issue::INFO]);
        $this->assertStringContainsString('unserialize()', $issues[0]->message);
    }

    public function test_json_decode_is_clean(): void
    {
        file_put_contents(
            $this->tempDir . '/api.php',
            "<?php json_decode(\$json); json_decode(\$_POST['payload']);\n"
        );

        $this->assertSame([], $this->runCheck());
    }

    public function test_unserialize_of_local_variable_is_warn(): void
    {
        file_put_contents(
            $this->tempDir . '/cache.php',
            "<?php unserialize(\$cached);\n"
        );

        $issues = $this->runCheck();

        $this->assertCount(1, $issues);
        $this->assertFinding($issues, 'unserialize()', Issue::WARN);
    }

    public function test_allowed_classes_false_does_not_hide_untrusted_input(): void
    {
        file_put_contents(
            $this->tempDir . '/cache.php',
            "<?php unserialize(\$_POST['data'], ['allowed_classes' => false]);\n"
        );

        $issues = $this->runCheck();

        $this->assertCount(1, $issues);
        $this->assertFinding($issues, 'untrusted input', Issue::CRITICAL);
    }

    public function test_maybe_unserialize_with_untrusted_input_is_critical(): void
    {
        file_put_contents(
            $this->tempDir . '/wp.php',
            "<?php maybe_unserialize(\$_GET['opt']);\n"
        );

        $issues = $this->runCheck();

        $this->assertCount(1, $issues);
        $this->assertFinding($issues, 'maybe_unserialize()', Issue::CRITICAL);
    }

    public function test_vendor_files_are_skipped(): void
    {
        mkdir($this->tempDir . '/vendor', 0777, true);
        file_put_contents(
            $this->tempDir . '/vendor/lib.php',
            "<?php unserialize(\$_POST['data']);\n"
        );

        $this->assertSame([], $this->runCheck());
    }
}
