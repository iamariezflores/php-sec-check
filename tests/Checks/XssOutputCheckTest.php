<?php

namespace Aquilinoflores\PhpSecCheck\Tests\Checks;

use Aquilinoflores\PhpSecCheck\Checks\XssOutputCheck;
use Aquilinoflores\PhpSecCheck\Issue;
use PHPUnit\Framework\TestCase;

class XssOutputCheckTest extends TestCase
{
    private string $tempDir;

    protected function setUp(): void
    {
        $this->tempDir = sys_get_temp_dir() . '/php-sec-check-xss-' . uniqid();
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
        $result = (new XssOutputCheck())->run($this->tempDir);
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
                $this->assertSame('XssOutputCheck', $issue->check);
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

    public function test_echo_of_get_in_php_view_is_critical(): void
    {
        file_put_contents(
            $this->tempDir . '/view.php',
            <<<'PHP'
<?php
echo $_GET['q'];
PHP
        );

        $issues = $this->runCheck();

        $this->assertCount(1, $issues);
        $this->assertFinding($issues, 'echo', Issue::CRITICAL);
        $this->assertStringContainsString('view.php:', $issues[0]->message);
        $this->assertStringContainsString('untrusted input', $issues[0]->message);
    }

    public function test_htmlspecialchars_of_get_is_clean(): void
    {
        file_put_contents(
            $this->tempDir . '/view.php',
            <<<'PHP'
<?php
echo htmlspecialchars($_GET['q'], ENT_QUOTES, 'UTF-8');
PHP
        );

        $this->assertSame([], $this->runCheck());
    }

    public function test_htmlentities_and_laravel_e_are_clean(): void
    {
        file_put_contents(
            $this->tempDir . '/a.php',
            "<?php echo htmlentities(\$_POST['x'], ENT_QUOTES, 'UTF-8');\n"
        );
        file_put_contents(
            $this->tempDir . '/b.php',
            "<?php echo e(\$_REQUEST['y']);\n"
        );

        $this->assertSame([], $this->runCheck());
    }

    public function test_blade_escaped_echo_is_clean(): void
    {
        mkdir($this->tempDir . '/views', 0777, true);
        file_put_contents(
            $this->tempDir . '/views/q.blade.php',
            "<h1>{{ \$q }}</h1>\n<p>{{ \$_GET['q'] }}</p>\n"
        );

        $this->assertSame([], $this->runCheck());
    }

    public function test_blade_raw_with_untrusted_input_is_critical(): void
    {
        mkdir($this->tempDir . '/views', 0777, true);
        file_put_contents(
            $this->tempDir . '/views/q.blade.php',
            "<div>{!! \$_GET['q'] !!}</div>\n"
        );

        $issues = $this->runCheck();

        $this->assertCount(1, $issues);
        $this->assertFinding($issues, '{!! !!}', Issue::CRITICAL);
        $this->assertStringContainsString('untrusted input', $issues[0]->message);
    }

    public function test_blade_raw_without_superglobal_is_warn(): void
    {
        mkdir($this->tempDir . '/views', 0777, true);
        file_put_contents(
            $this->tempDir . '/views/q.blade.php',
            "<div>{!! \$q !!}</div>\n"
        );

        $issues = $this->runCheck();

        $this->assertCount(1, $issues);
        $this->assertFinding($issues, '{!! !!}', Issue::WARN);
    }

    public function test_print_and_short_echo_are_flagged(): void
    {
        file_put_contents(
            $this->tempDir . '/print.php',
            "<?php print \$_POST['x'];\n"
        );
        file_put_contents(
            $this->tempDir . '/short.php',
            "<?= \$_COOKIE['c'] ?>"
        );

        $issues = $this->runCheck();

        $this->assertCount(2, $issues);
        $this->assertFinding($issues, 'print', Issue::CRITICAL);
        $this->assertFinding($issues, '<?=', Issue::CRITICAL);
    }

    public function test_json_content_type_file_is_out_of_scope(): void
    {
        file_put_contents(
            $this->tempDir . '/api.php',
            <<<'PHP'
<?php
header('Content-Type: application/json');
echo $_GET['q'];
PHP
        );

        $this->assertSame([], $this->runCheck());
    }

    public function test_json_encode_of_untrusted_is_not_html_xss(): void
    {
        file_put_contents(
            $this->tempDir . '/api.php',
            "<?php echo json_encode(\$_GET);\n"
        );

        $this->assertSame([], $this->runCheck());
    }

    public function test_untrusted_concatenated_outside_escape_is_critical(): void
    {
        file_put_contents(
            $this->tempDir . '/view.php',
            "<?php echo htmlspecialchars(\$_GET['a'], ENT_QUOTES, 'UTF-8') . \$_GET['b'];\n"
        );

        $issues = $this->runCheck();

        $this->assertCount(1, $issues);
        $this->assertFinding($issues, 'echo', Issue::CRITICAL);
    }

    public function test_vendor_files_are_skipped(): void
    {
        mkdir($this->tempDir . '/vendor', 0777, true);
        file_put_contents(
            $this->tempDir . '/vendor/lib.php',
            "<?php echo \$_GET['q'];\n"
        );

        $this->assertSame([], $this->runCheck());
    }

    public function test_echo_without_untrusted_input_is_clean(): void
    {
        file_put_contents(
            $this->tempDir . '/view.php',
            "<?php echo 'hello'; echo \$title;\n"
        );

        $this->assertSame([], $this->runCheck());
    }

    public function test_blade_raw_with_e_helper_is_clean(): void
    {
        mkdir($this->tempDir . '/views', 0777, true);
        file_put_contents(
            $this->tempDir . '/views/q.blade.php',
            "{!! e(\$_GET['q']) !!}\n"
        );

        $this->assertSame([], $this->runCheck());
    }
}
