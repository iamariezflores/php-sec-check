<?php

namespace Aquilinoflores\PhpSecCheck\Tests\Checks;

use Aquilinoflores\PhpSecCheck\Checks\SqlInjectionCheck;
use Aquilinoflores\PhpSecCheck\Issue;
use PHPUnit\Framework\TestCase;

class SqlInjectionCheckTest extends TestCase
{
    private string $tempDir;

    protected function setUp(): void
    {
        $this->tempDir = sys_get_temp_dir() . '/php-sec-check-sqli-' . uniqid();
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
        $result = (new SqlInjectionCheck())->run($this->tempDir);
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
                $this->assertSame('SqlInjectionCheck', $issue->check);
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

    public function test_concatenated_select_with_get_is_critical(): void
    {
        file_put_contents(
            $this->tempDir . '/query.php',
            <<<'PHP'
<?php
$sql = "SELECT * FROM users WHERE id = " . $_GET['id'];
PHP
        );

        $issues = $this->runCheck();

        $this->assertCount(1, $issues);
        $this->assertFinding($issues, 'Concatenated SQL', Issue::CRITICAL);
        $this->assertStringContainsString('query.php:', $issues[0]->message);
    }

    public function test_prepared_statement_with_execute_is_clean(): void
    {
        file_put_contents(
            $this->tempDir . '/query.php',
            <<<'PHP'
<?php
$stmt = $pdo->prepare('SELECT * FROM users WHERE id = ?');
$stmt->execute([$id]);
PHP
        );

        $this->assertSame([], $this->runCheck());
    }

    public function test_laravel_where_binding_is_clean(): void
    {
        file_put_contents(
            $this->tempDir . '/query.php',
            <<<'PHP'
<?php
User::where('id', $id)->first();
User::where('id', $_GET['id'])->get();
PHP
        );

        $this->assertSame([], $this->runCheck());
    }

    public function test_interpolated_sql_is_critical(): void
    {
        file_put_contents(
            $this->tempDir . '/query.php',
            <<<'PHP'
<?php
$sql = "SELECT * FROM users WHERE id = {$_GET['id']}";
PHP
        );

        $issues = $this->runCheck();

        $this->assertCount(1, $issues);
        $this->assertFinding($issues, 'untrusted input', Issue::CRITICAL);
    }

    public function test_mysqli_query_with_concat_is_critical(): void
    {
        file_put_contents(
            $this->tempDir . '/query.php',
            <<<'PHP'
<?php
mysqli_query($conn, "SELECT * FROM users WHERE id = " . $_GET['id']);
PHP
        );

        $issues = $this->runCheck();

        $this->assertNotEmpty($issues);
        $this->assertSame(Issue::CRITICAL, $issues[0]->severity);
        $this->assertSame('SqlInjectionCheck', $issues[0]->check);
    }

    public function test_pdo_query_with_concat_is_critical(): void
    {
        file_put_contents(
            $this->tempDir . '/query.php',
            <<<'PHP'
<?php
$pdo->query("SELECT * FROM users WHERE id = " . $_GET['id']);
PHP
        );

        $issues = $this->runCheck();

        $this->assertNotEmpty($issues);
        $this->assertFinding($issues, 'query()', Issue::CRITICAL);
    }

    public function test_db_select_with_placeholder_is_clean(): void
    {
        file_put_contents(
            $this->tempDir . '/query.php',
            <<<'PHP'
<?php
DB::select('SELECT * FROM users WHERE id = ?', [$_GET['id']]);
PHP
        );

        $this->assertSame([], $this->runCheck());
    }

    public function test_db_select_with_concat_is_critical(): void
    {
        file_put_contents(
            $this->tempDir . '/query.php',
            <<<'PHP'
<?php
DB::select("SELECT * FROM users WHERE id = " . $_GET['id']);
PHP
        );

        $issues = $this->runCheck();

        $this->assertNotEmpty($issues);
        $this->assertSame(Issue::CRITICAL, $issues[0]->severity);
    }

    public function test_where_raw_with_concat_is_critical(): void
    {
        file_put_contents(
            $this->tempDir . '/query.php',
            <<<'PHP'
<?php
User::whereRaw('id = ' . $_GET['id'])->get();
PHP
        );

        $issues = $this->runCheck();

        $this->assertNotEmpty($issues);
        $this->assertFinding($issues, 'whereraw()', Issue::CRITICAL);
    }

    public function test_where_raw_with_binding_is_clean(): void
    {
        file_put_contents(
            $this->tempDir . '/query.php',
            <<<'PHP'
<?php
User::whereRaw('id = ?', [$_GET['id']])->get();
PHP
        );

        $this->assertSame([], $this->runCheck());
    }

    public function test_static_sql_query_is_clean(): void
    {
        file_put_contents(
            $this->tempDir . '/query.php',
            <<<'PHP'
<?php
$pdo->query('SELECT * FROM users');
mysqli_query($conn, 'SELECT id FROM users');
PHP
        );

        $this->assertSame([], $this->runCheck());
    }

    public function test_php_exec_with_untrusted_input_is_not_sql(): void
    {
        file_put_contents($this->tempDir . '/job.php', "<?php exec(\$_GET['cmd']);\n");

        $this->assertSame([], $this->runCheck());
    }

    public function test_pdo_exec_with_concatenated_sql_is_critical(): void
    {
        file_put_contents(
            $this->tempDir . '/query.php',
            "<?php \$pdo->exec('DELETE FROM users WHERE id = ' . \$_GET['id']);\n"
        );

        $issues = $this->runCheck();

        $this->assertCount(1, $issues);
        $this->assertSame(Issue::CRITICAL, $issues[0]->severity);
        $this->assertStringContainsString('exec()', $issues[0]->message);
    }

    public function test_vendor_files_are_skipped(): void
    {
        mkdir($this->tempDir . '/vendor', 0777, true);
        file_put_contents(
            $this->tempDir . '/vendor/lib.php',
            '<?php $sql = "SELECT * FROM users WHERE id = " . $_GET[\'id\'];' . "\n"
        );

        $this->assertSame([], $this->runCheck());
    }
}
