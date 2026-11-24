<?php

namespace Aquilinoflores\PhpSecCheck\Tests\Checks;

use Aquilinoflores\PhpSecCheck\Checks\DisplayErrorsCheck;
use Aquilinoflores\PhpSecCheck\Issue;
use PHPUnit\Framework\TestCase;

class DisplayErrorsCheckTest extends TestCase
{
    private string $tempDir;
    private DisplayErrorsCheck $check;

    protected function setUp(): void
    {
        $this->tempDir = sys_get_temp_dir() . '/php-sec-check-display-' . uniqid();
        mkdir($this->tempDir, 0777, true);
        $this->check = new DisplayErrorsCheck();
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
            is_dir($path) ? $this->removeDir($path) : unlink($path);
        }
        rmdir($dir);
    }

    /**
     * @return list<Issue>
     */
    private function runSilently(string $projectRoot): array
    {
        ob_start();
        $result = $this->check->run($projectRoot);
        ob_end_clean();
        return $result;
    }

    public function test_returns_array(): void
    {
        $this->assertIsArray($this->runSilently(''));
    }

    public function test_empty_project_returns_no_issues(): void
    {
        $this->assertSame([], $this->runSilently($this->tempDir));
    }

    public function test_scanner_process_ini_is_not_a_finding(): void
    {
        $previous = ini_get('display_errors');
        ini_set('display_errors', '1');

        $result = $this->runSilently($this->tempDir);

        ini_set('display_errors', $previous);

        $this->assertSame([], $result);
    }

    public function test_user_ini_display_errors_is_medium(): void
    {
        file_put_contents($this->tempDir . '/.user.ini', "display_errors = On\n");

        $result = $this->runSilently($this->tempDir);

        $this->assertCount(1, $result);
        $this->assertSame(Issue::WARN, $result[0]->severity);
        $this->assertSame(DisplayErrorsCheck::RULE_ID, $result[0]->ruleId);
        $this->assertSame(Issue::CONFIRMED, $result[0]->confidence);
        $this->assertStringContainsString("'display_errors' is enabled", $result[0]->message);
        $this->assertSame('.user.ini', $result[0]->path);
        $this->assertSame(1, $result[0]->line);
    }

    public function test_ini_set_in_project_source_is_a_finding(): void
    {
        file_put_contents($this->tempDir . '/index.php', "<?php\nini_set('display_errors', '1');\n");

        $result = $this->runSilently($this->tempDir);

        $this->assertCount(1, $result);
        $this->assertSame('index.php', $result[0]->path);
        $this->assertSame(2, $result[0]->line);
    }

    public function test_display_errors_off_is_clean(): void
    {
        file_put_contents($this->tempDir . '/.user.ini', "display_errors = Off\n");

        $this->assertSame([], $this->runSilently($this->tempDir));
    }

    public function test_allow_url_include_is_critical_and_expose_php_is_low(): void
    {
        file_put_contents($this->tempDir . '/.user.ini', "allow_url_include = On\nexpose_php = On\n");

        $result = $this->runSilently($this->tempDir);

        $this->assertCount(2, $result);
        $this->assertSame(DisplayErrorsCheck::RULE_URL_INCLUDE, $result[0]->ruleId);
        $this->assertSame(Issue::CRITICAL, $result[0]->severity);
        $this->assertSame(DisplayErrorsCheck::RULE_EXPOSE_PHP, $result[1]->ruleId);
        $this->assertSame(Issue::LOW, $result[1]->severity);
    }

    public function test_check_does_not_print(): void
    {
        ob_start();
        $this->check->run($this->tempDir);
        $this->assertSame('', ob_get_clean());
    }
}
