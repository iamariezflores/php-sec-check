<?php

namespace Aquilinoflores\PhpSecCheck\Tests\Checks;

use Aquilinoflores\PhpSecCheck\Checks\IncludeRequestCheck;
use Aquilinoflores\PhpSecCheck\Issue;
use PHPUnit\Framework\TestCase;

class IncludeRequestCheckTest extends TestCase
{
    private string $tempDir;

    protected function setUp(): void
    {
        $this->tempDir = sys_get_temp_dir() . '/php-sec-check-include-' . uniqid();
        mkdir($this->tempDir, 0777, true);
    }

    protected function tearDown(): void
    {
        foreach (glob($this->tempDir . '/*') ?: [] as $file) {
            unlink($file);
        }
        rmdir($this->tempDir);
    }

    /**
     * @return list<Issue>
     */
    private function findings(): array
    {
        ob_start();
        $result = (new IncludeRequestCheck())->run($this->tempDir);
        ob_end_clean();
        return $result;
    }

    public function test_include_of_request_is_critical(): void
    {
        file_put_contents($this->tempDir . '/page.php', "<?php\ninclude \$_GET['page'];\n");

        $issues = $this->findings();

        $this->assertCount(1, $issues);
        $this->assertSame(Issue::CRITICAL, $issues[0]->severity);
        $this->assertSame(Issue::LIKELY, $issues[0]->confidence);
        $this->assertSame(IncludeRequestCheck::RULE_ID, $issues[0]->ruleId);
        $this->assertSame('page.php', $issues[0]->path);
        $this->assertSame(2, $issues[0]->line);
    }

    public function test_fixed_include_and_bare_variable_are_clean(): void
    {
        file_put_contents($this->tempDir . '/page.php', "<?php\ninclude 'header.php';\nrequire \$page;\n");

        $this->assertSame([], $this->findings());
    }
}
