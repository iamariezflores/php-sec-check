<?php

namespace Aquilinoflores\PhpSecCheck\Tests\Checks;

use Aquilinoflores\PhpSecCheck\Checks\InsecureRandomCheck;
use Aquilinoflores\PhpSecCheck\Issue;
use PHPUnit\Framework\TestCase;

class InsecureRandomCheckTest extends TestCase
{
    private string $tempDir;

    protected function setUp(): void
    {
        $this->tempDir = sys_get_temp_dir() . '/php-sec-check-rand-' . uniqid();
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
        $result = (new InsecureRandomCheck())->run($this->tempDir);
        ob_end_clean();
        return $result;
    }

    public function test_uniqid_token_is_medium(): void
    {
        file_put_contents($this->tempDir . '/token.php', "<?php\n\$csrf = uniqid();\n\$id = uniqid();\n");

        $issues = $this->findings();

        $this->assertCount(1, $issues);
        $this->assertSame(Issue::MEDIUM, $issues[0]->severity);
        $this->assertSame(Issue::HEURISTIC, $issues[0]->confidence);
        $this->assertSame(InsecureRandomCheck::RULE_ID, $issues[0]->ruleId);
        $this->assertSame(2, $issues[0]->line);
    }

    public function test_random_bytes_is_clean(): void
    {
        file_put_contents($this->tempDir . '/token.php', "<?php\n\$token = bin2hex(random_bytes(16));\n");

        $this->assertSame([], $this->findings());
    }
}
