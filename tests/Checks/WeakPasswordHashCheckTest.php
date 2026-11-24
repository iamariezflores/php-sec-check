<?php

namespace Aquilinoflores\PhpSecCheck\Tests\Checks;

use Aquilinoflores\PhpSecCheck\Checks\WeakPasswordHashCheck;
use Aquilinoflores\PhpSecCheck\Issue;
use PHPUnit\Framework\TestCase;

class WeakPasswordHashCheckTest extends TestCase
{
    private string $tempDir;

    protected function setUp(): void
    {
        $this->tempDir = sys_get_temp_dir() . '/php-sec-check-hash-' . uniqid();
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
        $result = (new WeakPasswordHashCheck())->run($this->tempDir);
        ob_end_clean();
        return $result;
    }

    public function test_md5_of_a_password_is_high(): void
    {
        file_put_contents($this->tempDir . '/login.php', "<?php\n\$hash = md5(\$password);\n");

        $issues = $this->findings();

        $this->assertCount(1, $issues);
        $this->assertSame(Issue::HIGH, $issues[0]->severity);
        $this->assertSame(Issue::LIKELY, $issues[0]->confidence);
        $this->assertSame(WeakPasswordHashCheck::RULE_ID, $issues[0]->ruleId);
    }

    public function test_sha1_hash_function_of_a_password_is_high(): void
    {
        file_put_contents($this->tempDir . '/login.php', "<?php\n\$hash = hash('sha1', \$passwd);\n");

        $this->assertCount(1, $this->findings());
    }

    public function test_unrelated_md5_and_sha256_are_clean(): void
    {
        file_put_contents(
            $this->tempDir . '/login.php',
            "<?php\n\$etag = md5(\$contents);\n\$hash = hash('sha256', \$password);\n"
        );

        $this->assertSame([], $this->findings());
    }
}
