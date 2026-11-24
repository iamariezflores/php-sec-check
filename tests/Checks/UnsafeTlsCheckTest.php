<?php

namespace Aquilinoflores\PhpSecCheck\Tests\Checks;

use Aquilinoflores\PhpSecCheck\Checks\UnsafeTlsCheck;
use Aquilinoflores\PhpSecCheck\Issue;
use PHPUnit\Framework\TestCase;

class UnsafeTlsCheckTest extends TestCase
{
    private string $tempDir;

    protected function setUp(): void
    {
        $this->tempDir = sys_get_temp_dir() . '/php-sec-check-tls-' . uniqid();
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
        $result = (new UnsafeTlsCheck())->run($this->tempDir);
        ob_end_clean();
        return $result;
    }

    public function test_verifypeer_false_is_high(): void
    {
        file_put_contents(
            $this->tempDir . '/fetch.php',
            "<?php\ncurl_setopt(\$ch, CURLOPT_SSL_VERIFYPEER, false);\n"
        );

        $issues = $this->findings();

        $this->assertCount(1, $issues);
        $this->assertSame(Issue::HIGH, $issues[0]->severity);
        $this->assertSame(Issue::LIKELY, $issues[0]->confidence);
        $this->assertSame(UnsafeTlsCheck::RULE_ID, $issues[0]->ruleId);
    }

    public function test_verify_peer_true_is_clean(): void
    {
        file_put_contents(
            $this->tempDir . '/fetch.php',
            "<?php\n\$ctx = ['ssl' => ['verify_peer' => true]];\n"
        );

        $this->assertSame([], $this->findings());
    }
}
