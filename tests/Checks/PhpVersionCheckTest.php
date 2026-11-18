<?php

namespace Aquilinoflores\PhpSecCheck\Tests\Checks;

use Aquilinoflores\PhpSecCheck\Checks\PhpVersionCheck;
use Aquilinoflores\PhpSecCheck\Issue;
use PHPUnit\Framework\TestCase;

class PhpVersionCheckTest extends TestCase
{
    private PhpVersionCheck $check;

    protected function setUp(): void
    {
        $this->check = new PhpVersionCheck();
    }

    private function runSilently(string $projectRoot): array
    {
        ob_start();
        $result = $this->check->run($projectRoot);
        ob_end_clean();
        return $result;
    }

    public function test_returns_array(): void
    {
        $result = $this->runSilently('');
        $this->assertIsArray($result);
    }

    public function test_passes_on_php_8_or_higher(): void
    {
        $this->assertGreaterThanOrEqual(
            0,
            version_compare(phpversion(), '8.0.0'),
            'Test environment must be PHP 8.0+ for this assertion to be valid.'
        );

        $result = $this->runSilently('');
        $this->assertEmpty($result, 'Expected no issues on PHP 8.0+.');
    }

    public function test_output_contains_php_version_header(): void
    {
        ob_start();
        $this->check->run('');
        $output = ob_get_clean();

        $this->assertStringContainsString('[PHP VERSION]', $output);
        $this->assertStringContainsString(phpversion(), $output);
    }

    public function test_returns_issue_objects(): void
    {
        $result = $this->runSilently('');

        $this->assertIsArray($result);
        foreach ($result as $item) {
            $this->assertInstanceOf(Issue::class, $item);
        }
    }

    public function test_issue_message_and_severity_when_outdated(): void
    {
        $version   = phpversion();
        $isOutdated = version_compare($version, '8.0.0', '<');

        $result = $this->runSilently('');

        if ($isOutdated) {
            $this->assertCount(1, $result);
            $this->assertSame(Issue::WARN, $result[0]->severity);
            $this->assertStringContainsString('PHP version is outdated', $result[0]->message);
            $this->assertStringContainsString($version, $result[0]->message);
        } else {
            $this->assertEmpty($result);
        }
    }
}
