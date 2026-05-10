<?php

namespace Aquilinoflores\PhpSecCheck\Tests\Checks;

use Aquilinoflores\PhpSecCheck\Checks\PhpVersionCheck;
use PHPUnit\Framework\TestCase;

class PhpVersionCheckTest extends TestCase
{
    private PhpVersionCheck $check;

    protected function setUp(): void
    {
        $this->check = new PhpVersionCheck();
    }

    /** Suppress echo output from checks during all tests in this class. */
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
        // The test environment runs PHP 8.x, so no issues should be reported.
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

    public function test_issue_message_format_when_outdated(): void
    {
        // We cannot change the running PHP version, so we verify the expected
        // message format by checking the version_compare logic directly.
        $version = phpversion();
        $isOutdated = version_compare($version, '8.0.0', '<');

        $result = $this->runSilently('');

        if ($isOutdated) {
            $this->assertCount(1, $result);
            $this->assertStringContainsString('PHP version is outdated', $result[0]);
            $this->assertStringContainsString($version, $result[0]);
        } else {
            $this->assertEmpty($result);
        }
    }
}
