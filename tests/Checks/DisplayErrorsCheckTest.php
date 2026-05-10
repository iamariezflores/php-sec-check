<?php

namespace Aquilinoflores\PhpSecCheck\Tests\Checks;

use Aquilinoflores\PhpSecCheck\Checks\DisplayErrorsCheck;
use PHPUnit\Framework\TestCase;

class DisplayErrorsCheckTest extends TestCase
{
    private DisplayErrorsCheck $check;

    protected function setUp(): void
    {
        $this->check = new DisplayErrorsCheck();
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

    public function test_returns_at_most_one_issue(): void
    {
        // display_errors is a boolean setting — only one warning possible.
        $result = $this->runSilently('');
        $this->assertLessThanOrEqual(1, count($result));
    }

    public function test_issue_message_when_display_errors_enabled(): void
    {
        $previous = ini_get('display_errors');
        ini_set('display_errors', '1');

        $result = $this->runSilently('');

        ini_set('display_errors', $previous);

        $this->assertCount(1, $result);
        $this->assertStringContainsString("'display_errors' is enabled", $result[0]);
        $this->assertStringContainsString('Disable in production', $result[0]);
    }

    public function test_no_issue_when_display_errors_disabled(): void
    {
        $previous = ini_get('display_errors');
        ini_set('display_errors', '0');

        $result = $this->runSilently('');

        ini_set('display_errors', $previous);

        $this->assertEmpty($result);
    }

    public function test_output_contains_display_errors_header(): void
    {
        ob_start();
        $this->check->run('');
        $output = ob_get_clean();

        $this->assertStringContainsString('[DISPLAY ERRORS]', $output);
    }
}
