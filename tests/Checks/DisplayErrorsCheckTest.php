<?php

namespace Aquilinoflores\PhpSecCheck\Tests\Checks;

use Aquilinoflores\PhpSecCheck\Checks\DisplayErrorsCheck;
use Aquilinoflores\PhpSecCheck\Issue;
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

    public function test_returns_issue_objects(): void
    {
        $result = $this->runSilently('');
        foreach ($result as $item) {
            $this->assertInstanceOf(Issue::class, $item);
        }
    }

    public function test_returns_at_most_one_issue(): void
    {
        $result = $this->runSilently('');
        $this->assertLessThanOrEqual(1, count($result));
    }

    public function test_warn_severity_and_message_when_display_errors_enabled(): void
    {
        $previous = ini_get('display_errors');
        ini_set('display_errors', '1');

        $result = $this->runSilently('');

        ini_set('display_errors', $previous);

        $this->assertCount(1, $result);
        $this->assertInstanceOf(Issue::class, $result[0]);
        $this->assertSame(Issue::WARN, $result[0]->severity);
        $this->assertStringContainsString("'display_errors' is enabled", $result[0]->message);
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
