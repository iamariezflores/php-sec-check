<?php

namespace Aquilinoflores\PhpSecCheck\Tests\Checks;

use Aquilinoflores\PhpSecCheck\Checks\DangerousFunctionsCheck;
use Aquilinoflores\PhpSecCheck\Issue;
use PHPUnit\Framework\TestCase;

class DangerousFunctionsCheckTest extends TestCase
{
    private function runSilently(DangerousFunctionsCheck $check): array
    {
        ob_start();
        $result = $check->run('');
        ob_end_clean();
        return $result;
    }

    public function test_returns_array(): void
    {
        $result = $this->runSilently(new DangerousFunctionsCheck(''));
        $this->assertIsArray($result);
    }

    public function test_returns_issue_objects(): void
    {
        $result = $this->runSilently(new DangerousFunctionsCheck(''));
        foreach ($result as $item) {
            $this->assertInstanceOf(Issue::class, $item);
        }
    }

    public function test_output_contains_dangerous_functions_header(): void
    {
        ob_start();
        (new DangerousFunctionsCheck(''))->run('');
        $output = ob_get_clean();

        $this->assertStringContainsString('[DANGEROUS FUNCTIONS]', $output);
    }

    public function test_reports_all_twelve_functions_when_none_disabled(): void
    {
        $result = $this->runSilently(new DangerousFunctionsCheck(''));
        $this->assertCount(count(DangerousFunctionsCheck::DANGEROUS_FUNCTIONS), $result);
    }

    public function test_all_issues_have_warn_severity(): void
    {
        $result = $this->runSilently(new DangerousFunctionsCheck(''));
        foreach ($result as $issue) {
            $this->assertSame(Issue::WARN, $issue->severity);
        }
    }

    public function test_issue_message_format(): void
    {
        $result = $this->runSilently(new DangerousFunctionsCheck(''));
        foreach ($result as $issue) {
            $this->assertStringStartsWith('Dangerous function enabled: ', $issue->message);
        }
    }

    public function test_disabled_function_is_not_reported(): void
    {
        $result = $this->runSilently(new DangerousFunctionsCheck('exec,shell_exec'));

        $reported = array_map(
            fn($issue) => str_replace('Dangerous function enabled: ', '', $issue->message),
            $result
        );

        $this->assertNotContains('exec', $reported);
        $this->assertNotContains('shell_exec', $reported);
    }

    public function test_reports_only_non_disabled_functions(): void
    {
        $result = $this->runSilently(new DangerousFunctionsCheck('exec,eval,system'));

        $expectedCount = count(DangerousFunctionsCheck::DANGEROUS_FUNCTIONS) - 3;
        $this->assertCount($expectedCount, $result);
    }

    public function test_returns_empty_when_all_dangerous_functions_disabled(): void
    {
        $allDisabled = implode(',', DangerousFunctionsCheck::DANGEROUS_FUNCTIONS);
        $result      = $this->runSilently(new DangerousFunctionsCheck($allDisabled));

        $this->assertEmpty($result);
    }

    public function test_each_dangerous_function_is_individually_detected(): void
    {
        $result = $this->runSilently(new DangerousFunctionsCheck(''));

        foreach (DangerousFunctionsCheck::DANGEROUS_FUNCTIONS as $fn) {
            $messages = array_map(fn($i) => $i->message, $result);
            $this->assertContains(
                "Dangerous function enabled: $fn",
                $messages,
                "Expected '$fn' to be reported as dangerous when not disabled."
            );
        }
    }

    public function test_default_constructor_reads_runtime_ini(): void
    {
        $result = $this->runSilently(new DangerousFunctionsCheck());
        $this->assertIsArray($result);
    }
}
