<?php

namespace Aquilinoflores\PhpSecCheck\Tests\Checks;

use Aquilinoflores\PhpSecCheck\Checks\DangerousFunctionsCheck;
use Aquilinoflores\PhpSecCheck\Issue;
use PHPUnit\Framework\TestCase;

class DangerousFunctionsCheckTest extends TestCase
{
    /**
     * @return list<Issue>
     */
    private function runSilently(DangerousFunctionsCheck $check): array
    {
        ob_start();
        $result = $check->run('');
        ob_end_clean();
        return $result;
    }

    /**
     * @return list<string>
     */
    private function reportedFunctions(array $issues): array
    {
        $names = [];
        foreach ($issues as $issue) {
            if (preg_match("/'([^']+)'/", $issue->message, $m)) {
                $names[] = $m[1];
            }
        }
        return $names;
    }

    public function test_returns_issue_objects(): void
    {
        $result = $this->runSilently(new DangerousFunctionsCheck(''));
        foreach ($result as $item) {
            $this->assertInstanceOf(Issue::class, $item);
            $this->assertSame(Issue::WARN, $item->severity);
        }
    }

    public function test_check_does_not_print(): void
    {
        ob_start();
        (new DangerousFunctionsCheck(''))->run('');
        $output = ob_get_clean();

        $this->assertSame('', $output);
    }

    public function test_reports_only_disable_candidates_when_none_disabled(): void
    {
        $result = $this->runSilently(new DangerousFunctionsCheck(''));
        $this->assertCount(count(DangerousFunctionsCheck::DISABLE_CANDIDATES), $result);
        $this->assertSame(DangerousFunctionsCheck::DISABLE_CANDIDATES, $this->reportedFunctions($result));
    }

    public function test_does_not_flag_curl_exec_as_a_config_issue(): void
    {
        $result = $this->runSilently(new DangerousFunctionsCheck(''));
        $this->assertNotContains('curl_exec', $this->reportedFunctions($result));
        $this->assertNotContains('curl_multi_exec', $this->reportedFunctions($result));
        $this->assertNotContains('eval', $this->reportedFunctions($result));
        $this->assertNotContains('parse_ini_file', $this->reportedFunctions($result));
        $this->assertNotContains('show_source', $this->reportedFunctions($result));
        $this->assertNotContains('create_function', $this->reportedFunctions($result));
    }

    public function test_disabled_function_is_not_reported(): void
    {
        $result = $this->runSilently(new DangerousFunctionsCheck('exec,shell_exec'));
        $reported = $this->reportedFunctions($result);

        $this->assertNotContains('exec', $reported);
        $this->assertNotContains('shell_exec', $reported);
        $this->assertContains('system', $reported);
    }

    public function test_curl_exec_in_disable_functions_does_not_count_as_exec(): void
    {
        $result = $this->runSilently(new DangerousFunctionsCheck('curl_exec,passthru'));
        $reported = $this->reportedFunctions($result);

        $this->assertContains('exec', $reported, 'Matching must be whole-name, not a substring of curl_exec.');
        $this->assertNotContains('passthru', $reported);
        $this->assertNotContains('curl_exec', $reported);
    }

    public function test_returns_empty_when_all_disable_candidates_are_listed(): void
    {
        $allDisabled = implode(',', DangerousFunctionsCheck::DISABLE_CANDIDATES);
        $result      = $this->runSilently(new DangerousFunctionsCheck($allDisabled));

        $this->assertEmpty($result);
    }

    public function test_default_constructor_reads_runtime_ini(): void
    {
        $result = $this->runSilently(new DangerousFunctionsCheck());
        $this->assertIsArray($result);
    }
}
