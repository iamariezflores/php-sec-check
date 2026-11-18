<?php

namespace Aquilinoflores\PhpSecCheck\Tests\Integration;

use PHPUnit\Framework\TestCase;

/**
 * JSON Output Tests
 *
 * Verifies that --format=json prints a single machine-readable document
 * (no coloured text), with a summary and issue list, while keeping the
 * same 0 / 1 exit-code contract as text mode.
 */
class JsonOutputTest extends TestCase
{
    private string $tempDir;
    private string $binPath;

    protected function setUp(): void
    {
        $this->tempDir = sys_get_temp_dir() . '/php-sec-check-json-test-' . uniqid();
        mkdir($this->tempDir, 0777, true);

        $this->binPath = dirname(__DIR__, 2) . '/bin/sec-check';
    }

    protected function tearDown(): void
    {
        $this->removeTempDir($this->tempDir);
    }

    private function removeTempDir(string $dir): void
    {
        if (!is_dir($dir)) {
            return;
        }
        foreach (array_diff(scandir($dir), ['.', '..']) as $item) {
            $path = $dir . DIRECTORY_SEPARATOR . $item;
            is_dir($path) ? $this->removeTempDir($path) : unlink($path);
        }
        rmdir($dir);
    }

    /**
     * @return array{exit: int, output: string, json: ?array}
     */
    private function runSecCheck(string $projectRoot, string $format = 'json'): array
    {
        $cmd = [PHP_BINARY, $this->binPath];
        if ($format === 'json') {
            $cmd[] = '--format=json';
        }

        $proc = proc_open(
            $cmd,
            [
                0 => ['pipe', 'r'],
                1 => ['pipe', 'w'],
                2 => ['pipe', 'w'],
            ],
            $pipes,
            $projectRoot
        );

        $this->assertIsResource($proc, 'Failed to start sec-check process.');

        fclose($pipes[0]);
        $raw = stream_get_contents($pipes[1]);
        fclose($pipes[1]);
        fclose($pipes[2]);
        $exitCode = proc_close($proc);

        $json = json_decode($raw, true);

        return [
            'exit'   => $exitCode,
            'output' => $raw,
            'json'   => is_array($json) ? $json : null,
        ];
    }

    private function makeLaravelProject(string $env): void
    {
        touch($this->tempDir . '/artisan');
        mkdir($this->tempDir . '/bootstrap', 0777, true);
        file_put_contents($this->tempDir . '/bootstrap/app.php', '<?php return new class {};');
        file_put_contents($this->tempDir . '/.env', $env);
        file_put_contents(
            $this->tempDir . '/php-sec-check-config.php',
            "<?php return ['sensitive_keys' => ['APP_KEY']];"
        );
    }

    public function test_json_output_is_valid_and_has_required_keys(): void
    {
        $this->makeLaravelProject("APP_KEY=base64:SomeSuperSecretKey=\n");

        $result = $this->runSecCheck($this->tempDir);

        $this->assertNotNull($result['json'], 'CLI must print valid JSON. Got: ' . $result['output']);
        $this->assertArrayHasKey('summary', $result['json']);
        $this->assertArrayHasKey('issues', $result['json']);
        $this->assertArrayHasKey('total', $result['json']['summary']);
        $this->assertArrayHasKey('critical', $result['json']['summary']);
        $this->assertArrayHasKey('warn', $result['json']['summary']);
        $this->assertArrayHasKey('info', $result['json']['summary']);
    }

    public function test_json_mode_suppresses_coloured_text_report(): void
    {
        $this->makeLaravelProject("APP_KEY=base64:SomeSuperSecretKey=\n");

        $result = $this->runSecCheck($this->tempDir);

        $this->assertStringNotContainsString('=== PHP Security Check Tool ===', $result['output']);
        $this->assertStringNotContainsString('Scan complete.', $result['output']);
        $this->assertStringNotContainsString('[WARN]', $result['output']);
        $this->assertStringNotContainsString('[CRITICAL]', $result['output']);
        $this->assertStringNotContainsString("\033[", $result['output']);
    }

    public function test_json_issues_have_severity_message_and_check(): void
    {
        $this->makeLaravelProject("APP_KEY=base64:SomeSuperSecretKey=\n");

        $result = $this->runSecCheck($this->tempDir);
        $issues = $result['json']['issues'] ?? [];

        $this->assertNotEmpty($issues);
        foreach ($issues as $issue) {
            $this->assertArrayHasKey('severity', $issue);
            $this->assertArrayHasKey('message', $issue);
            $this->assertArrayHasKey('check', $issue);
            $this->assertContains($issue['severity'], ['CRITICAL', 'WARN', 'INFO']);
        }
    }

    public function test_json_summary_counts_match_issues(): void
    {
        $this->makeLaravelProject("APP_KEY=base64:SomeSuperSecretKey=\n");

        $result  = $this->runSecCheck($this->tempDir);
        $summary = $result['json']['summary'];
        $issues  = $result['json']['issues'];

        $critical = count(array_filter($issues, fn($i) => $i['severity'] === 'CRITICAL'));
        $warn     = count(array_filter($issues, fn($i) => $i['severity'] === 'WARN'));
        $info     = count(array_filter($issues, fn($i) => $i['severity'] === 'INFO'));

        $this->assertSame(count($issues), $summary['total']);
        $this->assertSame($critical, $summary['critical']);
        $this->assertSame($warn, $summary['warn']);
        $this->assertSame($info, $summary['info']);
        $this->assertSame($summary['total'], $summary['critical'] + $summary['warn'] + $summary['info']);
    }

    public function test_json_includes_env_credential_warning(): void
    {
        $this->makeLaravelProject("APP_KEY=base64:SomeSuperSecretKey=\n");

        $result = $this->runSecCheck($this->tempDir);
        $issues = $result['json']['issues'] ?? [];

        $envIssues = array_filter($issues, fn($i) => $i['check'] === 'EnvCredentialsCheck');

        $this->assertNotEmpty($envIssues, 'JSON output should include the APP_KEY finding.');
        $this->assertSame('WARN', array_values($envIssues)[0]['severity']);
        $this->assertStringContainsString('APP_KEY', array_values($envIssues)[0]['message']);
    }

    public function test_json_marks_production_debug_as_critical(): void
    {
        $this->makeLaravelProject("APP_ENV=production\nAPP_DEBUG=true\n");

        $result = $this->runSecCheck($this->tempDir);
        $issues = $result['json']['issues'] ?? [];

        $debugIssues = array_values(array_filter($issues, fn($i) => $i['check'] === 'AppDebugCheck'));

        $this->assertNotEmpty($debugIssues);
        $this->assertSame('CRITICAL', $debugIssues[0]['severity']);
        $this->assertGreaterThanOrEqual(1, $result['json']['summary']['critical']);
    }

    public function test_json_marks_empty_db_password_as_critical(): void
    {
        $this->makeLaravelProject("DB_USERNAME=appuser\nDB_PASSWORD=\n");

        $result = $this->runSecCheck($this->tempDir);
        $issues = $result['json']['issues'] ?? [];

        $credIssues = array_values(array_filter(
            $issues,
            fn($i) => $i['check'] === 'DefaultCredentialsCheck' && $i['severity'] === 'CRITICAL'
        ));

        $this->assertNotEmpty($credIssues);
        $this->assertStringContainsString('DB_PASSWORD', $credIssues[0]['message']);
    }

    public function test_json_mode_exits_one_when_issues_found(): void
    {
        $this->makeLaravelProject("APP_KEY=base64:SomeSuperSecretKey=\n");

        $result = $this->runSecCheck($this->tempDir);

        $this->assertSame(1, $result['exit'], 'JSON mode should still exit 1 when issues are found.');
        $this->assertGreaterThan(0, $result['json']['summary']['total']);
    }

    public function test_json_mode_exit_code_is_always_zero_or_one(): void
    {
        $result = $this->runSecCheck($this->tempDir);

        $this->assertContains($result['exit'], [0, 1]);
        $this->assertNotNull($result['json']);
    }
}
