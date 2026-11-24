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
     * @param list<string> $extraArgs
     * @return array{exit: int, output: string, json: ?array}
     */
    private function runSecCheck(string $projectRoot, array $extraArgs = ['--min-severity=info']): array
    {
        $cmd = array_merge([PHP_BINARY, $this->binPath, '--format=json'], $extraArgs);

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
        $this->assertArrayHasKey('findings', $result['json']);
        $this->assertArrayHasKey('total', $result['json']['summary']);
        $this->assertArrayHasKey('critical', $result['json']['summary']);
        $this->assertArrayHasKey('high', $result['json']['summary']);
        $this->assertArrayHasKey('medium', $result['json']['summary']);
        $this->assertArrayHasKey('low', $result['json']['summary']);
        $this->assertArrayHasKey('info', $result['json']['summary']);
        $this->assertArrayHasKey('hidden', $result['json']['summary']);
        $this->assertArrayHasKey('threshold', $result['json']['summary']);
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
        file_put_contents($this->tempDir . '/.env', "DB_PASSWORD=password\n");

        $result = $this->runSecCheck($this->tempDir);
        $findings = $result['json']['findings'] ?? [];

        $this->assertNotEmpty($findings);
        foreach ($findings as $finding) {
            $this->assertArrayHasKey('severity', $finding);
            $this->assertArrayHasKey('message', $finding);
            $this->assertArrayHasKey('check', $finding);
            $this->assertArrayHasKey('ruleId', $finding);
            $this->assertArrayHasKey('confidence', $finding);
            $this->assertArrayHasKey('recommendation', $finding);
            $this->assertContains($finding['severity'], ['critical', 'high', 'medium', 'low', 'info']);
        }
    }

    public function test_json_summary_counts_match_issues(): void
    {
        $this->makeLaravelProject("APP_KEY=base64:SomeSuperSecretKey=\n");

        $result  = $this->runSecCheck($this->tempDir);
        $summary = $result['json']['summary'];
        $findings = $result['json']['findings'];

        $critical = count(array_filter($findings, fn($i) => $i['severity'] === 'critical'));
        $high     = count(array_filter($findings, fn($i) => $i['severity'] === 'high'));
        $medium   = count(array_filter($findings, fn($i) => $i['severity'] === 'medium'));
        $low      = count(array_filter($findings, fn($i) => $i['severity'] === 'low'));
        $info     = count(array_filter($findings, fn($i) => $i['severity'] === 'info'));

        $this->assertSame(count($findings), $summary['total']);
        $this->assertSame($critical, $summary['critical']);
        $this->assertSame($high, $summary['high']);
        $this->assertSame($medium, $summary['medium']);
        $this->assertSame($low, $summary['low']);
        $this->assertSame($info, $summary['info']);
        $this->assertSame(0, $summary['hidden']);
        $this->assertSame(
            $summary['total'],
            $summary['critical'] + $summary['high'] + $summary['medium'] + $summary['low'] + $summary['info']
        );
    }

    public function test_json_includes_env_example_secret_finding(): void
    {
        $this->makeLaravelProject("APP_KEY=base64:SomeSuperSecretKey=\n");
        file_put_contents(
            $this->tempDir . '/.env.example',
            "APP_KEY=base64:ThisIsARealLookingApplicationKey=\n"
        );

        $result = $this->runSecCheck($this->tempDir);
        $findings = $result['json']['findings'] ?? [];

        $envIssues = array_values(array_filter($findings, fn($i) => $i['check'] === 'EnvCredentialsCheck'));

        $this->assertNotEmpty($envIssues, 'JSON output should include the .env.example leak.');
        $this->assertSame('critical', $envIssues[0]['severity']);
        $this->assertStringContainsString('.env.example', $envIssues[0]['message']);
        $this->assertStringContainsString('APP_KEY', $envIssues[0]['message']);
    }

    public function test_json_marks_production_debug_as_critical(): void
    {
        $this->makeLaravelProject("APP_ENV=production\nAPP_DEBUG=true\n");

        $result = $this->runSecCheck($this->tempDir, ['--min-severity=info', '--profile=laravel']);
        $findings = $result['json']['findings'] ?? [];

        $debugIssues = array_values(array_filter($findings, fn($i) => $i['check'] === 'AppDebugCheck'));

        $this->assertNotEmpty($debugIssues);
        $this->assertSame('critical', $debugIssues[0]['severity']);
        $this->assertGreaterThanOrEqual(1, $result['json']['summary']['critical']);
    }

    public function test_json_marks_empty_db_password_as_critical(): void
    {
        $this->makeLaravelProject("DB_USERNAME=appuser\nDB_PASSWORD=\n");

        $result = $this->runSecCheck($this->tempDir, ['--min-severity=info', '--profile=laravel']);
        $findings = $result['json']['findings'] ?? [];

        $credIssues = array_values(array_filter(
            $findings,
            fn($i) => $i['check'] === 'DefaultCredentialsCheck' && $i['severity'] === 'critical'
        ));

        $this->assertNotEmpty($credIssues);
        $this->assertStringContainsString('DB_PASSWORD', $credIssues[0]['message']);
    }

    public function test_json_mode_exits_one_when_issues_found(): void
    {
        $this->makeLaravelProject("APP_KEY=base64:SomeSuperSecretKey=\n");
        mkdir($this->tempDir . '/public');
        file_put_contents($this->tempDir . '/public/.env', "APP_KEY=base64:SomeSuperSecretKey=\n");

        $result = $this->runSecCheck($this->tempDir);

        $this->assertSame(1, $result['exit'], 'JSON mode should still exit 1 when a finding meets the threshold.');
        $this->assertGreaterThan(0, $result['json']['summary']['total']);
    }

    public function test_default_threshold_hides_medium_findings_and_does_not_write_config(): void
    {
        file_put_contents($this->tempDir . '/.env', "DB_PASSWORD=password\n");

        $result = $this->runSecCheck($this->tempDir, []);
        $shown = $result['json']['findings'] ?? [];

        $this->assertNotNull($result['json']);
        $this->assertGreaterThan(0, $result['json']['summary']['hidden']);
        $this->assertFileDoesNotExist($this->tempDir . '/php-sec-check-config.php');
        foreach ($shown as $finding) {
            $this->assertContains($finding['severity'], ['critical', 'high']);
            $this->assertStringNotContainsString('DB_PASSWORD', $finding['message']);
        }
        $this->assertSame($shown === [] ? 0 : 1, $result['exit']);
    }

    public function test_json_mode_exit_code_is_always_zero_or_one(): void
    {
        $result = $this->runSecCheck($this->tempDir);

        $this->assertContains($result['exit'], [0, 1]);
        $this->assertNotNull($result['json']);
    }
}
