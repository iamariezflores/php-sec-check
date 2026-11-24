<?php

namespace Aquilinoflores\PhpSecCheck\Tests\Integration;

use PHPUnit\Framework\TestCase;

/**
 * CLI exit codes.
 *
 * 0 — nothing at or above the threshold.
 * 1 — a finding meets the threshold.
 * 2 — invalid arguments.
 * 3 — the path cannot be read.
 */
class ExitCodeTest extends TestCase
{
    private string $tempDir;
    private string $binPath;

    protected function setUp(): void
    {
        $this->tempDir = sys_get_temp_dir() . '/php-sec-check-exit-test-' . uniqid();
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
     * @param list<string> $args
     * @return array{exit: int, stdout: string, stderr: string}
     */
    private function runSecCheck(array $args = [], ?string $cwd = null): array
    {
        $proc = proc_open(
            array_merge([PHP_BINARY, $this->binPath], $args),
            [
                0 => ['pipe', 'r'],
                1 => ['pipe', 'w'],
                2 => ['pipe', 'w'],
            ],
            $pipes,
            $cwd ?? $this->tempDir
        );

        $this->assertIsResource($proc);

        fclose($pipes[0]);
        $stdout = stream_get_contents($pipes[1]);
        $stderr = stream_get_contents($pipes[2]);
        fclose($pipes[1]);
        fclose($pipes[2]);

        return [
            'exit'   => proc_close($proc),
            'stdout' => $stdout,
            'stderr' => $stderr,
        ];
    }

    public function test_default_threshold_omits_medium_findings(): void
    {
        file_put_contents($this->tempDir . '/.env', "DB_PASSWORD=password\n");

        $result = $this->runSecCheck();

        $this->assertStringNotContainsString('DB_PASSWORD', $result['stdout']);
        $this->assertStringContainsString('hidden below high', $result['stdout']);
        $this->assertFileDoesNotExist($this->tempDir . '/php-sec-check-config.php');
        $this->assertContains($result['exit'], [0, 1]);
    }

    public function test_exits_one_when_env_is_publicly_accessible(): void
    {
        mkdir($this->tempDir . '/public');
        file_put_contents($this->tempDir . '/public/.env', "APP_KEY=base64:SomeSuperSecretKey=\n");

        $result = $this->runSecCheck([$this->tempDir], dirname($this->tempDir));

        $this->assertSame(1, $result['exit']);
        $this->assertStringContainsString('public/.env', $result['stdout']);
        $this->assertStringContainsString($this->tempDir, $result['stdout']);
    }

    public function test_medium_threshold_fails_on_a_medium_finding(): void
    {
        file_put_contents($this->tempDir . '/.env', "DB_PASSWORD=password\n");

        $result = $this->runSecCheck(['--min-severity=medium']);

        $this->assertSame(1, $result['exit']);
        $this->assertStringContainsString('DB_PASSWORD', $result['stdout']);
    }

    public function test_unknown_option_exits_two(): void
    {
        $result = $this->runSecCheck(['--nope']);

        $this->assertSame(2, $result['exit']);
        $this->assertStringContainsString('Unknown option', $result['stderr']);
    }

    public function test_missing_directory_exits_three(): void
    {
        $result = $this->runSecCheck([$this->tempDir . '/missing']);

        $this->assertSame(3, $result['exit']);
        $this->assertStringContainsString('Not a directory', $result['stderr']);
    }

    public function test_init_writes_config_and_refuses_to_overwrite(): void
    {
        $created = $this->runSecCheck(['init']);
        $this->assertSame(0, $created['exit']);
        $this->assertFileExists($this->tempDir . '/php-sec-check-config.php');

        $again = $this->runSecCheck(['init']);
        $this->assertSame(2, $again['exit']);
        $this->assertStringContainsString('already exists', $again['stderr']);
    }

    public function test_rules_lists_ids_and_exits_zero(): void
    {
        $result = $this->runSecCheck(['rules']);

        $this->assertSame(0, $result['exit']);
        $this->assertStringContainsString('PSC-SRC-080', $result['stdout']);
        $this->assertStringContainsString('PSC-WEB-001', $result['stdout']);
    }

    public function test_exclude_hides_a_public_env_path(): void
    {
        mkdir($this->tempDir . '/public');
        file_put_contents($this->tempDir . '/public/.env', "APP_KEY=base64:SomeSuperSecretKey=\n");

        $result = $this->runSecCheck(['--exclude=public/.env', '--min-severity=info']);

        $this->assertStringNotContainsString('public/.env', $result['stdout']);
    }
}
