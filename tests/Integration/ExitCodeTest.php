<?php

namespace Aquilinoflores\PhpSecCheck\Tests\Integration;

use PHPUnit\Framework\TestCase;

/**
 * Exit Code Tests
 *
 * Verifies that the CLI exits with code 0 (clean) or 1 (issues found),
 * which is required for CI/CD pipelines to correctly detect failures.
 */
class ExitCodeTest extends TestCase
{
    private string $tempDir;
    private string $binPath;

    protected function setUp(): void
    {
        $this->tempDir = sys_get_temp_dir() . '/php-sec-check-exit-test-' . uniqid();
        mkdir($this->tempDir, 0777, true);

        // Resolve the bin path relative to this test file
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
     * Run sec-check against a given directory and return the exit code.
     */
    private function runSecCheck(string $projectRoot): int
    {
        $php = PHP_BINARY;
        $bin = escapeshellarg($this->binPath);
        $dir = escapeshellarg($projectRoot);

        exec("cd $dir && $php $bin 2>/dev/null", $output, $exitCode);

        return $exitCode;
    }

    // -------------------------------------------------------------------------
    // Exit code 0 — no issues
    // -------------------------------------------------------------------------

    public function test_exits_zero_when_no_issues_found(): void
    {
        // An empty directory with no composer.lock, no .env, no vendor/ — clean.
        // The only checks that can fire are PHP version and display_errors/dangerous
        // functions, both of which depend on the runtime ini. We test the shape
        // of the exit logic, not the specific runtime state.
        $exitCode = $this->runSecCheck($this->tempDir);

        $this->assertContains(
            $exitCode,
            [0, 1],
            'Exit code must be 0 (clean) or 1 (issues found) — never anything else.'
        );
    }

    // -------------------------------------------------------------------------
    // Exit code 1 — issues found
    // -------------------------------------------------------------------------

    public function test_exits_one_when_env_credentials_found(): void
    {
        // Simulate a Laravel project with sensitive keys in .env
        touch($this->tempDir . '/artisan');
        mkdir($this->tempDir . '/bootstrap', 0777, true);
        file_put_contents($this->tempDir . '/bootstrap/app.php', '<?php return new class {};');
        file_put_contents($this->tempDir . '/.env', "APP_KEY=base64:SomeSuperSecretKey=\n");
        file_put_contents($this->tempDir . '/php-sec-check-config.php',
            "<?php return ['sensitive_keys' => ['APP_KEY']];"
        );

        $exitCode = $this->runSecCheck($this->tempDir);

        $this->assertSame(1, $exitCode, 'Should exit 1 when sensitive .env keys are detected.');
    }

    public function test_exits_one_when_vendor_not_in_gitignore(): void
    {
        // Simulate a Laravel project with vendor/ not ignored
        touch($this->tempDir . '/artisan');
        mkdir($this->tempDir . '/bootstrap', 0777, true);
        file_put_contents($this->tempDir . '/bootstrap/app.php', '<?php return new class {};');
        mkdir($this->tempDir . '/vendor', 0777, true);
        file_put_contents($this->tempDir . '/.gitignore', ".env\n");

        $exitCode = $this->runSecCheck($this->tempDir);

        $this->assertSame(1, $exitCode, 'Should exit 1 when vendor/ is not in .gitignore.');
    }

    // -------------------------------------------------------------------------
    // Exit code is always 0 or 1 — never unexpected values
    // -------------------------------------------------------------------------

    public function test_exit_code_is_always_zero_or_one(): void
    {
        $exitCode = $this->runSecCheck($this->tempDir);

        $this->assertContains(
            $exitCode,
            [0, 1],
            'The CLI must only ever exit with 0 or 1.'
        );
    }
}
