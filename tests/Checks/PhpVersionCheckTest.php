<?php

namespace Aquilinoflores\PhpSecCheck\Tests\Checks;

use Aquilinoflores\PhpSecCheck\Checks\PhpVersionCheck;
use Aquilinoflores\PhpSecCheck\Issue;
use DateTimeImmutable;
use PHPUnit\Framework\TestCase;

class PhpVersionCheckTest extends TestCase
{
    private string $tempDir;
    private DateTimeImmutable $today;

    protected function setUp(): void
    {
        $this->tempDir = sys_get_temp_dir() . '/php-sec-check-phpver-' . uniqid();
        mkdir($this->tempDir, 0777, true);
        $this->today = new DateTimeImmutable('2026-11-18');
    }

    protected function tearDown(): void
    {
        $this->removeDir($this->tempDir);
    }

    private function removeDir(string $dir): void
    {
        if (!is_dir($dir)) {
            return;
        }
        foreach (array_diff(scandir($dir), ['.', '..']) as $item) {
            $path = $dir . DIRECTORY_SEPARATOR . $item;
            is_file($path) ? @unlink($path) : $this->removeDir($path);
        }
        @rmdir($dir);
    }

    /**
     * @return list<Issue>
     */
    private function runCheck(string $runtime, string $root = ''): array
    {
        $root = $root === '' ? $this->tempDir : $root;
        ob_start();
        $result = (new PhpVersionCheck($runtime, $this->today))->run($root);
        ob_end_clean();
        return $result;
    }

    public function test_output_contains_php_version_header_and_runtime(): void
    {
        ob_start();
        (new PhpVersionCheck('8.3.36', $this->today))->run($this->tempDir);
        $output = ob_get_clean();

        $this->assertStringContainsString('[PHP VERSION]', $output);
        $this->assertStringContainsString('Scanner runtime: 8.3.36', $output);
        $this->assertStringNotContainsString('recommend >=8.0', $output);
    }

    public function test_supported_runtime_without_pins_is_clean(): void
    {
        $result = $this->runCheck('8.3.36');
        $this->assertEmpty($result);
    }

    public function test_eol_runtime_is_critical(): void
    {
        $result = $this->runCheck('8.1.32');

        $this->assertCount(1, $result);
        $this->assertSame(Issue::CRITICAL, $result[0]->severity);
        $this->assertStringContainsString('PHP 8.1', $result[0]->message);
        $this->assertStringContainsString('scanner runtime', $result[0]->message);
        $this->assertStringContainsString('past security support', $result[0]->message);
        $this->assertStringContainsString('2025-12-31', $result[0]->message);
    }

    public function test_runtime_nearing_eol_is_a_warning(): void
    {
        $result = $this->runCheck('8.2.26');

        $this->assertCount(1, $result);
        $this->assertSame(Issue::WARN, $result[0]->severity);
        $this->assertStringContainsString('nearing the end of security support', $result[0]->message);
        $this->assertStringContainsString('2026-12-31', $result[0]->message);
    }

    public function test_composer_floor_eol_is_critical_even_when_runtime_is_supported(): void
    {
        file_put_contents($this->tempDir . '/composer.json', json_encode([
            'require' => ['php' => '>=8.1'],
        ]));

        $result = $this->runCheck('8.3.36');
        $messages = array_map(fn(Issue $i) => $i->message, $result);

        $this->assertTrue((bool) array_filter(
            $messages,
            fn($m) => str_contains($m, 'composer.json require.php') && str_contains($m, 'PHP 8.1')
        ));
        $this->assertSame(Issue::CRITICAL, $result[0]->severity);
    }

    public function test_platform_php_mismatch_is_a_warning(): void
    {
        file_put_contents($this->tempDir . '/composer.json', json_encode([
            'require' => ['php' => '>=8.2'],
            'config'  => ['platform' => ['php' => '8.2.24']],
        ]));

        $result = $this->runCheck('8.4.1');
        $messages = array_map(fn(Issue $i) => $i->message, $result);

        $this->assertTrue((bool) array_filter(
            $messages,
            fn($m) => str_contains($m, 'platform.php') && str_contains($m, 'Production may differ')
        ));
    }

    public function test_php_version_file_pin_is_detected(): void
    {
        file_put_contents($this->tempDir . '/.php-version', "8.1.27\n");

        $result = $this->runCheck('8.3.36');
        $messages = array_map(fn(Issue $i) => $i->message, $result);

        $this->assertTrue((bool) array_filter($messages, fn($m) => str_contains($m, '.php-version')));
        $this->assertTrue((bool) array_filter(
            $messages,
            fn($m) => str_contains($m, 'PHP 8.1') && str_contains($m, 'past security support')
        ));
    }

    public function test_tool_versions_pin_is_detected(): void
    {
        file_put_contents($this->tempDir . '/.tool-versions', "nodejs 20.11.0\nphp 8.1.99\n");

        $result = $this->runCheck('8.3.0');
        $messages = array_map(fn(Issue $i) => $i->message, $result);

        $this->assertTrue((bool) array_filter($messages, fn($m) => str_contains($m, '.tool-versions')));
    }

    public function test_dockerfile_php_image_is_detected(): void
    {
        file_put_contents($this->tempDir . '/Dockerfile', "FROM php:8.1-cli-alpine\n");

        $result = $this->runCheck('8.3.0');
        $messages = array_map(fn(Issue $i) => $i->message, $result);

        $this->assertTrue((bool) array_filter($messages, fn($m) => str_contains($m, 'Dockerfile')));
        $this->assertTrue((bool) array_filter($messages, fn($m) => str_contains($m, 'PHP 8.1')));
    }

    public function test_caret_constraint_uses_the_lowest_allowed_minor(): void
    {
        file_put_contents($this->tempDir . '/composer.json', json_encode([
            'require' => ['php' => '^8.3 || ^8.2'],
        ]));

        ob_start();
        (new PhpVersionCheck('8.3.36', $this->today))->run($this->tempDir);
        $output = ob_get_clean();

        $this->assertStringContainsString('floor 8.2.0', $output);
    }

    public function test_does_not_use_hardcoded_php_80_threshold(): void
    {
        $result = $this->runCheck('8.0.30');

        $this->assertNotEmpty($result);
        $this->assertStringContainsString('past security support', $result[0]->message);
        $this->assertStringNotContainsString('>=8.0', $result[0]->message);
        $this->assertStringNotContainsString('below 8.0', $result[0]->message);
    }

    public function test_always_returns_issue_objects(): void
    {
        $result = $this->runCheck('8.1.0');
        foreach ($result as $item) {
            $this->assertInstanceOf(Issue::class, $item);
            $this->assertSame('PhpVersionCheck', $item->check);
        }
    }
}
