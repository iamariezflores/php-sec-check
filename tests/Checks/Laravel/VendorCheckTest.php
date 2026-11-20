<?php

namespace Aquilinoflores\PhpSecCheck\Tests\Checks\Laravel;

use Aquilinoflores\PhpSecCheck\Checks\Laravel\VendorCheck;
use Aquilinoflores\PhpSecCheck\Issue;
use PHPUnit\Framework\TestCase;

class VendorCheckTest extends TestCase
{
    private VendorCheck $check;
    private string $tempDir;

    protected function setUp(): void
    {
        $this->check   = new VendorCheck();
        $this->tempDir = sys_get_temp_dir() . '/php-sec-check-vendor-test-' . uniqid();
        mkdir($this->tempDir, 0777, true);
    }

    protected function tearDown(): void
    {
        $this->removeTempDir($this->tempDir);
    }

    private function removeTempDir(string $dir): void
    {
        if (!is_dir($dir)) return;
        foreach (array_diff(scandir($dir), ['.', '..']) as $item) {
            $path = $dir . DIRECTORY_SEPARATOR . $item;
            is_dir($path) ? $this->removeTempDir($path) : unlink($path);
        }
        rmdir($dir);
    }

    public function test_returns_empty_when_no_vendor_dir(): void
    {
        $result = $this->check->run($this->tempDir);
        $this->assertEmpty($result);
    }

    public function test_warns_when_vendor_exists_and_no_gitignore(): void
    {
        mkdir($this->tempDir . '/vendor', 0777, true);

        $result = $this->check->run($this->tempDir);

        $this->assertCount(1, $result);
        $this->assertInstanceOf(Issue::class, $result[0]);
        $this->assertSame(Issue::WARN, $result[0]->severity);
        $this->assertStringContainsString('vendor/', $result[0]->message);
        $this->assertStringContainsString('.gitignore', $result[0]->message);
    }

    public function test_warns_when_vendor_exists_and_gitignore_missing_vendor_entry(): void
    {
        mkdir($this->tempDir . '/vendor', 0777, true);
        file_put_contents($this->tempDir . '/.gitignore', ".env\n.DS_Store\n");

        $result = $this->check->run($this->tempDir);

        $this->assertCount(1, $result);
        $this->assertStringContainsString('vendor/', $result[0]->message);
    }

    public function test_no_warning_when_vendor_in_gitignore(): void
    {
        mkdir($this->tempDir . '/vendor', 0777, true);
        file_put_contents($this->tempDir . '/.gitignore', ".env\nvendor/\n");

        $result = $this->check->run($this->tempDir);
        $this->assertEmpty($result);
    }

    public function test_no_warning_when_vendor_in_gitignore_with_leading_slash(): void
    {
        mkdir($this->tempDir . '/vendor', 0777, true);
        file_put_contents($this->tempDir . '/.gitignore', "/vendor/\n");

        $result = $this->check->run($this->tempDir);
        $this->assertEmpty($result);
    }

    public function test_no_warning_when_gitignore_lists_vendor_without_a_slash(): void
    {
        mkdir($this->tempDir . '/vendor', 0777, true);
        file_put_contents($this->tempDir . '/.gitignore', "vendor\n");

        $result = $this->check->run($this->tempDir);
        $this->assertEmpty($result);
    }

    public function test_warns_when_vendor_appears_only_in_a_comment(): void
    {
        mkdir($this->tempDir . '/vendor', 0777, true);
        file_put_contents($this->tempDir . '/.gitignore', "# keep vendor/ out of the web root\n");

        $result = $this->check->run($this->tempDir);

        $this->assertCount(1, $result);
        $this->assertSame(Issue::WARN, $result[0]->severity);
    }

    public function test_warning_message_mentions_gitignore(): void
    {
        mkdir($this->tempDir . '/vendor', 0777, true);

        $result = $this->check->run($this->tempDir);
        $this->assertStringContainsString('not ignored in .gitignore', $result[0]->message);
    }

    public function test_always_returns_array(): void
    {
        $result = $this->check->run($this->tempDir);
        $this->assertIsArray($result);
    }
}
