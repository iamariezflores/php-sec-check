<?php

namespace Aquilinoflores\PhpSecCheck\Tests\Checks\Laravel;

use Aquilinoflores\PhpSecCheck\Checks\Laravel\VendorCheck;
use PHPUnit\Framework\TestCase;

class VendorCheckTest extends TestCase
{
    private VendorCheck $check;
    private string $tempDir;

    protected function setUp(): void
    {
        $this->check = new VendorCheck();
        $this->tempDir = sys_get_temp_dir() . '/php-sec-check-vendor-test-' . uniqid();
        mkdir($this->tempDir, 0777, true);
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

    // -------------------------------------------------------------------------
    // No vendor directory
    // -------------------------------------------------------------------------

    public function test_returns_empty_when_no_vendor_dir(): void
    {
        $result = $this->check->run($this->tempDir);
        $this->assertEmpty($result);
    }

    // -------------------------------------------------------------------------
    // Vendor directory present
    // -------------------------------------------------------------------------

    public function test_warns_when_vendor_exists_and_no_gitignore(): void
    {
        mkdir($this->tempDir . '/vendor', 0777, true);

        $result = $this->check->run($this->tempDir);

        $this->assertCount(1, $result);
        $this->assertStringContainsString('vendor/', $result[0]);
        $this->assertStringContainsString('.gitignore', $result[0]);
    }

    public function test_warns_when_vendor_exists_and_gitignore_missing_vendor_entry(): void
    {
        mkdir($this->tempDir . '/vendor', 0777, true);
        file_put_contents($this->tempDir . '/.gitignore', ".env\n.DS_Store\n");

        $result = $this->check->run($this->tempDir);

        $this->assertCount(1, $result);
        $this->assertStringContainsString('vendor/', $result[0]);
    }

    public function test_no_warning_when_vendor_in_gitignore(): void
    {
        mkdir($this->tempDir . '/vendor', 0777, true);
        file_put_contents($this->tempDir . '/.gitignore', ".env\nvendor/\n.DS_Store\n");

        $result = $this->check->run($this->tempDir);

        $this->assertEmpty($result);
    }

    public function test_no_warning_when_vendor_in_gitignore_with_leading_slash(): void
    {
        mkdir($this->tempDir . '/vendor', 0777, true);
        // "/vendor/" with a leading slash is also a valid .gitignore pattern
        // but the current check uses strpos('vendor/') — this documents the behaviour.
        file_put_contents($this->tempDir . '/.gitignore', "/vendor/\n");

        $result = $this->check->run($this->tempDir);

        // strpos finds 'vendor/' inside '/vendor/', so this should pass too.
        $this->assertEmpty($result);
    }

    // -------------------------------------------------------------------------
    // Warning message format
    // -------------------------------------------------------------------------

    public function test_warning_message_mentions_gitignore(): void
    {
        mkdir($this->tempDir . '/vendor', 0777, true);

        $result = $this->check->run($this->tempDir);

        $this->assertStringContainsString('not ignored in .gitignore', $result[0]);
    }

    // -------------------------------------------------------------------------
    // Return type
    // -------------------------------------------------------------------------

    public function test_always_returns_array(): void
    {
        $result = $this->check->run($this->tempDir);
        $this->assertIsArray($result);
    }
}
