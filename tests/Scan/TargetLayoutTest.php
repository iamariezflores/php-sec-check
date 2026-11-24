<?php

namespace Aquilinoflores\PhpSecCheck\Tests\Scan;

use Aquilinoflores\PhpSecCheck\Scan\TargetLayout;
use PHPUnit\Framework\TestCase;

class TargetLayoutTest extends TestCase
{
    private string $tempDir;

    protected function setUp(): void
    {
        $this->tempDir = sys_get_temp_dir() . '/php-sec-check-layout-' . uniqid();
        mkdir($this->tempDir, 0777, true);
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
            is_dir($path) ? $this->removeDir($path) : unlink($path);
        }
        rmdir($dir);
    }

    public function test_public_is_a_root_without_an_index(): void
    {
        mkdir($this->tempDir . '/public');

        $roots = TargetLayout::documentRoots($this->tempDir);

        $this->assertArrayHasKey('public', $roots);
        $this->assertArrayNotHasKey('', $roots);
    }

    public function test_www_needs_an_index_or_htaccess(): void
    {
        mkdir($this->tempDir . '/www');
        $this->assertSame([], TargetLayout::documentRoots($this->tempDir));

        file_put_contents($this->tempDir . '/www/.htaccess', "Options -Indexes\n");
        $this->assertArrayHasKey('www', TargetLayout::documentRoots($this->tempDir));
    }

    public function test_root_index_is_the_docroot_until_a_named_directory_has_one(): void
    {
        file_put_contents($this->tempDir . '/index.php', "<?php\n");
        $this->assertArrayHasKey('', TargetLayout::documentRoots($this->tempDir));

        mkdir($this->tempDir . '/htdocs');
        file_put_contents($this->tempDir . '/htdocs/index.php', "<?php\n");
        $roots = TargetLayout::documentRoots($this->tempDir);
        $this->assertArrayHasKey('htdocs', $roots);
        $this->assertArrayNotHasKey('', $roots);
    }
}
