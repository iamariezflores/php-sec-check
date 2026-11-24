<?php

namespace Aquilinoflores\PhpSecCheck\Tests\Php;

use Aquilinoflores\PhpSecCheck\Php\ProjectPhpSettings;
use PHPUnit\Framework\TestCase;

class ProjectPhpSettingsTest extends TestCase
{
    private string $tempDir;

    protected function setUp(): void
    {
        $this->tempDir = sys_get_temp_dir() . '/php-sec-check-settings-' . uniqid();
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

    public function test_reads_user_ini_htaccess_and_ini_set(): void
    {
        file_put_contents($this->tempDir . '/.user.ini', "display_errors = On\n");
        file_put_contents($this->tempDir . '/.htaccess', "php_value session.cookie_samesite None\n");
        file_put_contents($this->tempDir . '/boot.php', "<?php\nini_set('expose_php', '0');\n");
        mkdir($this->tempDir . '/vendor');
        file_put_contents($this->tempDir . '/vendor/skip.php', "<?php\nini_set('display_errors', '1');\n");

        $settings = ProjectPhpSettings::load($this->tempDir);

        $display = $settings->directives('display_errors');
        $this->assertCount(1, $display);
        $this->assertTrue($display[0]->isEnabled());
        $this->assertSame('.user.ini', $display[0]->path);

        $sameSite = $settings->directives('session.cookie_samesite');
        $this->assertSame('None', $sameSite[0]->value);
        $this->assertSame('.htaccess', $sameSite[0]->path);

        $expose = $settings->directives('expose_php');
        $this->assertTrue($expose[0]->isDisabled());
        $this->assertSame('boot.php', $expose[0]->path);
        $this->assertSame(2, $expose[0]->line);
    }

    public function test_scanner_ini_is_not_loaded(): void
    {
        $previous = ini_get('display_errors');
        ini_set('display_errors', '1');

        $settings = ProjectPhpSettings::load($this->tempDir);

        ini_set('display_errors', $previous);

        $this->assertFalse($settings->has('display_errors'));
    }
}
