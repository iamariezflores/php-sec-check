<?php

namespace Aquilinoflores\PhpSecCheck\Tests\Checks\Laravel;

use Aquilinoflores\PhpSecCheck\Checks\Laravel\EnvCredentialsCheck;
use InvalidArgumentException;
use PHPUnit\Framework\TestCase;

class EnvCredentialsCheckTest extends TestCase
{
    private string $tempDir;

    protected function setUp(): void
    {
        $this->tempDir = sys_get_temp_dir() . '/php-sec-check-env-test-' . uniqid();
        mkdir($this->tempDir, 0777, true);
    }

    protected function tearDown(): void
    {
        foreach (array_diff(scandir($this->tempDir), ['.', '..']) as $item) {
            $path = $this->tempDir . DIRECTORY_SEPARATOR . $item;
            if (is_file($path)) {
                unlink($path);
            }
        }
        rmdir($this->tempDir);
    }

    // -------------------------------------------------------------------------
    // Constructor validation
    // -------------------------------------------------------------------------

    public function test_throws_when_custom_key_is_not_a_string(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageMatches('/must be strings/');

        new EnvCredentialsCheck([123]);
    }

    public function test_accepts_empty_custom_keys(): void
    {
        $check = new EnvCredentialsCheck([]);
        $this->assertInstanceOf(EnvCredentialsCheck::class, $check);
    }

    public function test_accepts_valid_string_custom_keys(): void
    {
        $check = new EnvCredentialsCheck(['MY_SECRET', 'ANOTHER_KEY']);
        $this->assertInstanceOf(EnvCredentialsCheck::class, $check);
    }

    // -------------------------------------------------------------------------
    // Project root validation
    // -------------------------------------------------------------------------

    public function test_throws_on_empty_project_root(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageMatches('/Invalid project root/');

        (new EnvCredentialsCheck())->run('');
    }

    public function test_throws_on_non_existent_project_root(): void
    {
        $this->expectException(InvalidArgumentException::class);

        (new EnvCredentialsCheck())->run('/this/does/not/exist');
    }

    // -------------------------------------------------------------------------
    // Missing .env file
    // -------------------------------------------------------------------------

    public function test_returns_message_when_no_env_file(): void
    {
        $result = (new EnvCredentialsCheck())->run($this->tempDir);

        $this->assertCount(1, $result);
        $this->assertStringContainsString('No .env file found', $result[0]);
    }

    // -------------------------------------------------------------------------
    // Key detection
    // -------------------------------------------------------------------------

    public function test_detects_sensitive_key_in_env(): void
    {
        // Use a key that is NOT in the built-in default list to avoid duplicates.
        file_put_contents($this->tempDir . '/.env', "MY_SECRET_TOKEN=supersecretvalue\n");

        $result = (new EnvCredentialsCheck(['MY_SECRET_TOKEN']))->run($this->tempDir);

        $this->assertCount(1, $result);
        $this->assertStringContainsString("Sensitive key 'MY_SECRET_TOKEN'", $result[0]);
        $this->assertStringContainsString('.env', $result[0]);
    }

    public function test_detects_multiple_sensitive_keys(): void
    {
        file_put_contents($this->tempDir . '/.env',
            "CUSTOM_API_KEY=abc123\nCUSTOM_SECRET=xyz789\n"
        );

        $result = (new EnvCredentialsCheck(['CUSTOM_API_KEY', 'CUSTOM_SECRET']))->run($this->tempDir);

        $this->assertCount(2, $result);
    }

    public function test_skips_key_with_null_value(): void
    {
        file_put_contents($this->tempDir . '/.env', "DB_PASSWORD=null\n");

        $result = (new EnvCredentialsCheck(['DB_PASSWORD']))->run($this->tempDir);

        $this->assertEmpty($result);
    }

    public function test_skips_key_with_empty_value(): void
    {
        file_put_contents($this->tempDir . '/.env', "DB_PASSWORD=\n");

        $result = (new EnvCredentialsCheck(['DB_PASSWORD']))->run($this->tempDir);

        $this->assertEmpty($result);
    }

    public function test_skips_key_not_present_in_env(): void
    {
        file_put_contents($this->tempDir . '/.env', "APP_NAME=MyApp\n");

        $result = (new EnvCredentialsCheck(['DB_PASSWORD']))->run($this->tempDir);

        $this->assertEmpty($result);
    }

    // -------------------------------------------------------------------------
    // Value masking
    // -------------------------------------------------------------------------

    public function test_masks_value_correctly(): void
    {
        file_put_contents($this->tempDir . '/.env', "MY_TOKEN=base64:AbcDefGhi=\n");

        $result = (new EnvCredentialsCheck(['MY_TOKEN']))->run($this->tempDir);

        $this->assertCount(1, $result);
        // First 4 chars exposed, rest masked with asterisks
        $this->assertStringContainsString("base****", $result[0]);
        $this->assertStringNotContainsString('AbcDefGhi', $result[0]);
    }

    public function test_short_value_masked_entirely(): void
    {
        // Value shorter than 4 chars — all chars shown, no asterisks needed
        file_put_contents($this->tempDir . '/.env', "MY_TOKEN=abc\n");

        $result = (new EnvCredentialsCheck(['MY_TOKEN']))->run($this->tempDir);

        $this->assertCount(1, $result);
        $this->assertStringContainsString('abc', $result[0]);
    }

    // -------------------------------------------------------------------------
    // Config file integration
    // -------------------------------------------------------------------------

    public function test_reads_keys_from_config_file_when_present(): void
    {
        file_put_contents($this->tempDir . '/.env', "STRIPE_SECRET_KEY=sk_live_secret\n");

        file_put_contents($this->tempDir . '/php-sec-check-config.php', <<<'PHP'
<?php
return ['sensitive_keys' => ['STRIPE_SECRET_KEY']];
PHP);

        $result = (new EnvCredentialsCheck())->run($this->tempDir);

        $this->assertCount(1, $result);
        $this->assertStringContainsString("'STRIPE_SECRET_KEY'", $result[0]);

        unlink($this->tempDir . '/php-sec-check-config.php');
    }

    public function test_uses_default_keys_when_no_config_file(): void
    {
        file_put_contents($this->tempDir . '/.env', "DB_PASSWORD=secret\n");

        // No config file — should fall back to built-in defaults which include DB_PASSWORD
        $result = (new EnvCredentialsCheck())->run($this->tempDir);

        $this->assertCount(1, $result);
        $this->assertStringContainsString("'DB_PASSWORD'", $result[0]);
    }

    public function test_constructor_custom_keys_merged_with_config_keys(): void
    {
        file_put_contents($this->tempDir . '/.env',
            "APP_KEY=base64:key=\nCUSTOM_TOKEN=supersecret\n"
        );

        file_put_contents($this->tempDir . '/php-sec-check-config.php', <<<'PHP'
<?php
return ['sensitive_keys' => ['APP_KEY']];
PHP);

        $result = (new EnvCredentialsCheck(['CUSTOM_TOKEN']))->run($this->tempDir);

        $this->assertCount(2, $result);

        unlink($this->tempDir . '/php-sec-check-config.php');
    }

    // -------------------------------------------------------------------------
    // Return type
    // -------------------------------------------------------------------------

    public function test_always_returns_array(): void
    {
        file_put_contents($this->tempDir . '/.env', "APP_NAME=MyApp\n");

        $result = (new EnvCredentialsCheck())->run($this->tempDir);

        $this->assertIsArray($result);
    }
}
