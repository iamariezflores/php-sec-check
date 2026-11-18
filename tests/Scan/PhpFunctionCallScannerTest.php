<?php

namespace Aquilinoflores\PhpSecCheck\Tests\Scan;

use Aquilinoflores\PhpSecCheck\Scan\PhpFunctionCallScanner;
use PHPUnit\Framework\TestCase;

class PhpFunctionCallScannerTest extends TestCase
{
    private PhpFunctionCallScanner $scanner;

    protected function setUp(): void
    {
        $this->scanner = new PhpFunctionCallScanner();
    }

    public function test_finds_plain_function_call(): void
    {
        $calls = $this->scanner->findCalls('<?php exec("ls");', ['exec']);

        $this->assertCount(1, $calls);
        $this->assertSame('exec', $calls[0]['function']);
        $this->assertFalse($calls[0]['untrusted']);
        $this->assertSame('call', $calls[0]['via']);
    }

    public function test_marks_superglobal_argument_as_untrusted(): void
    {
        $calls = $this->scanner->findCalls('<?php exec($_GET["cmd"]);', ['exec']);

        $this->assertCount(1, $calls);
        $this->assertTrue($calls[0]['untrusted']);
    }

    public function test_marks_php_input_as_untrusted(): void
    {
        $calls = $this->scanner->findCalls('<?php eval(file_get_contents("php://input"));', ['eval']);

        $this->assertCount(1, $calls);
        $this->assertTrue($calls[0]['untrusted']);
    }

    public function test_detects_eval_construct(): void
    {
        $calls = $this->scanner->findCalls('<?php eval("1+1");', ['eval']);

        $this->assertCount(1, $calls);
        $this->assertSame('eval', $calls[0]['function']);
    }

    public function test_detects_backtick_shell_execution(): void
    {
        $calls = $this->scanner->findCalls('<?php $out = `ls`;', ['shell_exec']);

        $this->assertCount(1, $calls);
        $this->assertSame('shell_exec', $calls[0]['function']);
        $this->assertSame('backtick', $calls[0]['via']);
    }

    public function test_backtick_with_untrusted_input(): void
    {
        $calls = $this->scanner->findCalls('<?php $out = `$_GET[cmd]`;', ['shell_exec']);

        $this->assertNotEmpty($calls);
        $this->assertTrue($calls[0]['untrusted']);
    }

    public function test_ignores_method_calls(): void
    {
        $calls = $this->scanner->findCalls('<?php $db->exec("SELECT 1"); $this?->system();', ['exec', 'system']);
        $this->assertEmpty($calls);
    }

    public function test_ignores_static_calls_and_function_definitions(): void
    {
        $source = <<<'PHP'
<?php
class Demo {
    public static function exec($x) {}
    public function system() {}
}
Demo::exec('x');
function passthru() {}
PHP;
        $calls = $this->scanner->findCalls($source, ['exec', 'system', 'passthru']);
        $this->assertEmpty($calls);
    }

    public function test_ignores_namespaced_calls_but_not_global_backslash(): void
    {
        $source = <<<'PHP'
<?php
Foo\exec('x');
\exec('y');
PHP;
        $calls = $this->scanner->findCalls($source, ['exec']);

        $this->assertCount(1, $calls);
        $this->assertSame('exec', $calls[0]['function']);
    }

    public function test_does_not_report_unrequested_functions(): void
    {
        $calls = $this->scanner->findCalls('<?php curl_exec($ch); exec("ls");', ['curl_exec']);

        $this->assertCount(1, $calls);
        $this->assertSame('curl_exec', $calls[0]['function']);
    }
}
