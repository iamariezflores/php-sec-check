<?php

/**
 * Builds php-sec-check.phar from src/. The scanner has no runtime dependencies,
 * so the archive does not vendor anything.
 *
 *   php -d phar.readonly=0 build/phar.php
 */

$root = dirname(__DIR__);
$out = $root . DIRECTORY_SEPARATOR . 'php-sec-check.phar';

if (file_exists($out)) {
    unlink($out);
}

$phar = new Phar($out, 0, 'php-sec-check.phar');
$phar->startBuffering();

$iterator = new RecursiveIteratorIterator(
    new RecursiveDirectoryIterator($root . '/src', FilesystemIterator::SKIP_DOTS)
);
$phar->buildFromIterator($iterator, $root);
$phar->setStub(<<<'STUB'
#!/usr/bin/env php
<?php
Phar::mapPhar('php-sec-check.phar');
spl_autoload_register(static function (string $class): void {
    $prefix = 'Aquilinoflores\\PhpSecCheck\\';
    if (!str_starts_with($class, $prefix)) {
        return;
    }
    $file = 'phar://php-sec-check.phar/src/' . str_replace('\\', '/', substr($class, strlen($prefix))) . '.php';
    if (is_file($file)) {
        require $file;
    }
});
exit((new Aquilinoflores\PhpSecCheck\Cli\Application())->run($argv));
__HALT_COMPILER();
STUB);

$phar->stopBuffering();

fwrite(STDOUT, "Wrote {$out}\n");
