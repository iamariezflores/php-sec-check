<?php
namespace Aquilinoflores\PhpSecCheck\Checks;

use Aquilinoflores\PhpSecCheck\Output;

class PhpVersionCheck implements CheckInterface {
    public function run(): void {
        echo "[PHP VERSION]\n";
        $current = phpversion();
        $latest = '8.3.10';

        if(version_compare($current, $latest, '<')) {
            Output::warn("Outdated PHP version: $current (Latest: $latest)");
        } else {
            Output::ok("PHP version is up-to-date ($current).");
        }

        echo "\n";
    }
}

