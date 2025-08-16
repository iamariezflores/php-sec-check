<?php
namespace Aquilinoflores\PhpSecCheck\Checks;

use Aquilinoflores\PhpSecCheck\Output;

class PhpVersionCheck implements CheckInterface {
    public function run(string $projectRoot): array {
        $issues = [];

        echo "[PHP VERSION]\n";
        $version = phpversion();
        echo "Current PHP version: $version\n";

        if (version_compare($version, '8.0.0', '<')) {
            $issues[] = "PHP version is outdated: $version (recommend >=8.0)";
            Output::warn(end($issues));
        } else {
            Output::ok("PHP version is up-to-date.");
        }

        echo "\n";
        return $issues;
    }
}