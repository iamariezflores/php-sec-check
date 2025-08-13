<?php
namespace Aquilinoflores\PhpSecCheck\Checks;

use Aquilinoflores\PhpSecCheck\Output;

class DisplayErrorsCheck implements CheckInterface {
    public function run(): void {
        echo "[DISPLAY ERRORS]\n";
        $displayErrors = ini_get('display_errors');
        if (filter_var($displayErrors, FILTER_VALIDATE_BOOLEAN)) {
            Output::warn("'display_errors' is enabled. Disable in production.");
        } else {
            Output::ok("'display_errors' is disabled.");
        }
        echo "\n";
    }
}