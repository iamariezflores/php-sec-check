<?php
namespace Aquilinoflores\PhpSecCheck\Checks;

use Aquilinoflores\PhpSecCheck\Output;

class DangerousFunctionsCheck implements CheckInterface {
    public function run(string $projectRoot): array {
        $issues = [];

        echo "[DANGEROUS FUNCTIONS]\n";
        $dangerous = ['exec', 'shell_exec', 'system', 'passthru', 'eval', 'create_function'];
        $disabled = ini_get('disable_functions');

        foreach ($dangerous as $fn) {
            if (stripos($disabled, $fn) === false) {
                $issues[] = "Dangerous function enabled: $fn";
                Output::warn("Dangerous function enabled: $fn");
            }
        }

        if ($disabled) {
            Output::ok("Some dangerous functions are disabled: $disabled");
        }

        echo "\n";
        return $issues;
    }
}