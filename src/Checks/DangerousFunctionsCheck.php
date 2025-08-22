<?php
namespace Aquilinoflores\PhpSecCheck\Checks;

use Aquilinoflores\PhpSecCheck\Output;

class DangerousFunctionsCheck implements CheckInterface {
    public function run(string $projectRoot): array {
        $issues = [];

        echo "[DANGEROUS FUNCTIONS]\n";
        $dangerous = ['exec', 
                      'shell_exec', 
                      'system', 
                      'passthru', 
                      'eval', 
                      'create_function',
                      'proc_open',
                      'popen',
                      'curl_exec',
                      'curl_multi_exec',
                      'parse_ini_file',
                      'show_source'
                    ];
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