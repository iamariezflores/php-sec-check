<?php

namespace Aquilinoflores\PhpSecCheck\Checks;

use Aquilinoflores\PhpSecCheck\Issue;
use Aquilinoflores\PhpSecCheck\Output;

class DangerousFunctionsCheck implements CheckInterface
{
    public const DANGEROUS_FUNCTIONS = [
        'exec', 'shell_exec', 'system', 'passthru', 'eval',
        'create_function', 'proc_open', 'popen', 'curl_exec',
        'curl_multi_exec', 'parse_ini_file', 'show_source',
    ];

    public function __construct(private readonly ?string $disabledFunctions = null) {}

    public function run(string $projectRoot): array
    {
        $issues = [];

        echo "[DANGEROUS FUNCTIONS]\n";

        $disabled = $this->disabledFunctions ?? ini_get('disable_functions');

        foreach (self::DANGEROUS_FUNCTIONS as $fn) {
            if (stripos($disabled, $fn) === false) {
                $issue = new Issue(
                    Issue::WARN,
                    "Dangerous function enabled: $fn",
                    'DangerousFunctionsCheck'
                );
                $issues[] = $issue;
                Output::issue($issue);
            }
        }

        if ($disabled) {
            Output::ok("Some dangerous functions are disabled: $disabled");
        }

        echo "\n";
        return $issues;
    }
}
