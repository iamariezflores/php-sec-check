<?php
namespace Aquilinoflores\PhpSecCheck\Checks;

use Aquilinoflores\PhpSecCheck\Output;

class DangerousFunctionsCheck implements CheckInterface {

    public const DANGEROUS_FUNCTIONS = [
        'exec', 'shell_exec', 'system', 'passthru', 'eval',
        'create_function', 'proc_open', 'popen', 'curl_exec',
        'curl_multi_exec', 'parse_ini_file', 'show_source',
    ];

    /**
     * @param string|null $disabledFunctions Comma-separated list of disabled
     *   functions. Defaults to the runtime php.ini value. Accepts an explicit
     *   value to allow testing without relying on PHP_INI_SYSTEM settings.
     */
    public function __construct(private readonly ?string $disabledFunctions = null) {}

    public function run(string $projectRoot): array {
        $issues = [];

        echo "[DANGEROUS FUNCTIONS]\n";

        $disabled = $this->disabledFunctions ?? ini_get('disable_functions');

        foreach (self::DANGEROUS_FUNCTIONS as $fn) {
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