<?php

namespace Aquilinoflores\PhpSecCheck\Checks;

use Aquilinoflores\PhpSecCheck\Issue;
use Aquilinoflores\PhpSecCheck\Output;

/**
 * Configuration check: whether shell-execution functions that *can* be
 * disabled via php.ini `disable_functions` are actually listed there.
 *
 * Language constructs such as eval() cannot be disabled this way.
 * Legitimate HTTP helpers such as curl_exec() are not part of this list.
 */
class DangerousFunctionsCheck implements CheckInterface
{
    /**
     * Functions that should typically be listed in disable_functions
     * for hardened / production environments.
     *
     * @var list<string>
     */
    public const DISABLE_CANDIDATES = [
        'exec',
        'shell_exec',
        'system',
        'passthru',
        'proc_open',
        'popen',
    ];

    public function __construct(private readonly ?string $disabledFunctions = null) {}

    public function run(string $projectRoot): array
    {
        $issues   = [];
        $disabled = $this->parseDisabledList($this->disabledFunctions ?? (string) ini_get('disable_functions'));

        echo "[DANGEROUS FUNCTIONS]\n";

        foreach (self::DISABLE_CANDIDATES as $fn) {
            if (in_array($fn, $disabled, true)) {
                continue;
            }

            $issue = new Issue(
                Issue::WARN,
                "Shell-execution function '{$fn}' is not listed in disable_functions. Disable it in production php.ini.",
                'DangerousFunctionsCheck'
            );
            $issues[] = $issue;
            Output::issue($issue);
        }

        if (empty($issues)) {
            Output::ok('Shell-execution functions are listed in disable_functions.');
        }

        echo "\n";
        return $issues;
    }

    /**
     * Split disable_functions on commas and match whole names only, so that
     * "curl_exec" is not treated as evidence that "exec" is disabled.
     *
     * @return list<string>
     */
    private function parseDisabledList(string $raw): array
    {
        $names = [];
        foreach (explode(',', $raw) as $name) {
            $name = strtolower(trim($name));
            if ($name !== '') {
                $names[] = $name;
            }
        }

        return $names;
    }
}
