<?php

namespace Aquilinoflores\PhpSecCheck\Checks;

use Aquilinoflores\PhpSecCheck\Issue;
use Aquilinoflores\PhpSecCheck\Php\ProjectPhpSettings;

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
    public const RULE_ID = 'PSC-RUN-020';

    public const RECOMMENDATION = 'If the application does not need a shell, list the function in disable_functions in the project .user.ini or .htaccess. This check only reports a list the project itself writes.';

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
        $path = null;
        $line = null;

        if ($this->disabledFunctions !== null) {
            $disabled = $this->parseDisabledList($this->disabledFunctions);
        } else {
            if ($projectRoot === '' || !is_dir($projectRoot)) {
                return [];
            }
            $directives = ProjectPhpSettings::load($projectRoot)->directives('disable_functions');
            if ($directives === []) {
                return [];
            }
            $directive = $directives[array_key_last($directives)];
            $disabled = $this->parseDisabledList($directive->value);
            $path = $directive->path;
            $line = $directive->line;
        }

        $issues = [];
        foreach (self::DISABLE_CANDIDATES as $fn) {
            if (in_array($fn, $disabled, true)) {
                continue;
            }

            $where = $path === null ? '' : " in {$path}:{$line}";
            $issues[] = new Issue(
                Issue::WARN,
                "Shell-execution function '{$fn}' is not listed in disable_functions{$where}.",
                'DangerousFunctionsCheck',
                self::RULE_ID,
                $path === null ? Issue::HEURISTIC : Issue::CONFIRMED,
                self::RECOMMENDATION,
                $path,
                $line,
            );
        }

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
