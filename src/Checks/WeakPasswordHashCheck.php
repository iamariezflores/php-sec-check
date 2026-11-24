<?php

namespace Aquilinoflores\PhpSecCheck\Checks;

use Aquilinoflores\PhpSecCheck\Issue;
use Aquilinoflores\PhpSecCheck\Scan\PhpFiles;
use Aquilinoflores\PhpSecCheck\Scan\PhpFunctionCallScanner;

/**
 * md5() or sha1() of a password-like argument in the same call.
 */
class WeakPasswordHashCheck implements CheckInterface
{
    public const RULE_ID = 'PSC-SRC-050';

    public function __construct(private readonly ?PhpFunctionCallScanner $scanner = null) {}

    public function run(string $projectRoot): array
    {
        $scanner = $this->scanner ?? new PhpFunctionCallScanner();
        $issues = [];

        foreach (PhpFiles::iterate($projectRoot) as $absolute => $relative) {
            $source = @file_get_contents($absolute);
            if ($source === false) {
                continue;
            }

            foreach ($scanner->findCallsWithArguments($source, ['md5', 'sha1', 'hash']) as $call) {
                $args = $call['arguments'];
                if ($call['function'] === 'hash') {
                    if ($args === [] || !$this->isWeakAlgo($args[0])) {
                        continue;
                    }
                    $subject = array_slice($args, 1);
                } else {
                    $subject = $args === [] ? [] : [$args[0]];
                }

                if (!$this->looksLikePassword($subject)) {
                    continue;
                }

                $issues[] = new Issue(
                    Issue::HIGH,
                    "{$call['function']}() hashes a password-like value in {$relative}:{$call['line']}.",
                    'WeakPasswordHashCheck',
                    self::RULE_ID,
                    Issue::LIKELY,
                    'Store passwords with password_hash() and check them with password_verify().',
                    $relative,
                    $call['line'],
                );
            }
        }

        return $issues;
    }

    /**
     * @param list<list<string|array{0: int, 1: string, 2: int}>> $tokens
     */
    private function isWeakAlgo(array $tokens): bool
    {
        foreach ($tokens as $token) {
            if (!is_array($token) || $token[0] !== T_CONSTANT_ENCAPSED_STRING) {
                continue;
            }
            $value = strtolower(trim(stripcslashes(substr($token[1], 1, -1))));
            return in_array($value, ['md5', 'sha1'], true);
        }

        return false;
    }

    /**
     * @param list<list<string|array{0: int, 1: string, 2: int}>> $groups
     */
    private function looksLikePassword(array $groups): bool
    {
        foreach ($groups as $tokens) {
            foreach ($tokens as $token) {
                if (!is_array($token)) {
                    continue;
                }
                $text = strtolower($token[1]);
                if (preg_match('/password|passwd|pwd/', $text) === 1) {
                    return true;
                }
            }
        }

        return false;
    }
}
