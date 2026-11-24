<?php

namespace Aquilinoflores\PhpSecCheck\Checks;

use Aquilinoflores\PhpSecCheck\Issue;
use Aquilinoflores\PhpSecCheck\Scan\PhpFiles;

/**
 * include/require of a request superglobal in the same expression.
 */
class IncludeRequestCheck implements CheckInterface
{
    public const RULE_ID = 'PSC-SRC-080';

    /** @var list<string> */
    private const UNTRUSTED = ['$_GET', '$_POST', '$_REQUEST', '$_COOKIE'];

    public function run(string $projectRoot): array
    {
        $issues = [];
        foreach (PhpFiles::iterate($projectRoot) as $absolute => $relative) {
            $source = @file_get_contents($absolute);
            if ($source === false) {
                continue;
            }
            $tokens = @token_get_all($source);
            if (!is_array($tokens)) {
                continue;
            }

            $count = count($tokens);
            for ($i = 0; $i < $count; $i++) {
                $token = $tokens[$i];
                if (!is_array($token) || !in_array($token[0], [T_INCLUDE, T_INCLUDE_ONCE, T_REQUIRE, T_REQUIRE_ONCE], true)) {
                    continue;
                }

                $chunk = [];
                $depth = 0;
                for ($j = $i + 1; $j < $count; $j++) {
                    $next = $tokens[$j];
                    $char = is_array($next) ? null : $next;
                    if ($char === '(') {
                        $depth++;
                    } elseif ($char === ')') {
                        $depth--;
                    }
                    if ($char === ';' && $depth <= 0) {
                        break;
                    }
                    $chunk[] = $next;
                }

                foreach ($chunk as $part) {
                    if (!is_array($part) || $part[0] !== T_VARIABLE) {
                        continue;
                    }
                    if (!in_array($part[1], self::UNTRUSTED, true)) {
                        continue;
                    }
                    $name = strtolower(trim($token[1]));
                    $issues[] = new Issue(
                        Issue::CRITICAL,
                        "{$name} uses {$part[1]} in {$relative}:{$token[2]}. The request chooses which file PHP loads.",
                        'IncludeRequestCheck',
                        self::RULE_ID,
                        Issue::LIKELY,
                        'Include a fixed file. If a page name has to vary, map it through an allow-list the application owns.',
                        $relative,
                        $token[2],
                    );
                    break;
                }
            }
        }

        return $issues;
    }
}
