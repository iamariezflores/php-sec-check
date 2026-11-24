<?php

namespace Aquilinoflores\PhpSecCheck\Checks;

use Aquilinoflores\PhpSecCheck\Issue;
use Aquilinoflores\PhpSecCheck\Scan\PhpFiles;

/**
 * Certificate verification turned off in the same statement.
 */
class UnsafeTlsCheck implements CheckInterface
{
    public const RULE_ID = 'PSC-SRC-070';

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

            $statement = [];
            $depth = 0;
            $reported = [];
            $flush = function () use (&$statement, &$issues, &$reported, $relative): void {
                if ($statement !== [] && $this->disablesVerification($statement)) {
                    $line = 1;
                    foreach ($statement as $token) {
                        if (is_array($token)) {
                            $line = $token[2];
                            break;
                        }
                    }
                    $key = $relative . ':' . $line;
                    if (!isset($reported[$key])) {
                        $reported[$key] = true;
                        $issues[] = new Issue(
                            Issue::HIGH,
                            "TLS certificate verification is disabled in {$relative}:{$line}.",
                            'UnsafeTlsCheck',
                            self::RULE_ID,
                            Issue::LIKELY,
                            'Leave CURLOPT_SSL_VERIFYPEER and verify_peer at their defaults so the peer certificate is checked.',
                            $relative,
                            $line,
                        );
                    }
                }
                $statement = [];
            };

            foreach ($tokens as $token) {
                $char = is_array($token) ? null : $token;
                if ($char === '(' || $char === '[') {
                    $depth++;
                } elseif ($char === ')' || $char === ']') {
                    $depth--;
                }
                $statement[] = $token;
                if ($char === ';' && $depth <= 0) {
                    $flush();
                }
            }
            $flush();
        }

        return $issues;
    }

    /**
     * @param list<string|array{0: int, 1: string, 2: int}> $statement
     */
    private function disablesVerification(array $statement): bool
    {
        $names = false;
        $off = false;
        foreach ($statement as $token) {
            if (!is_array($token)) {
                continue;
            }
            $text = strtolower($token[1]);
            if (str_contains($text, 'curlopt_ssl_verifypeer') || str_contains($text, 'verify_peer') || str_contains($text, 'verify_peer_name')) {
                $names = true;
            }
            if ($token[0] === T_STRING && $text === 'false') {
                $off = true;
            }
            if ($token[0] === T_LNUMBER && $token[1] === '0') {
                $off = true;
            }
        }

        return $names && $off;
    }
}
