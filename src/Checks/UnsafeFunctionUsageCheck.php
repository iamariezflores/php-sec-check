<?php

namespace Aquilinoflores\PhpSecCheck\Checks;

use Aquilinoflores\PhpSecCheck\Issue;
use Aquilinoflores\PhpSecCheck\Scan\PhpFunctionCallScanner;
use RecursiveDirectoryIterator;
use RecursiveIteratorIterator;
use SplFileInfo;

/**
 * Source-code check: whether potentially unsafe functions are actually used
 * in application PHP, and whether their arguments look like untrusted input.
 *
 * Scanning uses token_get_all() as a first pass. Full taint / AST analysis
 * is a later improvement.
 */
class UnsafeFunctionUsageCheck implements CheckInterface
{
    public const RULE_ID = 'PSC-SRC-001';

    public const RECOMMENDATION = 'Remove the call, or pass only values the application constructed. escapeshellarg() is not a substitute for avoiding a shell when the whole command comes from a request.';
    /**
     * Always-risky: command execution and dynamic code. Reported on any use;
     * CRITICAL when the argument list includes untrusted input.
     *
     * @var list<string>
     */
    public const ALWAYS_RISKY = [
        'exec',
        'shell_exec',
        'system',
        'passthru',
        'proc_open',
        'popen',
        'eval',
        'create_function',
    ];

    /**
     * Legitimate in isolation (e.g. HTTP clients). Only reported when
     * untrusted input reaches the call.
     *
     * @var list<string>
     */
    public const UNTRUSTED_ONLY = [
        'curl_exec',
        'curl_multi_exec',
    ];

    private const SKIP_DIR_FRAGMENTS = [
        '/vendor/',
        '/node_modules/',
        '/.git/',
        '/storage/framework/',
        '/bootstrap/cache/',
    ];

    public function __construct(private readonly ?PhpFunctionCallScanner $scanner = null) {}

    public function run(string $projectRoot): array
    {
        $issues = [];

        if ($projectRoot === '' || !is_dir($projectRoot)) {
            return $issues;
        }

        $scanner = $this->scanner ?? new PhpFunctionCallScanner();
        $wanted  = array_merge(self::ALWAYS_RISKY, self::UNTRUSTED_ONLY);

        foreach ($this->phpFiles($projectRoot) as $absolute => $relative) {
            $source = @file_get_contents($absolute);
            if ($source === false) {
                continue;
            }

            foreach ($scanner->findCalls($source, $wanted) as $call) {
                $untrustedOnly = in_array($call['function'], self::UNTRUSTED_ONLY, true);
                if ($untrustedOnly && !$call['untrusted']) {
                    continue;
                }

                $severity = $call['untrusted'] ? Issue::CRITICAL : Issue::WARN;
                $via      = $call['via'] === 'backtick' ? 'backtick shell execution' : $call['function'] . '()';
                $taint    = $call['untrusted']
                    ? ' receives untrusted input'
                    : ' is used';

                $issues[] = new Issue(
                    $severity,
                    "{$via}{$taint} in {$relative}:{$call['line']}.",
                    'UnsafeFunctionUsageCheck',
                    self::RULE_ID,
                    $call['untrusted'] ? Issue::LIKELY : Issue::HEURISTIC,
                    self::RECOMMENDATION,
                    $relative,
                    $call['line'],
                );
            }
        }

        return $issues;
    }

    /**
     * @return iterable<string, string> absolute path => relative path
     */
    private function phpFiles(string $projectRoot): iterable
    {
        $root = rtrim(str_replace('\\', '/', $projectRoot), '/');
        $iterator = new RecursiveIteratorIterator(
            new RecursiveDirectoryIterator($projectRoot, RecursiveDirectoryIterator::SKIP_DOTS)
        );

        /** @var SplFileInfo $file */
        foreach ($iterator as $file) {
            if (!$file->isFile() || strtolower($file->getExtension()) !== 'php') {
                continue;
            }

            $absolute = $file->getPathname();
            $relative = ltrim(str_replace('\\', '/', substr(str_replace('\\', '/', $absolute), strlen($root))), '/');

            if ($this->shouldSkip($relative)) {
                continue;
            }

            yield $absolute => $relative;
        }
    }

    private function shouldSkip(string $relative): bool
    {
        $haystack = '/' . $relative;
        foreach (self::SKIP_DIR_FRAGMENTS as $fragment) {
            if (str_contains($haystack, $fragment) || str_starts_with($relative, ltrim($fragment, '/'))) {
                return true;
            }
        }

        return false;
    }
}
