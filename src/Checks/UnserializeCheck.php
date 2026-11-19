<?php

namespace Aquilinoflores\PhpSecCheck\Checks;

use Aquilinoflores\PhpSecCheck\Issue;
use Aquilinoflores\PhpSecCheck\Output;
use Aquilinoflores\PhpSecCheck\Scan\PhpFunctionCallScanner;
use RecursiveDirectoryIterator;
use RecursiveIteratorIterator;
use SplFileInfo;

/**
 * Source check: unserialize() / maybe_unserialize() object-injection risk.
 *
 * Any use is WARN. Untrusted input in the argument list is CRITICAL.
 * allowed_classes restrictions can lower a local-cache hit but never hide
 * untrusted input. json_decode() is not a finding.
 */
class UnserializeCheck implements CheckInterface
{
    /** @var list<string> */
    public const FUNCTIONS = ['unserialize', 'maybe_unserialize'];

    private const SKIP_DIR_FRAGMENTS = [
        '/vendor/',
        '/node_modules/',
        '/.git/',
        '/storage/framework/',
        '/bootstrap/cache/',
    ];

    /** @var list<string> */
    private const UNTRUSTED = [
        '$_GET', '$_POST', '$_REQUEST', '$_COOKIE', '$_FILES', '$_SERVER', '$argv',
    ];

    public function __construct(private readonly ?PhpFunctionCallScanner $scanner = null) {}

    public function run(string $projectRoot): array
    {
        $issues = [];

        echo "[UNSERIALIZE]\n";

        if ($projectRoot === '' || !is_dir($projectRoot)) {
            Output::info('No project root to scan for unserialize() usage.');
            echo "\n";
            return $issues;
        }

        $scanner = $this->scanner ?? new PhpFunctionCallScanner();

        foreach ($this->phpFiles($projectRoot) as $absolute => $relative) {
            $source = @file_get_contents($absolute);
            if ($source === false) {
                continue;
            }

            foreach ($scanner->findCallsWithArguments($source, self::FUNCTIONS) as $call) {
                $flat = [];
                foreach ($call['arguments'] as $group) {
                    foreach ($group as $token) {
                        $flat[] = $token;
                    }
                }

                $untrusted  = $this->tokensHaveUntrusted($flat);
                $restricted = isset($call['arguments'][1]) && $this->restrictsClasses($call['arguments'][1]);
                $fn         = $call['function'] . '()';

                if ($untrusted) {
                    $this->add(
                        $issues,
                        Issue::CRITICAL,
                        "{$fn} receives untrusted input in {$relative}:{$call['line']}."
                    );
                    continue;
                }

                $suffix = $restricted
                    ? ' allowed_classes is restricted, so this is WARN at most.'
                    : '';

                $this->add(
                    $issues,
                    Issue::WARN,
                    "{$fn} is used in {$relative}:{$call['line']}.{$suffix}"
                );
            }
        }

        if ($issues === []) {
            Output::ok('No unserialize() usage detected in application source.');
        }

        echo "\n";
        return $issues;
    }

    /**
     * @param list<string|array{0: int, 1: string, 2: int}> $tokens
     */
    private function tokensHaveUntrusted(array $tokens): bool
    {
        foreach ($tokens as $token) {
            if (!is_array($token)) {
                continue;
            }

            if ($token[0] === T_VARIABLE && in_array($token[1], self::UNTRUSTED, true)) {
                return true;
            }

            if (
                in_array($token[0], [T_CONSTANT_ENCAPSED_STRING, T_ENCAPSED_AND_WHITESPACE], true)
                && stripos($token[1], 'php://input') !== false
            ) {
                return true;
            }
        }

        return false;
    }

    /**
     * @param list<string|array{0: int, 1: string, 2: int}> $tokens
     */
    private function restrictsClasses(array $tokens): bool
    {
        $text = '';
        foreach ($tokens as $token) {
            $text .= is_array($token) ? $token[1] : $token;
        }

        if (preg_match('/allowed_classes\s*=>\s*(false|0)/i', $text)) {
            return true;
        }

        return (bool) preg_match('/allowed_classes\s*=>\s*\[/', $text);
    }

    /**
     * @return iterable<string, string>
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

    /**
     * @param list<Issue> $issues
     */
    private function add(array &$issues, string $severity, string $message): void
    {
        $issue = new Issue($severity, $message, 'UnserializeCheck');
        $issues[] = $issue;
        Output::issue($issue);
    }
}
