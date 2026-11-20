<?php

namespace Aquilinoflores\PhpSecCheck\Git;

class GitWorkingTree implements GitStatus
{
    public function __construct(private readonly string $projectRoot) {}

    public function isRepository(): bool
    {
        [$exit, $output] = $this->git(['rev-parse', '--is-inside-work-tree']);

        return $exit === 0 && strtolower($output) === 'true';
    }

    public function isTracked(string $relativePath): bool
    {
        [$exit] = $this->git(['ls-files', '--error-unmatch', '--', $relativePath]);

        return $exit === 0;
    }

    public function isIgnoredByRules(string $relativePath): bool
    {
        [$exit] = $this->git(['check-ignore', '--no-index', '-q', '--', $relativePath]);

        return $exit === 0;
    }

    public function trackedFiles(): array
    {
        [$exit, $output] = $this->git(['ls-files', '--']);
        if ($exit !== 0 || $output === '') {
            return [];
        }

        $paths = [];
        foreach (explode("\n", $output) as $path) {
            $path = str_replace('\\', '/', trim($path));
            if ($path !== '') {
                $paths[] = $path;
            }
        }

        return $paths;
    }

    /**
     * @param list<string> $args
     * @return array{0: int, 1: string}
     */
    private function git(array $args): array
    {
        $cmd = array_merge(['git', '-C', $this->projectRoot], $args);

        $proc = @proc_open(
            $cmd,
            [
                0 => ['pipe', 'r'],
                1 => ['pipe', 'w'],
                2 => ['pipe', 'w'],
            ],
            $pipes
        );

        if (!is_resource($proc)) {
            return [127, ''];
        }

        fclose($pipes[0]);
        $stdout = stream_get_contents($pipes[1]) ?: '';
        fclose($pipes[1]);
        fclose($pipes[2]);

        return [proc_close($proc), trim($stdout)];
    }
}
