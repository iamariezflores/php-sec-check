<?php

namespace Aquilinoflores\PhpSecCheck\Tests\Support;

use Aquilinoflores\PhpSecCheck\Git\GitStatus;

final class FakeGitStatus implements GitStatus
{
    /**
     * @param list<string> $tracked
     * @param list<string> $ignored
     */
    public function __construct(
        private readonly bool $repository = true,
        private readonly array $tracked = [],
        private readonly array $ignored = [],
    ) {}

    public function isRepository(): bool
    {
        return $this->repository;
    }

    public function isTracked(string $relativePath): bool
    {
        return in_array($relativePath, $this->tracked, true);
    }

    public function isIgnoredByRules(string $relativePath): bool
    {
        return in_array($relativePath, $this->ignored, true);
    }
}
