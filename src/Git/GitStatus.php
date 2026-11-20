<?php

namespace Aquilinoflores\PhpSecCheck\Git;

/**
 * Inspects whether paths are tracked or ignored in a Git working tree.
 *
 * Implementations must distinguish "listed in .gitignore" from "actually
 * excluded from Git": a file can be named in .gitignore and still be tracked
 * if it was committed before the ignore rule was added.
 */
interface GitStatus
{
    public function isRepository(): bool;

    /**
     * True when the path is in the Git index (would be committed).
     */
    public function isTracked(string $relativePath): bool;

    /**
     * True when ignore rules would apply to the path, even if it is already
     * tracked. Uses `git check-ignore --no-index` semantics.
     */
    public function isIgnoredByRules(string $relativePath): bool;

    /**
     * Paths currently in the index, relative to the work tree, with forward slashes.
     *
     * @return list<string>
     */
    public function trackedFiles(): array;
}
