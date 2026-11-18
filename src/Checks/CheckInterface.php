<?php

namespace Aquilinoflores\PhpSecCheck\Checks;

use Aquilinoflores\PhpSecCheck\Issue;

interface CheckInterface
{
    /**
     * Run the check against the given project root.
     *
     * @return Issue[]
     */
    public function run(string $projectRoot): array;
}
