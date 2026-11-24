<?php

namespace Aquilinoflores\PhpSecCheck\Checks;

use Aquilinoflores\PhpSecCheck\Finding;

interface CheckInterface
{
    /**
     * Run the check against the given project root.
     *
     * Checks return findings and do not print or write files.
     *
     * @return Finding[]
     */
    public function run(string $projectRoot): array;
}
