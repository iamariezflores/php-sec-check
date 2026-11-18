<?php

namespace Aquilinoflores\PhpSecCheck\Checks;

use Aquilinoflores\PhpSecCheck\Issue;
use Aquilinoflores\PhpSecCheck\Output;

class PhpVersionCheck implements CheckInterface
{
    public function run(string $projectRoot): array
    {
        $issues = [];

        echo "[PHP VERSION]\n";
        $version = phpversion();
        echo "Current PHP version: $version\n";

        if (version_compare($version, '8.0.0', '<')) {
            $issue = new Issue(
                Issue::WARN,
                "PHP version is outdated: $version (recommend >=8.0)",
                'PhpVersionCheck'
            );
            $issues[] = $issue;
            Output::issue($issue);
        } else {
            Output::ok('PHP version is up-to-date.');
        }

        echo "\n";
        return $issues;
    }
}
