<?php

namespace Aquilinoflores\PhpSecCheck\Checks\Laravel;

use Aquilinoflores\PhpSecCheck\Checks\CheckInterface;
use Aquilinoflores\PhpSecCheck\Issue;
use Aquilinoflores\PhpSecCheck\Output;

class VendorCheck implements CheckInterface
{
    public function run(string $projectRoot): array
    {
        $issues    = [];
        $gitignore = $projectRoot . '/.gitignore';
        $vendorDir = $projectRoot . '/vendor';

        echo "[VENDOR CHECK]\n";

        if (file_exists($vendorDir)) {
            $gitignoreContent = file_exists($gitignore) ? file_get_contents($gitignore) : '';

            if (strpos($gitignoreContent, 'vendor/') === false) {
                $issue = new Issue(
                    Issue::WARN,
                    'vendor/ directory exists and is not ignored in .gitignore!',
                    'VendorCheck'
                );
                $issues[] = $issue;
                Output::issue($issue);
            } else {
                Output::ok('vendor/ is correctly excluded in .gitignore.');
            }
        } else {
            Output::ok('No vendor/ directory found (or it is already excluded).');
        }

        echo "\n";
        return $issues;
    }
}
