<?php
namespace Aquilinoflores\PhpSecCheck\Checks\Laravel;

use Aquilinoflores\PhpSecCheck\Checks\CheckInterface;

class VendorCheck implements CheckInterface
{
    public function run(string $projectRoot): array
    {
        $results = [];
        $gitignore = $projectRoot . '/.gitignore';
        $vendorDir = $projectRoot . '/vendor';

        // Warn if vendor exists and is not in .gitignore
        if (file_exists($vendorDir)) {
            $gitignoreContent = file_exists($gitignore) ? file_get_contents($gitignore) : '';

            if (strpos($gitignoreContent, 'vendor/') === false) {
                $results[] = "vendor/ directory exists and is not ignored in .gitignore!";
            }
        }

        return $results;
    }
}
