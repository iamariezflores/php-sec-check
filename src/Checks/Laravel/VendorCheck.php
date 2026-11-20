<?php

namespace Aquilinoflores\PhpSecCheck\Checks\Laravel;

use Aquilinoflores\PhpSecCheck\Checks\CheckInterface;
use Aquilinoflores\PhpSecCheck\Git\GitWorkingTree;
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
            if (!$this->vendorIsIgnored($projectRoot, $gitignore)) {
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

    private function vendorIsIgnored(string $projectRoot, string $gitignore): bool
    {
        $git = new GitWorkingTree($projectRoot);
        if ($git->isRepository()) {
            return $git->isIgnoredByRules('vendor/autoload.php')
                || $git->isIgnoredByRules('vendor');
        }

        if (!is_file($gitignore)) {
            return false;
        }

        return $this->gitignoreExcludesVendor((string) file_get_contents($gitignore));
    }

    /**
     * Used when the project is not a git repository. A real repository uses
     * git check-ignore so comments and unrelated names are not matches.
     */
    private function gitignoreExcludesVendor(string $contents): bool
    {
        foreach (preg_split('/\r\n|\n|\r/', $contents) ?: [] as $line) {
            $line = trim($line);
            if ($line === '' || str_starts_with($line, '#')) {
                continue;
            }

            $line = trim((string) preg_replace('/\s+#.*$/', '', $line));
            if (in_array($line, ['vendor', '/vendor', 'vendor/', '/vendor/'], true)) {
                return true;
            }
        }

        return false;
    }
}
