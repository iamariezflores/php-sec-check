<?php

namespace Aquilinoflores\PhpSecCheck\Checks;

use Aquilinoflores\PhpSecCheck\Issue;
use Aquilinoflores\PhpSecCheck\Output;

class DisplayErrorsCheck implements CheckInterface
{
    public function run(string $projectRoot): array
    {
        $issues = [];

        echo "[DISPLAY ERRORS]\n";

        if (filter_var(ini_get('display_errors'), FILTER_VALIDATE_BOOLEAN)) {
            $issue = new Issue(
                Issue::WARN,
                "'display_errors' is enabled. Disable in production.",
                'DisplayErrorsCheck'
            );
            $issues[] = $issue;
            Output::issue($issue);
        } else {
            Output::ok("'display_errors' is disabled.");
        }

        echo "\n";
        return $issues;
    }
}
