<?php

namespace Aquilinoflores\PhpSecCheck\Checks;

use Aquilinoflores\PhpSecCheck\Issue;
use Aquilinoflores\PhpSecCheck\Php\ProjectPhpSettings;

class DisplayErrorsCheck implements CheckInterface
{
    public const RULE_ID = 'PSC-RUN-010';
    public const RULE_URL_INCLUDE = 'PSC-RUN-011';
    public const RULE_EXPOSE_PHP = 'PSC-RUN-012';

    public function run(string $projectRoot): array
    {
        if ($projectRoot === '' || !is_dir($projectRoot)) {
            return [];
        }

        $settings = ProjectPhpSettings::load($projectRoot);
        $issues = [];

        foreach ($settings->directives('display_errors') as $directive) {
            if (!$directive->isEnabled()) {
                continue;
            }
            $issues[] = new Issue(
                Issue::WARN,
                "'display_errors' is enabled in {$directive->path}:{$directive->line}. Disable it in the application's PHP configuration.",
                'DisplayErrorsCheck',
                self::RULE_ID,
                Issue::CONFIRMED,
                'Set display_errors=Off in .user.ini or .htaccess, and remove ini_set(\'display_errors\', ...) from entry scripts.',
                $directive->path,
                $directive->line,
            );
        }

        foreach ($settings->directives('allow_url_include') as $directive) {
            if (!$directive->isEnabled()) {
                continue;
            }
            $issues[] = new Issue(
                Issue::CRITICAL,
                "allow_url_include is enabled in {$directive->path}:{$directive->line}. Remote files can be included as PHP.",
                'DisplayErrorsCheck',
                self::RULE_URL_INCLUDE,
                Issue::CONFIRMED,
                'Set allow_url_include=Off. allow_url_fopen is a separate setting and is not reported.',
                $directive->path,
                $directive->line,
            );
        }

        foreach ($settings->directives('expose_php') as $directive) {
            if (!$directive->isEnabled()) {
                continue;
            }
            $issues[] = new Issue(
                Issue::LOW,
                "expose_php is enabled in {$directive->path}:{$directive->line}. Responses advertise the PHP version.",
                'DisplayErrorsCheck',
                self::RULE_EXPOSE_PHP,
                Issue::CONFIRMED,
                'Set expose_php=Off in the application PHP configuration.',
                $directive->path,
                $directive->line,
            );
        }

        return $issues;
    }
}
