<?php

namespace Aquilinoflores\PhpSecCheck\Scan;

use Aquilinoflores\PhpSecCheck\Checks\CheckInterface;
use Aquilinoflores\PhpSecCheck\Checks\ComposerAuditCheck;
use Aquilinoflores\PhpSecCheck\Checks\CookieFlagsCheck;
use Aquilinoflores\PhpSecCheck\Checks\DangerousFunctionsCheck;
use Aquilinoflores\PhpSecCheck\Checks\DirectoryExposureCheck;
use Aquilinoflores\PhpSecCheck\Checks\DisplayErrorsCheck;
use Aquilinoflores\PhpSecCheck\Checks\FilePermissionCheck;
use Aquilinoflores\PhpSecCheck\Checks\FileUploadCheck;
use Aquilinoflores\PhpSecCheck\Checks\HtaccessCheck;
use Aquilinoflores\PhpSecCheck\Checks\IncludeRequestCheck;
use Aquilinoflores\PhpSecCheck\Checks\InsecureRandomCheck;
use Aquilinoflores\PhpSecCheck\Checks\Laravel\AppDebugCheck;
use Aquilinoflores\PhpSecCheck\Checks\Laravel\DefaultCredentialsCheck;
use Aquilinoflores\PhpSecCheck\Checks\Laravel\EnvCredentialsCheck;
use Aquilinoflores\PhpSecCheck\Checks\Laravel\VendorCheck;
use Aquilinoflores\PhpSecCheck\Checks\PhpVersionCheck;
use Aquilinoflores\PhpSecCheck\Checks\SessionSecurityCheck;
use Aquilinoflores\PhpSecCheck\Checks\SqlInjectionCheck;
use Aquilinoflores\PhpSecCheck\Checks\UnserializeCheck;
use Aquilinoflores\PhpSecCheck\Checks\UnsafeFunctionUsageCheck;
use Aquilinoflores\PhpSecCheck\Checks\UnsafeTlsCheck;
use Aquilinoflores\PhpSecCheck\Checks\WeakPasswordHashCheck;
use Aquilinoflores\PhpSecCheck\Checks\XssOutputCheck;
use Aquilinoflores\PhpSecCheck\Config\ScanOptions;
use Aquilinoflores\PhpSecCheck\Finding;

/**
 * Runs the built-in checks against a directory.
 *
 * The target does not need composer.json, vendor, or a framework.
 */
class ProjectScanner
{
    /**
     * @return list<Finding>
     */
    public function scan(string $projectRoot, ?ScanOptions $options = null): array
    {
        $options ??= ScanOptions::fromProject($projectRoot);
        ScanContext::set($options->profile);

        try {
            $findings = [];
            foreach ($this->checks($options->profile) as $check) {
                foreach ($check->run($projectRoot) as $finding) {
                    if (!$options->hides($finding)) {
                        $findings[] = $finding;
                    }
                }
            }

            return $findings;
        } finally {
            ScanContext::reset();
        }
    }

    /**
     * @return list<CheckInterface>
     */
    private function checks(string $profile): array
    {
        $framework = $profile === 'laravel';
        $checks = [
            new PhpVersionCheck(),
            new DisplayErrorsCheck(),
            new DangerousFunctionsCheck(),
            new UnsafeFunctionUsageCheck(),
            new DirectoryExposureCheck(),
            new EnvCredentialsCheck(),
            new SessionSecurityCheck(null, $framework),
            new CookieFlagsCheck(null, null, $framework),
            new FileUploadCheck(),
            new XssOutputCheck(),
            new SqlInjectionCheck(),
            new UnserializeCheck(),
            new IncludeRequestCheck(),
            new WeakPasswordHashCheck(),
            new InsecureRandomCheck(),
            new UnsafeTlsCheck(),
            new HtaccessCheck(),
        ];

        if ($profile === 'dependencies') {
            $checks[] = new ComposerAuditCheck();
        }

        if ($profile === 'host') {
            $checks[] = new FilePermissionCheck();
        }

        if ($framework) {
            $checks[] = new AppDebugCheck();
            $checks[] = new DefaultCredentialsCheck();
            $checks[] = new VendorCheck();
        }

        return $checks;
    }
}
