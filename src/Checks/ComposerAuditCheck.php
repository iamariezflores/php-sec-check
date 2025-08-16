<?php
namespace Aquilinoflores\PhpSecCheck\Checks;

use Aquilinoflores\PhpSecCheck\Output;

class ComposerAuditCheck implements CheckInterface {
    public function run(string $projectRoot): array {
        $issues = [];

        echo "[COMPOSER DEPENDENCIES]\n";

        $lockFile = $projectRoot . '/composer.lock';
        if (!file_exists($lockFile)) {
            Output::info("No composer.lock found. Skipping dependency audit.");
            echo "\n";
            return $issues;
        }

        $output = [];
        exec('composer audit --format=json 2>/dev/null', $output);
        $data = json_decode(implode("\n", $output), true);

        if (!empty($data['advisories'])) {
            Output::warn("Vulnerable dependencies found:");
            foreach ($data['advisories'] as $package => $advisories) {
                foreach ($advisories as $adv) {
                    $issueMsg = "$package: {$adv['title']} ({$adv['cve']})";
                    $issues[] = $issueMsg;
                    echo "  - $issueMsg\n";
                }
            }
        } else {
            Output::ok("No known vulnerabilities found in dependencies.");
        }

        echo "\n";
        return $issues;
    }
}