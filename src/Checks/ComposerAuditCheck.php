<?php
namespace Aquilinoflores\PhpSecCheck\Checks;

use Aquilinoflores\PhpSecCheck\Output;

class ComposerAuditCheck implements CheckInterface {
    public function run(): void {
        echo "[COMPOSER DEPENDENCIES]\n";
        if (!file_exists('composer.lock')) {
            Output::info("No composer.lock found. Skipping dependency audit.");
            echo "\n";
            return;
        }

        $output = [];
        exec('composer audit --format=json 2>/dev/null', $output);
        $data = json_decode(implode("\n", $output), true);

        if (!empty($data['advisories'])) {
            Output::warn("Vulnerable dependencies found:");
            foreach ($data['advisories'] as $package => $issues) {
                foreach ($issues as $issue) {
                    echo "  - $package: {$issue['title']} ({$issue['cve']})\n";
                }
            }
        } else {
            Output::ok("No known vulnerabilities found in dependencies.");
        }
        echo "\n";
    }
}