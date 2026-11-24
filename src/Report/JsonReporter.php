<?php

namespace Aquilinoflores\PhpSecCheck\Report;

use Aquilinoflores\PhpSecCheck\Finding;

class JsonReporter
{
    /**
     * @param list<Finding> $findings Findings at or above the threshold.
     */
    public function render(array $findings, int $hidden, string $threshold): string
    {
        $counts = [
            Finding::CRITICAL => 0,
            Finding::HIGH     => 0,
            Finding::MEDIUM   => 0,
            Finding::LOW      => 0,
            Finding::INFO     => 0,
        ];

        foreach ($findings as $finding) {
            if (isset($counts[$finding->severity])) {
                $counts[$finding->severity]++;
            }
        }

        $payload = [
            'summary' => [
                'total'     => count($findings),
                'critical'  => $counts[Finding::CRITICAL],
                'high'      => $counts[Finding::HIGH],
                'medium'    => $counts[Finding::MEDIUM],
                'low'       => $counts[Finding::LOW],
                'info'      => $counts[Finding::INFO],
                'hidden'    => $hidden,
                'threshold' => $threshold,
            ],
            'findings' => array_map(fn(Finding $finding) => $finding->toArray(), $findings),
        ];

        return json_encode($payload, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES) . "\n";
    }
}
