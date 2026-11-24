<?php

namespace Aquilinoflores\PhpSecCheck\Report;

use Aquilinoflores\PhpSecCheck\Finding;

class TextReporter
{
    /**
     * @param list<Finding> $findings
     */
    public function render(string $projectRoot, array $findings, int $hidden, string $threshold): string
    {
        $lines = [];
        $lines[] = 'php-sec-check';
        $lines[] = 'Scanned: ' . $projectRoot;
        $lines[] = 'Threshold: ' . $threshold;
        $lines[] = '';

        if ($findings === []) {
            $lines[] = 'No findings at or above ' . $threshold . '.';
        } else {
            foreach ($findings as $finding) {
                $lines[] = $this->format($finding);
                $lines[] = '';
            }
        }

        $lines[] = sprintf(
            '%d shown, %d hidden below %s.',
            count($findings),
            $hidden,
            $threshold
        );

        return implode("\n", $lines) . "\n";
    }

    private function format(Finding $finding): string
    {
        $label = strtoupper($finding->severity);
        $where = '';
        if ($finding->path !== null && $finding->path !== '') {
            $where = $finding->path;
            if ($finding->line !== null) {
                $where .= ':' . $finding->line;
            }
            $where = ' (' . $where . ')';
        }

        $head = sprintf(
            '%s[%s]%s %s %s%s',
            $this->color($finding->severity),
            $label,
            "\033[0m",
            $finding->ruleId !== '' ? $finding->ruleId : $finding->check,
            $finding->confidence,
            $where
        );

        $body = [$head, $finding->message];
        if ($finding->recommendation !== '') {
            $body[] = 'Fix: ' . $finding->recommendation;
        }

        return implode("\n", $body);
    }

    private function color(string $severity): string
    {
        return match ($severity) {
            Finding::CRITICAL => "\033[41m\033[97m",
            Finding::HIGH     => "\033[31m",
            Finding::INFO, Finding::LOW => "\033[33m",
            default           => "\033[31m",
        };
    }
}
