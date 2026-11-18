<?php

namespace Aquilinoflores\PhpSecCheck\Php;

use DateTimeImmutable;
use DateTimeInterface;

/**
 * PHP branch security-support calendar.
 *
 * Dates follow https://www.php.net/supported-versions.php
 * and are the last day the branch receives security fixes.
 * Unknown newer minors are treated as supported; unknown older
 * minors are treated as end-of-life.
 */
class PhpSupportCalendar
{
    public const DEFAULT_SECURITY_EOL = [
        '8.1' => '2025-12-31',
        '8.2' => '2026-12-31',
        '8.3' => '2027-12-31',
        '8.4' => '2028-12-31',
        '8.5' => '2029-12-31',
    ];

    /**
     * @param array<string, string> $securityEolByMinor
     */
    public function __construct(private readonly array $securityEolByMinor = self::DEFAULT_SECURITY_EOL) {}

    public function minorBranch(string $version): string
    {
        if (preg_match('/^(\d+)\.(\d+)/', $version, $m)) {
            return $m[1] . '.' . $m[2];
        }

        return $version;
    }

    public function securityEol(string $version): ?string
    {
        return $this->securityEolByMinor[$this->minorBranch($version)] ?? null;
    }

    public function isReceivingSecuritySupport(string $version, DateTimeInterface $today): bool
    {
        $status = $this->supportStatus($version, $today);

        return $status === 'supported' || $status === 'ending';
    }

    /**
     * @return 'supported'|'ending'|'eol'
     */
    public function supportStatus(string $version, DateTimeInterface $today): string
    {
        $minor = $this->minorBranch($version);
        $eol   = $this->securityEol($minor);

        if ($eol === null) {
            return $this->inferUnknownMinor($minor);
        }

        $end = new DateTimeImmutable($eol);
        if ($today > $end) {
            return 'eol';
        }

        $daysLeft = (int) $today->diff($end)->format('%a');
        if ($daysLeft <= 90) {
            return 'ending';
        }

        return 'supported';
    }

    private function inferUnknownMinor(string $minor): string
    {
        $known = array_keys($this->securityEolByMinor);
        if ($known === []) {
            return 'supported';
        }

        $oldest = $known[0];
        foreach ($known as $branch) {
            if (version_compare($branch, $oldest, '<')) {
                $oldest = $branch;
            }
        }

        return version_compare($minor, $oldest, '<') ? 'eol' : 'supported';
    }
}
