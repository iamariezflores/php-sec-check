<?php

namespace Aquilinoflores\PhpSecCheck\Tests\Php;

use Aquilinoflores\PhpSecCheck\Php\PhpSupportCalendar;
use DateTimeImmutable;
use PHPUnit\Framework\TestCase;

class PhpSupportCalendarTest extends TestCase
{
    private PhpSupportCalendar $calendar;

    protected function setUp(): void
    {
        $this->calendar = new PhpSupportCalendar();
    }

    public function test_minor_branch_strips_patch(): void
    {
        $this->assertSame('8.3', $this->calendar->minorBranch('8.3.36'));
        $this->assertSame('8.2', $this->calendar->minorBranch('8.2'));
    }

    public function test_eol_branch_is_past_security_support(): void
    {
        $today = new DateTimeImmutable('2026-11-18');

        $this->assertSame('eol', $this->calendar->supportStatus('8.1.32', $today));
        $this->assertFalse($this->calendar->isReceivingSecuritySupport('8.1.32', $today));
        $this->assertSame('2025-12-31', $this->calendar->securityEol('8.1.32'));
    }

    public function test_branch_within_90_days_of_eol_is_ending(): void
    {
        $today = new DateTimeImmutable('2026-11-18');

        $this->assertSame('ending', $this->calendar->supportStatus('8.2.29', $today));
        $this->assertTrue($this->calendar->isReceivingSecuritySupport('8.2.29', $today));
    }

    public function test_supported_branch(): void
    {
        $today = new DateTimeImmutable('2026-11-18');

        $this->assertSame('supported', $this->calendar->supportStatus('8.3.0', $today));
        $this->assertTrue($this->calendar->isReceivingSecuritySupport('8.3.0', $today));
    }

    public function test_unknown_older_minor_is_eol(): void
    {
        $today = new DateTimeImmutable('2026-11-18');

        $this->assertSame('eol', $this->calendar->supportStatus('8.0.30', $today));
        $this->assertSame('eol', $this->calendar->supportStatus('7.4.33', $today));
    }

    public function test_unknown_newer_minor_is_treated_as_supported(): void
    {
        $today = new DateTimeImmutable('2026-11-18');

        $this->assertSame('supported', $this->calendar->supportStatus('8.6.0', $today));
    }

    public function test_day_after_eol_is_eol(): void
    {
        $this->assertSame('eol', $this->calendar->supportStatus('8.2.0', new DateTimeImmutable('2027-01-01')));
    }

    public function test_eol_day_is_still_supported_as_ending(): void
    {
        $this->assertSame('ending', $this->calendar->supportStatus('8.2.0', new DateTimeImmutable('2026-12-31')));
    }
}
