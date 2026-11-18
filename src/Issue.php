<?php

namespace Aquilinoflores\PhpSecCheck;

/**
 * Represents a single finding from a security check.
 *
 * Severity levels:
 *   CRITICAL — active security risk; must be fixed before production.
 *   WARN     — potential risk or bad practice that should be addressed.
 *   INFO     — informational notice; not necessarily a risk.
 */
class Issue
{
    public const CRITICAL = 'CRITICAL';
    public const WARN     = 'WARN';
    public const INFO     = 'INFO';

    public function __construct(
        public readonly string $severity,
        public readonly string $message,
        public readonly string $check = '',
    ) {}

    public function toArray(): array
    {
        return [
            'severity' => $this->severity,
            'message'  => $this->message,
            'check'    => $this->check,
        ];
    }

    public function __toString(): string
    {
        return $this->message;
    }
}
