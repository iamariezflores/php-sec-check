<?php

namespace Aquilinoflores\PhpSecCheck;

/**
 * One result from a security rule.
 *
 * Severity is ordered: info < low < medium < high < critical.
 * The historical WARN constant is medium, so a default high threshold
 * does not fail a build on hardening notes.
 *
 * Confidence says how the result was established:
 *   confirmed  — a file or directive was observed in the target
 *   likely     — untrusted input appears in the same expression as the sink
 *   heuristic  — a risky pattern was seen and taint was not shown
 */
class Finding
{
    public const CRITICAL = 'critical';
    public const HIGH     = 'high';
    public const MEDIUM   = 'medium';
    public const LOW      = 'low';
    public const INFO     = 'info';

    /** @deprecated Use MEDIUM. Preserved for existing callers. */
    public const WARN = self::MEDIUM;

    public const CONFIRMED = 'confirmed';
    public const LIKELY     = 'likely';
    public const HEURISTIC  = 'heuristic';

    /** @var array<string, int> */
    private const RANK = [
        self::INFO     => 1,
        self::LOW      => 2,
        self::MEDIUM   => 3,
        self::HIGH     => 4,
        self::CRITICAL => 5,
    ];

    public function __construct(
        public readonly string $severity,
        public readonly string $message,
        public readonly string $check = '',
        public readonly string $ruleId = '',
        public readonly string $confidence = self::HEURISTIC,
        public readonly string $recommendation = '',
        public readonly ?string $path = null,
        public readonly ?int $line = null,
        public readonly string $title = '',
    ) {}

    public static function normalizeSeverity(string $severity): ?string
    {
        $severity = strtolower(trim($severity));
        if ($severity === 'warn' || $severity === 'warning') {
            return self::MEDIUM;
        }

        return array_key_exists($severity, self::RANK) ? $severity : null;
    }

    public static function rank(string $severity): int
    {
        $normalized = self::normalizeSeverity($severity);

        return $normalized === null ? 0 : self::RANK[$normalized];
    }

    public function meets(string $minimum): bool
    {
        return self::rank($this->severity) >= self::rank($minimum);
    }

    /**
     * @return array{
     *     ruleId: string,
     *     severity: string,
     *     confidence: string,
     *     title: string,
     *     message: string,
     *     recommendation: string,
     *     path: ?string,
     *     line: ?int,
     *     check: string
     * }
     */
    public function toArray(): array
    {
        return [
            'ruleId'         => $this->ruleId,
            'severity'       => $this->severity,
            'confidence'     => $this->confidence,
            'title'          => $this->title !== '' ? $this->title : $this->message,
            'message'        => $this->message,
            'recommendation' => $this->recommendation,
            'path'           => $this->path,
            'line'           => $this->line,
            'check'          => $this->check,
        ];
    }

    public function __toString(): string
    {
        return $this->message;
    }
}
