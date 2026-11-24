<?php

namespace Aquilinoflores\PhpSecCheck\Scan;

/**
 * Profile and exclude patterns for the scan that is currently running.
 * Direct check calls, outside the CLI, see the legacy profile.
 */
final class ScanContext
{
    private static string $profile = 'legacy';

    public static function set(string $profile): void
    {
        self::$profile = $profile;
    }

    public static function reset(): void
    {
        self::$profile = 'legacy';
    }

    public static function profile(): string
    {
        return self::$profile;
    }

    public static function strictServer(): bool
    {
        return in_array(self::$profile, ['production', 'host'], true);
    }
}
