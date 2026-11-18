<?php

namespace Aquilinoflores\PhpSecCheck;

class Output
{
    public static function ok(string $msg): void
    {
        echo "\033[32m[OK]\033[0m $msg\n";
    }

    public static function critical(string $msg): void
    {
        echo "\033[41m\033[97m[CRITICAL]\033[0m $msg\n";
    }

    public static function warn(string $msg): void
    {
        echo "\033[31m[WARN]\033[0m $msg\n";
    }

    public static function info(string $msg): void
    {
        echo "\033[33m[INFO]\033[0m $msg\n";
    }

    public static function issue(Issue $issue): void
    {
        match ($issue->severity) {
            Issue::CRITICAL => static::critical($issue->message),
            Issue::INFO     => static::info($issue->message),
            default         => static::warn($issue->message),
        };
    }
}
