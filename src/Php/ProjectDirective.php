<?php

namespace Aquilinoflores\PhpSecCheck\Php;

/**
 * One PHP setting written in the target: .user.ini, php.ini, .htaccess, or ini_set().
 */
final class ProjectDirective
{
    public function __construct(
        public readonly string $key,
        public readonly string $value,
        public readonly string $path,
        public readonly int $line,
    ) {}

    public function isEnabled(): bool
    {
        return in_array($this->normalized(), ['1', 'on', 'true', 'yes'], true);
    }

    public function isDisabled(): bool
    {
        return in_array($this->normalized(), ['0', 'off', 'false', 'no', 'none', ''], true);
    }

    private function normalized(): string
    {
        return strtolower(trim($this->value, " \t\"'"));
    }
}
