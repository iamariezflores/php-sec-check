<?php
namespace Aquilinoflores\PhpSecCheck\Checks;

interface CheckInterface {
    public function run(string $projectRoot): array;
}