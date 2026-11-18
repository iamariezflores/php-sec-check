<?php

namespace Aquilinoflores\PhpSecCheck\Tests\Git;

use Aquilinoflores\PhpSecCheck\Git\GitWorkingTree;
use PHPUnit\Framework\TestCase;

class GitWorkingTreeTest extends TestCase
{
    public function test_plain_directory_is_not_a_repository(): void
    {
        $dir = sys_get_temp_dir() . '/php-sec-check-git-test-' . uniqid();
        mkdir($dir);

        try {
            $git = new GitWorkingTree($dir);
            $this->assertFalse($git->isRepository());
            $this->assertFalse($git->isTracked('.env'));
        } finally {
            rmdir($dir);
        }
    }
}
