<?php

namespace Aquilinoflores\PhpSecCheck\Tests\Checks;

use Aquilinoflores\PhpSecCheck\Checks\FileUploadCheck;
use Aquilinoflores\PhpSecCheck\Issue;
use PHPUnit\Framework\TestCase;

class FileUploadCheckTest extends TestCase
{
    private string $tempDir;

    protected function setUp(): void
    {
        $this->tempDir = sys_get_temp_dir() . '/php-sec-check-upload-' . uniqid();
        mkdir($this->tempDir, 0777, true);
    }

    protected function tearDown(): void
    {
        $this->removeDir($this->tempDir);
    }

    private function removeDir(string $dir): void
    {
        if (!is_dir($dir)) {
            return;
        }
        foreach (array_diff(scandir($dir), ['.', '..']) as $item) {
            $path = $dir . DIRECTORY_SEPARATOR . $item;
            if (is_dir($path)) {
                $this->removeDir($path);
            } else {
                @chmod($path, 0666);
                @unlink($path);
            }
        }
        @rmdir($dir);
    }

    /**
     * @return list<Issue>
     */
    private function runCheck(): array
    {
        ob_start();
        $result = (new FileUploadCheck())->run($this->tempDir);
        ob_end_clean();
        return $result;
    }

    /**
     * @param list<Issue> $issues
     */
    private function assertFinding(array $issues, string $needle, string $severity): Issue
    {
        foreach ($issues as $issue) {
            if (str_contains($issue->message, $needle)) {
                $this->assertSame($severity, $issue->severity, $issue->message);
                $this->assertSame('FileUploadCheck', $issue->check);
                return $issue;
            }
        }

        $this->fail("Expected a finding mentioning '{$needle}', got: " . json_encode(
            array_map(fn(Issue $i) => $i->message, $issues)
        ));
    }

    public function test_empty_project_returns_no_issues(): void
    {
        $this->assertSame([], $this->runCheck());
    }

    public function test_client_filename_into_public_is_critical(): void
    {
        file_put_contents(
            $this->tempDir . '/upload.php',
            <<<'PHP'
<?php
move_uploaded_file($tmp, 'public/' . $_FILES['f']['name']);
PHP
        );

        $issues = $this->runCheck();

        $this->assertCount(1, $issues);
        $this->assertFinding($issues, 'client filename', Issue::CRITICAL);
        $this->assertStringContainsString('web-accessible', $issues[0]->message);
        $this->assertStringContainsString('upload.php:', $issues[0]->message);
    }

    public function test_storage_generated_name_with_allow_list_is_clean(): void
    {
        file_put_contents(
            $this->tempDir . '/upload.php',
            <<<'PHP'
<?php
$allowed = ['jpg', 'png', 'gif', 'webp'];
$ext = strtolower(pathinfo($_FILES['f']['name'], PATHINFO_EXTENSION));
if (!in_array($ext, $allowed, true)) {
    return;
}
$dest = storage_path('app/uploads/' . bin2hex(random_bytes(16)) . '.' . $ext);
move_uploaded_file($_FILES['f']['tmp_name'], $dest);
PHP
        );

        $this->assertSame([], $this->runCheck());
    }

    public function test_public_destination_without_client_name_is_critical(): void
    {
        file_put_contents(
            $this->tempDir . '/upload.php',
            <<<'PHP'
<?php
move_uploaded_file($tmp, public_path('uploads/photo.jpg'));
PHP
        );

        $issues = $this->runCheck();

        $this->assertCount(1, $issues);
        $this->assertFinding($issues, 'web-accessible', Issue::CRITICAL);
    }

    public function test_client_filename_in_storage_is_critical(): void
    {
        file_put_contents(
            $this->tempDir . '/upload.php',
            <<<'PHP'
<?php
move_uploaded_file($tmp, storage_path('app/' . $_FILES['f']['name']));
PHP
        );

        $issues = $this->runCheck();

        $this->assertCount(1, $issues);
        $this->assertFinding($issues, 'client filename', Issue::CRITICAL);
    }

    public function test_generated_storage_path_without_allow_list_is_warn(): void
    {
        file_put_contents(
            $this->tempDir . '/upload.php',
            <<<'PHP'
<?php
move_uploaded_file($tmp, storage_path('app/' . bin2hex(random_bytes(8))));
PHP
        );

        $issues = $this->runCheck();

        $this->assertCount(1, $issues);
        $this->assertFinding($issues, 'allow-list', Issue::WARN);
    }

    public function test_tmp_name_is_not_treated_as_client_filename(): void
    {
        file_put_contents(
            $this->tempDir . '/upload.php',
            <<<'PHP'
<?php
$allowed = ['pdf'];
if (!in_array('pdf', $allowed, true)) {
    return;
}
move_uploaded_file($_FILES['f']['tmp_name'], storage_path('app/' . bin2hex(random_bytes(8)) . '.pdf'));
PHP
        );

        $this->assertSame([], $this->runCheck());
    }

    public function test_vendor_files_are_skipped(): void
    {
        mkdir($this->tempDir . '/vendor', 0777, true);
        file_put_contents(
            $this->tempDir . '/vendor/lib.php',
            <<<'PHP'
<?php
move_uploaded_file($tmp, 'public/' . $_FILES['f']['name']);
PHP
        );

        $this->assertSame([], $this->runCheck());
    }

    public function test_one_finding_per_call(): void
    {
        file_put_contents(
            $this->tempDir . '/upload.php',
            <<<'PHP'
<?php
move_uploaded_file($a, 'public/' . $_FILES['a']['name']);
move_uploaded_file($b, 'public/' . $_FILES['b']['name']);
PHP
        );

        $issues = $this->runCheck();

        $this->assertCount(2, $issues);
        foreach ($issues as $issue) {
            $this->assertSame(Issue::CRITICAL, $issue->severity);
            $this->assertSame('FileUploadCheck', $issue->check);
        }
    }

    public function test_laravel_mimes_rule_counts_as_allow_list(): void
    {
        file_put_contents(
            $this->tempDir . '/upload.php',
            <<<'PHP'
<?php
$request->validate(['photo' => 'required|file|mimes:jpg,png']);
move_uploaded_file($tmp, storage_path('app/' . uniqid('', true)));
PHP
        );

        $this->assertSame([], $this->runCheck());
    }

    public function test_files_without_move_uploaded_file_are_ignored(): void
    {
        file_put_contents(
            $this->tempDir . '/form.php',
            <<<'PHP'
<?php
$name = $_FILES['f']['name'];
copy($name, 'public/' . $name);
PHP
        );

        $this->assertSame([], $this->runCheck());
    }
}
