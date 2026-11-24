<?php

namespace Aquilinoflores\PhpSecCheck\Tests\Checks;

use Aquilinoflores\PhpSecCheck\Checks\HtaccessCheck;
use Aquilinoflores\PhpSecCheck\Issue;
use Aquilinoflores\PhpSecCheck\Scan\ScanContext;
use PHPUnit\Framework\TestCase;

class HtaccessCheckTest extends TestCase
{
    private string $tempDir;

    protected function setUp(): void
    {
        $this->tempDir = sys_get_temp_dir() . '/php-sec-check-htaccess-' . uniqid();
        mkdir($this->tempDir, 0777, true);
        ScanContext::reset();
    }

    protected function tearDown(): void
    {
        ScanContext::reset();
        $this->removeDir($this->tempDir);
    }

    private function removeDir(string $dir): void
    {
        if (!is_dir($dir)) {
            return;
        }
        foreach (array_diff(scandir($dir), ['.', '..']) as $item) {
            $path = $dir . DIRECTORY_SEPARATOR . $item;
            is_dir($path) ? $this->removeDir($path) : unlink($path);
        }
        rmdir($dir);
    }

    /**
     * @return list<Issue>
     */
    private function findings(): array
    {
        ob_start();
        $result = (new HtaccessCheck())->run($this->tempDir);
        ob_end_clean();
        return $result;
    }

    public function test_no_htaccess_is_clean(): void
    {
        mkdir($this->tempDir . '/public');
        $this->assertSame([], $this->findings());
    }

    public function test_options_indexes_is_high(): void
    {
        mkdir($this->tempDir . '/public');
        file_put_contents($this->tempDir . '/public/.htaccess', "Options Indexes\n");

        $issues = $this->findings();
        $indexes = array_values(array_filter($issues, fn(Issue $i) => $i->ruleId === HtaccessCheck::RULE_INDEXES));

        $this->assertCount(1, $indexes);
        $this->assertSame(Issue::HIGH, $indexes[0]->severity);
        $this->assertSame(Issue::CONFIRMED, $indexes[0]->confidence);
        $this->assertSame('public/.htaccess', $indexes[0]->path);
    }

    public function test_minus_indexes_is_not_a_listing_finding(): void
    {
        mkdir($this->tempDir . '/public');
        file_put_contents($this->tempDir . '/public/.htaccess', "Options All -Indexes\n");

        $issues = $this->findings();
        $indexes = array_filter($issues, fn(Issue $i) => $i->ruleId === HtaccessCheck::RULE_INDEXES);
        $this->assertSame([], array_values($indexes));
    }

    public function test_missing_denial_is_medium_and_high_on_production(): void
    {
        mkdir($this->tempDir . '/public_html', 0777, true);
        file_put_contents($this->tempDir . '/public_html/index.php', "<?php\n");
        file_put_contents($this->tempDir . '/public_html/.htaccess', "RewriteEngine On\n");

        $legacy = array_values(array_filter($this->findings(), fn(Issue $i) => $i->ruleId === HtaccessCheck::RULE_DENY));
        $this->assertCount(1, $legacy);
        $this->assertSame(Issue::MEDIUM, $legacy[0]->severity);
        $this->assertStringContainsString('.env', $legacy[0]->message);

        ScanContext::set('production');
        $production = array_values(array_filter($this->findings(), fn(Issue $i) => $i->ruleId === HtaccessCheck::RULE_DENY));
        $this->assertSame(Issue::HIGH, $production[0]->severity);
    }

    public function test_headers_are_info_until_one_is_present(): void
    {
        file_put_contents($this->tempDir . '/index.php', "<?php\n");
        file_put_contents($this->tempDir . '/.htaccess', "Options -Indexes\n");

        $headers = array_values(array_filter($this->findings(), fn(Issue $i) => $i->ruleId === HtaccessCheck::RULE_HEADERS));
        $this->assertCount(1, $headers);
        $this->assertSame(Issue::INFO, $headers[0]->severity);

        file_put_contents($this->tempDir . '/.htaccess', "Header set X-Frame-Options DENY\n");
        $gone = array_filter($this->findings(), fn(Issue $i) => $i->ruleId === HtaccessCheck::RULE_HEADERS);
        $this->assertSame([], array_values($gone));
    }

    public function test_html_directory_without_index_or_htaccess_is_ignored(): void
    {
        mkdir($this->tempDir . '/html');
        file_put_contents($this->tempDir . '/html/page.php', "<?php\n");
        $this->assertSame([], $this->findings());
    }
}
