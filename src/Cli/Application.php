<?php

namespace Aquilinoflores\PhpSecCheck\Cli;

use Aquilinoflores\PhpSecCheck\Config\ScanOptions;
use Aquilinoflores\PhpSecCheck\Finding;
use Aquilinoflores\PhpSecCheck\Report\JsonReporter;
use Aquilinoflores\PhpSecCheck\Report\TextReporter;
use Aquilinoflores\PhpSecCheck\Rule\RuleCatalog;
use Aquilinoflores\PhpSecCheck\Scan\ProjectScanner;
use InvalidArgumentException;

/**
 * Argument parsing, exit codes, and reporting.
 *
 * scan never writes into the target. init is the only command that creates a file.
 */
class Application
{
    public const EXIT_CLEAN = 0;
    public const EXIT_FINDINGS = 1;
    public const EXIT_USAGE = 2;
    public const EXIT_UNREADABLE = 3;

    public function __construct(
        private readonly ProjectScanner $scanner = new ProjectScanner(),
        private readonly TextReporter $text = new TextReporter(),
        private readonly JsonReporter $json = new JsonReporter(),
    ) {}

    /**
     * @param list<string> $argv
     */
    public function run(array $argv): int
    {
        try {
            $options = $this->parse($argv);
        } catch (InvalidArgumentException $e) {
            fwrite(STDERR, $e->getMessage() . "\n");
            return self::EXIT_USAGE;
        }

        if ($options['help']) {
            fwrite(STDOUT, $this->help());
            return self::EXIT_CLEAN;
        }

        if ($options['command'] === 'rules') {
            fwrite(STDOUT, $this->rules());
            return self::EXIT_CLEAN;
        }

        if ($options['command'] === 'init') {
            return $this->init($options['path']);
        }

        $path = $options['path'] ?? getcwd();
        if ($path === false || !is_dir($path)) {
            fwrite(STDERR, "Not a directory: {$path}\n");
            return self::EXIT_UNREADABLE;
        }

        $scan = ScanOptions::fromProject($path)->withOverrides(
            $options['profile'],
            $options['threshold'],
            $options['exclude'],
        );
        $findings = $this->scanner->scan($path, $scan);
        $shown = [];
        $hidden = 0;
        foreach ($findings as $finding) {
            if ($finding->meets($scan->minSeverity)) {
                $shown[] = $finding;
            } else {
                $hidden++;
            }
        }

        if ($options['format'] === 'json') {
            fwrite(STDOUT, $this->json->render($shown, $hidden, $scan->minSeverity));
        } else {
            fwrite(STDOUT, $this->text->render($path, $shown, $hidden, $scan->minSeverity));
        }

        return $shown === [] ? self::EXIT_CLEAN : self::EXIT_FINDINGS;
    }

    /**
     * @param list<string> $argv
     * @return array{command: string, path: ?string, format: string, threshold: ?string, profile: ?string, exclude: list<string>, help: bool}
     */
    private function parse(array $argv): array
    {
        $positionals = [];
        $format = 'text';
        $threshold = null;
        $profile = null;
        $exclude = [];
        $help = false;

        $args = array_slice($argv, 1);
        $count = count($args);
        for ($i = 0; $i < $count; $i++) {
            $arg = $args[$i];

            if ($arg === '--help' || $arg === '-h') {
                $help = true;
                continue;
            }

            if ($arg === '--format') {
                $format = $this->requireValue($args, $i, '--format');
                continue;
            }

            if (str_starts_with($arg, '--format=')) {
                $format = substr($arg, strlen('--format='));
                continue;
            }

            if ($arg === '--min-severity') {
                $threshold = $this->requireValue($args, $i, '--min-severity');
                continue;
            }

            if (str_starts_with($arg, '--min-severity=')) {
                $threshold = substr($arg, strlen('--min-severity='));
                continue;
            }

            if ($arg === '--profile') {
                $profile = $this->requireValue($args, $i, '--profile');
                continue;
            }

            if (str_starts_with($arg, '--profile=')) {
                $profile = substr($arg, strlen('--profile='));
                continue;
            }

            if ($arg === '--exclude') {
                $exclude[] = $this->requireValue($args, $i, '--exclude');
                continue;
            }

            if (str_starts_with($arg, '--exclude=')) {
                $exclude[] = substr($arg, strlen('--exclude='));
                continue;
            }

            if (str_starts_with($arg, '--')) {
                throw new InvalidArgumentException("Unknown option: {$arg}");
            }

            $positionals[] = $arg;
        }

        if (!in_array($format, ['text', 'json'], true)) {
            throw new InvalidArgumentException("Unknown format: {$format}. Use text or json.");
        }

        if ($threshold !== null) {
            $normalized = Finding::normalizeSeverity($threshold);
            if ($normalized === null) {
                throw new InvalidArgumentException(
                    "Unknown severity: {$threshold}. Use critical, high, medium, low, or info."
                );
            }
            $threshold = $normalized;
        }

        if ($profile !== null) {
            $profile = strtolower($profile);
            if (!in_array($profile, ['legacy', 'production', 'host', 'dependencies', 'laravel'], true)) {
                throw new InvalidArgumentException(
                    "Unknown profile: {$profile}. Use legacy, production, host, dependencies, or laravel."
                );
            }
        }

        $command = 'scan';
        if (in_array($positionals[0] ?? '', ['scan', 'init', 'rules'], true)) {
            $command = array_shift($positionals);
        }

        if ($command === 'rules' && $positionals !== []) {
            throw new InvalidArgumentException('rules does not take a path.');
        }

        if (count($positionals) > 1) {
            throw new InvalidArgumentException('Too many arguments. Pass one path.');
        }

        return [
            'command'   => $command,
            'path'      => $positionals[0] ?? null,
            'format'    => $format,
            'threshold' => $threshold,
            'profile'   => $profile,
            'exclude'   => $exclude,
            'help'      => $help,
        ];
    }

    /**
     * @param list<string> $args
     */
    private function requireValue(array $args, int &$index, string $flag): string
    {
        $index++;
        if (!isset($args[$index]) || str_starts_with($args[$index], '--')) {
            throw new InvalidArgumentException("{$flag} needs a value.");
        }

        return $args[$index];
    }

    private function init(?string $path): int
    {
        $root = $path ?? getcwd();
        if ($root === false || !is_dir($root)) {
            fwrite(STDERR, "Not a directory: {$root}\n");
            return self::EXIT_UNREADABLE;
        }

        $file = rtrim($root, '/\\') . DIRECTORY_SEPARATOR . 'php-sec-check-config.php';
        if (is_file($file)) {
            fwrite(STDERR, "Config already exists: {$file}\n");
            return self::EXIT_USAGE;
        }

        $template = <<<'PHP'
<?php

return [
    // Names checked for weak values in .env, live values in templates, and
    // hardcoded assignments in configuration files.
    // A filled value inside .env is expected and is not a finding.
    'sensitive_keys' => [
        'APP_KEY',
        'DB_PASSWORD',
        'MAIL_PASSWORD',
        'AWS_SECRET_ACCESS_KEY',
        'STRIPE_SECRET_KEY',
    ],
    // legacy, production, host, dependencies, or laravel.
    'profile' => 'legacy',
    // Directories or path fragments omitted from the report.
    'exclude' => [],
    // Rule ids to skip, for example 'PSC-WEB-003'.
    'disabled_rules' => [],
];

PHP;

        if (file_put_contents($file, $template) === false) {
            fwrite(STDERR, "Could not write {$file}\n");
            return self::EXIT_UNREADABLE;
        }

        fwrite(STDOUT, "Wrote {$file}\n");
        return self::EXIT_CLEAN;
    }

    private function help(): string
    {
        return <<<'TXT'
php-sec-check scan [path] [--profile=legacy] [--format=text|json] [--min-severity=high] [--exclude=dir]

  Scan a PHP application directory. The directory does not need Composer.
  scan does not write into the target.

  Profiles:
    legacy        default. Project files, document root, and same-expression rules.
    production    legacy, with missing .htaccess denials raised to high.
    host          production, plus world-writable files. Use this on the server.
    dependencies  legacy, plus composer audit when composer.lock exists.
    laravel       legacy, plus APP_DEBUG, default database credentials, and vendor gitignore.

  Exit 0 when nothing at or above the threshold is found.
  Exit 1 when a finding meets the threshold.
  Exit 2 when the arguments are invalid.
  Exit 3 when the path cannot be read.

  --min-severity  critical, high (default), medium, low, or info.
                  warn is accepted as an alias of medium.
  --exclude       path fragment to omit. Repeat the flag to add more.

php-sec-check rules

  List rule ids.

php-sec-check init [path]

  Write php-sec-check-config.php. Refuses to overwrite an existing file.

TXT;
    }

    private function rules(): string
    {
        $lines = ['Rule id       Severity   Summary'];
        foreach (RuleCatalog::all() as $rule) {
            $lines[] = sprintf('%-13s %-10s %s', $rule['id'], $rule['severity'], $rule['summary']);
        }

        return implode("\n", $lines) . "\n";
    }
}
