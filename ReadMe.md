# php-sec-check

> A lightweight CLI tool to scan PHP and Laravel projects for common security risks.

[![Packagist Version](https://img.shields.io/packagist/v/iamariezflores/php-sec-check)](https://packagist.org/packages/iamariezflores/php-sec-check)
[![Packagist Downloads](https://img.shields.io/packagist/dt/iamariezflores/php-sec-check)](https://packagist.org/packages/iamariezflores/php-sec-check)
[![PHP Version](https://img.shields.io/badge/php-%3E%3D8.2-blue)](https://packagist.org/packages/iamariezflores/php-sec-check)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![PHPUnit](https://img.shields.io/badge/tested%20with-PHPUnit-blue)](https://phpunit.de)

---

## Overview

`php-sec-check` is a Composer dev tool that audits your PHP or Laravel project for security misconfigurations and vulnerabilities in seconds. Run it from the command line — no setup required.

The package has **no runtime dependencies**. PHPUnit is included as a dev dependency for running the test suite during development and contributions.

```bash
vendor/bin/sec-check
```

---

## Features

### Generic PHP Checks
These run on **any** PHP project:

| Check | Description |
|---|---|
| PHP Version | Warns if your PHP version is below 8.0 |
| Display Errors | Detects if `display_errors` is enabled (exposes stack traces in production) |
| Composer Audit | Runs `composer audit` to surface known CVEs in your dependencies |
| Dangerous Functions | Checks if high-risk functions are unrestricted in `php.ini` |

**Dangerous functions checked:**
`exec`, `shell_exec`, `system`, `passthru`, `eval`, `create_function`, `proc_open`, `popen`, `curl_exec`, `curl_multi_exec`, `parse_ini_file`, `show_source`

### Laravel-Specific Checks
Auto-detected when `artisan` and `bootstrap/app.php` are present:

| Check | Description |
|---|---|
| `APP_DEBUG` Check | Warns if `APP_DEBUG=true`, critical if combined with `APP_ENV=production` |
| Default Credentials | Warns if `DB_USERNAME` uses a default value (`root`, `admin`, etc.) or `DB_PASSWORD` is empty |
| `.env` Credentials | Scans for exposed sensitive keys (e.g. `APP_KEY`, `DB_PASSWORD`) |
| Vendor in Git | Warns if `vendor/` is not excluded in `.gitignore` |

### Severity Levels

Every finding is tagged with a severity level so you can triage at a glance:

| Level | Color | Meaning |
|---|---|---|
| `CRITICAL` | Red background | Active security risk — fix before deploying to production |
| `WARN` | Red text | Bad practice or potential risk — should be addressed |
| `INFO` | Yellow text | Informational notice — not necessarily a risk |

---

## Requirements

- **PHP >= 8.2**
- Composer

## Installation

Install as a dev dependency via Composer:

```bash
composer require iamariezflores/php-sec-check --dev
```

Available on Packagist: [iamariezflores/php-sec-check](https://packagist.org/packages/iamariezflores/php-sec-check)

---

## Usage

From your project root, run:

```bash
vendor/bin/sec-check
```

The tool exits with **code `0`** when no issues are found, and **code `1`** when any issue is detected. This makes it compatible with any CI/CD pipeline out of the box.

### JSON Output

Pass `--format=json` to get machine-readable output instead of the coloured text report. All echo output is suppressed and a single JSON document is printed:

```bash
vendor/bin/sec-check --format=json
```

```json
{
    "summary": {
        "total": 3,
        "critical": 1,
        "warn": 2,
        "info": 0
    },
    "issues": [
        {
            "severity": "CRITICAL",
            "message": "APP_DEBUG is enabled while APP_ENV is set to \"production\". This exposes stack traces and environment data to end users.",
            "check": "AppDebugCheck"
        },
        {
            "severity": "WARN",
            "message": "Dangerous function enabled: exec",
            "check": "DangerousFunctionsCheck"
        },
        {
            "severity": "WARN",
            "message": "Sensitive key 'APP_KEY' found in .env with value like 'base****'",
            "check": "EnvCredentialsCheck"
        }
    ]
}
```

The JSON format is designed for downstream integrations — Slack bots, custom dashboards, CI reporters, or any tool that consumes structured data. The exit code still follows the same `0` / `1` convention.

### Example Output (text)

```
=== PHP Security Check Tool ===

[PHP VERSION]
[OK] PHP version is up-to-date.

[DISPLAY ERRORS]
[WARN] 'display_errors' is enabled. Disable in production.

[COMPOSER DEPENDENCIES]
[OK] No known vulnerabilities found in dependencies.

[DANGEROUS FUNCTIONS]
[WARN] Dangerous function enabled: exec
[WARN] Dangerous function enabled: shell_exec

Laravel project detected!
[CRITICAL] APP_DEBUG is enabled while APP_ENV is set to "production".
[WARN] DB_USERNAME is set to 'root'. Using default database usernames is a security risk.
[CRITICAL] DB_PASSWORD is empty or null. A database without a password is a critical security risk.

Scan complete.
```

### CI/CD Integration

Because `sec-check` exits with code `1` on any finding, you can drop it directly into your pipeline and it will **fail the build** automatically when issues are detected.

**GitHub Actions:**

```yaml
name: Security Check

on: [push, pull_request]

jobs:
  security:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Install dependencies
        run: composer install --no-interaction

      - name: Run security check
        run: vendor/bin/sec-check
```

**GitLab CI:**

```yaml
security-check:
  stage: test
  script:
    - composer install --no-interaction
    - vendor/bin/sec-check
```

**Makefile / Shell script:**

```bash
composer install --no-interaction
vendor/bin/sec-check || exit 1
```

**Capturing JSON output in CI:**

```bash
vendor/bin/sec-check --format=json > security-report.json
```

---

## Configuration

On first run, `php-sec-check` automatically creates a `php-sec-check-config.php` file at your project root. Edit this file to add your own sensitive `.env` key names:

```php
<?php

return [
    'sensitive_keys' => [
        'APP_KEY',
        'DB_PASSWORD',
        'MAIL_PASSWORD',
        'AWS_SECRET_ACCESS_KEY',
        'STRIPE_SECRET_KEY',
        'CUSTOM_SECRET',
    ],
];
```

---

## Advanced Usage

### Programmatic Usage

All checks return an array of `Issue` objects. Each `Issue` carries a `severity`, `message`, and the `check` name that produced it. This is ideal for building custom security dashboards, audit routes, or integrating findings into your own tooling.

```php
use Aquilinoflores\PhpSecCheck\Issue;
use Aquilinoflores\PhpSecCheck\Checks\PhpVersionCheck;
use Aquilinoflores\PhpSecCheck\Checks\DangerousFunctionsCheck;
use Aquilinoflores\PhpSecCheck\Checks\Laravel\EnvCredentialsCheck;
use Aquilinoflores\PhpSecCheck\Checks\Laravel\VendorCheck;

$projectRoot = base_path();

$checks = [
    new PhpVersionCheck(),
    new DangerousFunctionsCheck(),
    new EnvCredentialsCheck(['CUSTOM_SECRET', 'ANOTHER_KEY']),
    new VendorCheck(),
];

$allIssues = [];
foreach ($checks as $check) {
    $allIssues = array_merge($allIssues, $check->run($projectRoot));
}

// Filter by severity
$critical = array_filter($allIssues, fn(Issue $i) => $i->severity === Issue::CRITICAL);
$warnings = array_filter($allIssues, fn(Issue $i) => $i->severity === Issue::WARN);

// Serialize for an API response
$payload = array_map(fn(Issue $i) => $i->toArray(), $allIssues);
return response()->json($payload);
```

Each `Issue` object exposes:

| Property / Method | Description |
|---|---|
| `$issue->severity` | `'CRITICAL'`, `'WARN'`, or `'INFO'` |
| `$issue->message` | Human-readable description of the finding |
| `$issue->check` | Name of the check class that produced the issue |
| `$issue->toArray()` | Serializes to `['severity', 'message', 'check']` |
| `(string) $issue` | Returns `$issue->message` |

### Adding Custom Checks

All checks implement the `CheckInterface` contract:

```php
use Aquilinoflores\PhpSecCheck\Checks\CheckInterface;
use Aquilinoflores\PhpSecCheck\Issue;

class MyCustomCheck implements CheckInterface
{
    public function run(string $projectRoot): array
    {
        $issues = [];

        // ... your detection logic ...

        if ($somethingBad) {
            $issues[] = new Issue(Issue::CRITICAL, 'Something critical was found.', 'MyCustomCheck');
        }

        return $issues;
    }
}
```

To add a new built-in check, create the class in `src/Checks/` and register it in `bin/sec-check`.

---

## Running Tests

The test suite uses PHPUnit and covers all PHP and Laravel checks:

```bash
composer test
```

Tests live in `tests/Checks/` and `tests/Checks/Laravel/`, mirroring the `src/` structure. Integration tests for programmatic usage and exit codes are in `tests/Integration/`.

---

## Contributing

Contributions are welcome and encouraged!

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/your-check-name`
3. Implement your check in `src/Checks/`, following the `CheckInterface` contract
4. **Write tests** for your check in the corresponding `tests/Checks/` directory — PRs without tests will not be merged
5. Verify the full suite passes: `composer test`
6. Commit your changes: `git commit -m "feat: add your-check-name check"`
7. Push to your fork and open a Pull Request

**Guidelines:**
- Keep checks modular and focused on a single security concern
- Every new check must return `Issue[]` with an appropriate severity level
- Every new check class must have a corresponding `*Test.php` file
- Every bug fix must include a regression test that would have caught the bug
- Tests must pass before a PR will be reviewed

---

## License

This project is open-source software licensed under the [MIT License](LICENSE).
