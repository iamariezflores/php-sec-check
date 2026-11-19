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
| PHP Version | Compares scanner runtime, `composer.json`, and deploy pins against PHP security-support dates — not a hardcoded 8.0 cutoff |
| Display Errors | Detects if `display_errors` is enabled (exposes stack traces in production) |
| Composer Audit | Runs `composer audit` to surface known CVEs in your dependencies |
| Dangerous Functions | Configuration: whether shell-execution functions are listed in `disable_functions` |
| Unsafe Function Usage | Source: whether risky functions are used in application PHP, and whether they receive untrusted input |
| Directory Exposure | Sensitive files and directories sitting in the document root (`public/`, or a project-root `index.php`) |
| Session Security | php.ini session hardening (`use_strict_mode`, `use_only_cookies`, `use_trans_sid`, SID entropy). Laravel `config/session.php` only when Laravel is detected |

#### PHP version

The scanner does **not** hardcode “below 8.0”. Local PHP is often newer than production, so it collects several signals and checks them against PHP’s security-support calendar ([supported versions](https://www.php.net/supported-versions.php)):

| Signal | Source |
|---|---|
| Scanner runtime | `PHP_VERSION` of the process running `sec-check` |
| Composer requirement | Lowest version allowed by `composer.json` `require.php` |
| Composer platform | `config.platform.php` when set |
| Deploy pin | `.php-version`, `.tool-versions` (`php …`), or `FROM php:X.Y` in a Dockerfile |

| Finding | Severity |
|---|---|
| A collected version is **past** security support | `CRITICAL` |
| Security support ends within 90 days | `WARN` |
| Scanner minor version **differs** from a deploy pin / `platform.php` | `WARN` |

Unknown newer minors (not yet in the calendar) are treated as supported; unknown older minors are treated as end-of-life.

#### Dangerous PHP functions

These are **two checks**, on purpose. Not every PHP function is equally dangerous, and some cannot be disabled via `disable_functions` at all.

**1. Configuration (`DangerousFunctionsCheck`)**

Production hardening. Only functions that can actually be listed in `disable_functions` are considered:

`exec`, `shell_exec`, `system`, `passthru`, `proc_open`, `popen`

Not in this list:

- `eval()` — language construct; `disable_functions` cannot turn it off
- `curl_exec()` / `curl_multi_exec()` — legitimate HTTP helpers; presence in php.ini is not a finding

Matching is **whole-name only**. Listing `curl_exec` in `disable_functions` does **not** count as disabling `exec`.

**2. Source usage (`UnsafeFunctionUsageCheck`)**

Scans application `.php` files with `token_get_all()` (a first pass; full taint / AST analysis is later). Skips `vendor/`, `node_modules/`, `.git/`, `storage/framework/`, and `bootstrap/cache/`.

Method calls such as `$pdo->exec()` and function definitions are ignored. `\exec()` (global) is still reported.

| Call | When it is reported |
|---|---|
| `exec`, `shell_exec`, `system`, `passthru`, `proc_open`, `popen`, `eval`, `create_function`, backtick shells | `WARN` on any use |
| Same calls with untrusted input in the argument list | `CRITICAL` |
| `curl_exec`, `curl_multi_exec` | Only if untrusted input reaches the call — a normal `curl_exec($ch)` is clean |

Untrusted input, for this pass: `$_GET`, `$_POST`, `$_REQUEST`, `$_COOKIE`, `$_FILES`, `$_SERVER`, `$argv`, and `php://input`. Nested assignments are not followed yet.

#### Directory exposure

Looks at the **document root**, not at whether `vendor/` is listed in `.gitignore` (`VendorCheck` still owns that). `public/` is scanned when that directory exists. A project-root `index.php` is treated as the document root only when `public/index.php` is absent.

`.env` copies in the web root stay with `EnvCredentialsCheck` and are not double-counted here. A Laravel `public/storage` **symlink** (`php artisan storage:link`) is not a finding; a real `storage/` directory copied into the document root is.

Git tracking uses `git ls-files` and `git check-ignore --no-index`. Ignore rules do not hide a path the web server can still serve.

| Finding | Severity |
|---|---|
| `.git` or `vendor/` in the document root | `CRITICAL` |
| `backup/`, `dumps/`, `storage/` (real directory, not a symlink) | `CRITICAL` |
| `phpinfo.php` or `*.sql` in the document root | `CRITICAL` |
| `composer.json` / `composer.lock`, `*.log`, `.htaccess` backups | `WARN` |
| Path is also tracked by git | promoted to `CRITICAL` |
| `public/.env` | not this check — `EnvCredentialsCheck` |
| Project-root `vendor/` next to Laravel `public/` | not this check — `VendorCheck` |

#### Session security

Checks **php.ini / runtime** session settings. Cookie flags (`Secure`, `HttpOnly`, `SameSite`) are not part of this check.

Laravel extras run only when `artisan` and `bootstrap/app.php` are present. A normal `file` driver writing to `storage/framework/sessions` is clean.

| Finding | Severity |
|---|---|
| `session.use_trans_sid=1` | `CRITICAL` |
| `session.use_only_cookies=0` | `CRITICAL` |
| `session.save_path` inside the document root | `CRITICAL` |
| SID length below PHP's minimum (22) | `CRITICAL` |
| `session.use_strict_mode=0` | `WARN` |
| SID entropy below 128 bits | `WARN` |
| Laravel `cookie` driver with `encrypt` false | `WARN` |
| Laravel `file` driver path under `public/` | `CRITICAL` |
| Hardened PHP 8.2+ values (`strict_mode=1`, `use_only_cookies=1`, `use_trans_sid=0`, ≥128 bits) | clean |

### Laravel-Specific Checks
Auto-detected when `artisan` and `bootstrap/app.php` are present:

| Check | Description |
|---|---|
| `APP_DEBUG` Check | Warns if `APP_DEBUG=true`, critical if combined with `APP_ENV=production` |
| Default Credentials | Warns if `DB_USERNAME` uses a default value (`root`, `admin`, etc.) or `DB_PASSWORD` is empty |
| `.env` Credentials | Flags leaked or mis-tracked env files, weak credentials, and secrets in `.env.example` — not a normally configured `.env` |
| Vendor in Git | Warns if `vendor/` is not excluded in `.gitignore` |

A filled `APP_KEY` or `DB_PASSWORD` in `.env` is expected Laravel configuration and is **not** reported. The check looks for real exposure instead:

| Finding | Severity |
|---|---|
| `.env` (or `.env.local`, `.env.production`, …) is **tracked by git** | `CRITICAL` |
| `.env` is listed in `.gitignore` but **still in the index** | `CRITICAL` — run `git rm --cached .env` |
| `.env` exists and is **not ignored** | `WARN` |
| `public/.env` or `.env` next to a root `index.php` | `CRITICAL` |
| Weak values such as `DB_PASSWORD=password` | `WARN` |
| Empty `APP_KEY` | `WARN` |
| `.env.example` contains a real-looking secret | `CRITICAL` |

Git exclusion is verified with `git ls-files` and `git check-ignore --no-index`, not by searching `.gitignore` for the string `.env`. A file that was committed before the ignore rule was added is still treated as tracked.

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
        "total": 4,
        "critical": 2,
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
            "message": "Shell-execution function 'exec' is not listed in disable_functions. Disable it in production php.ini.",
            "check": "DangerousFunctionsCheck"
        },
        {
            "severity": "CRITICAL",
            "message": "exec() receives untrusted input in app/Job.php:12.",
            "check": "UnsafeFunctionUsageCheck"
        },
        {
            "severity": "CRITICAL",
            "message": ".env is listed in ignore rules but is still tracked by git. Remove it from the index with `git rm --cached .env`.",
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
Scanner runtime: 8.3.36
composer.json require.php: >=8.2 (floor 8.2.0)
[WARN] PHP 8.2 from composer.json require.php is nearing the end of security support. Security support ends 2026-12-31.

[DISPLAY ERRORS]
[WARN] 'display_errors' is enabled. Disable in production.

[COMPOSER DEPENDENCIES]
[OK] No known vulnerabilities found in dependencies.

[DANGEROUS FUNCTIONS]
[WARN] Shell-execution function 'exec' is not listed in disable_functions. Disable it in production php.ini.

[UNSAFE FUNCTION USAGE]
[CRITICAL] exec() receives untrusted input in app/Job.php:12.

[DIRECTORY EXPOSURE]
[CRITICAL] public/.git is inside the document root and can be downloaded. Move repository metadata out of the web root.

[SESSION SECURITY]
[WARN] session.use_strict_mode is disabled. Enable it so PHP rejects uninitialized session IDs (session fixation).

Laravel project detected!
[APP DEBUG]
[CRITICAL] APP_DEBUG is enabled while APP_ENV is set to "production". This exposes stack traces and environment data to end users.

[DEFAULT CREDENTIALS]
[WARN] DB_USERNAME is set to 'root'. Using default database usernames is a security risk.
[CRITICAL] DB_PASSWORD is empty or null. A database without a password is a critical security risk.

[ENV CREDENTIALS]
[CRITICAL] .env is listed in ignore rules but is still tracked by git. Remove it from the index with `git rm --cached .env`.
[CRITICAL] public/.env exists and is inside a web-accessible directory. Move secrets out of the document root.
[CRITICAL] .env.example contains what looks like a real secret for 'APP_KEY' (value like 'base****'). Template files must not include live credentials.

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

On first run, `php-sec-check` automatically creates a `php-sec-check-config.php` file at your project root. Add extra key names here if you store secrets under custom env keys. Those names are used to detect **weak values** in `.env` and **live secrets copied into `.env.example`**. They are not used to flag a normally configured `.env`.

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
use Aquilinoflores\PhpSecCheck\Checks\UnsafeFunctionUsageCheck;
use Aquilinoflores\PhpSecCheck\Checks\DirectoryExposureCheck;
use Aquilinoflores\PhpSecCheck\Checks\SessionSecurityCheck;
use Aquilinoflores\PhpSecCheck\Checks\Laravel\EnvCredentialsCheck;
use Aquilinoflores\PhpSecCheck\Checks\Laravel\VendorCheck;

$projectRoot = base_path();

$checks = [
    new PhpVersionCheck(),
    new DangerousFunctionsCheck(),              // php.ini disable_functions
    new UnsafeFunctionUsageCheck(),             // token_get_all() source scan
    new DirectoryExposureCheck(),               // document-root .git / vendor / dumps
    new SessionSecurityCheck(),                 // php.ini session hardening
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

Tests live in `tests/Checks/` and `tests/Checks/Laravel/`, mirroring the `src/` structure. Token-scanner tests are in `tests/Scan/`. PHP support-calendar tests are in `tests/Php/`. Git working-tree helpers are covered in `tests/Git/`. Integration tests for programmatic usage, JSON output, and exit codes are in `tests/Integration/`.

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
