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
| Cookie Flags | `setcookie()` / `setrawcookie()` options, `session.cookie_secure` / `httponly` / `samesite`, and Laravel session cookie flags |
| File Upload | `move_uploaded_file()` destinations that keep the client filename, skip an extension/MIME allow-list, or write under `public/` |
| XSS Output | `echo` / `print` / `<?=` of `$_GET` / `$_POST` / `$_REQUEST` / `$_COOKIE` without HTML escaping, and Blade `{!! !!}` |

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

`VendorCheck` only asks whether `vendor/` is listed in `.gitignore`. A web server does not read `.gitignore`. `DirectoryExposureCheck` asks whether sensitive paths sit in the **document root** and can be downloaded.

| Project layout | What is scanned |
|---|---|
| `public/` directory exists | `public/` |
| `index.php` at the project root and **no** `public/index.php` | project root |
| neither | nothing (informational only) |

Git is extra context, not the decision. Tracking uses `git ls-files`; ignore rules use `git check-ignore --no-index`. A path that is gitignored but still on disk in `public/` is still a finding. A path that is also tracked is promoted to `CRITICAL`.

A Laravel `public/storage` **symlink** (`php artisan storage:link`) is skipped. A real `storage/` directory copied into the document root is not.

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

This is php.ini session **mechanics**, not cookie flags. `Secure`, `HttpOnly`, and `SameSite` belong to a separate check.

Settings are read from runtime `ini_get()` (or an injected map when you construct `SessionSecurityCheck` yourself). SID strength is `sid_length × sid_bits_per_character`. PHP's own minimum length is 22; **128 bits** of entropy is the floor we treat as locked down. Both `32 × 4` (engine default length) and `26 × 5` (common `php.ini-production`) pass.

| Setting | Hardened value | Finding |
|---|---|---|
| `session.use_trans_sid` | `0` | `CRITICAL` if enabled — session IDs leak in URLs and `Referer` |
| `session.use_only_cookies` | `1` | `CRITICAL` if disabled — session IDs can be passed in URLs |
| `session.save_path` | not under the document root | `CRITICAL` if it resolves inside `public/` (including `N;mode;/path` prefixes) |
| `session.sid_length` | ≥ 22 | `CRITICAL` below PHP's minimum |
| `session.use_strict_mode` | `1` | `WARN` if disabled — uninitialized IDs (session fixation) |
| SID entropy | ≥ 128 bits | `WARN` if lower |

Laravel extras run **only** when `artisan` and `bootstrap/app.php` exist. `.env` overrides `config/session.php` defaults. A normal `file` driver writing to `storage_path('framework/sessions')` is clean.

| Laravel finding | Severity |
|---|---|
| `cookie` driver with `encrypt` false | `WARN` |
| `file` driver path under `public/` (`public_path(...)` or a `public/` string) | `CRITICAL` |

#### Cookie flags

Missing `Secure`, `HttpOnly`, or `SameSite` makes cookies easy to steal (XSS) or send cross-site (CSRF). **Session security** still owns trans-sid, strict mode, and SID entropy. This check owns the flags on the cookie itself.

Three signals, same first-pass style as the other source scans (`token_get_all()`, skip `vendor/` / `node_modules/` / `.git/`):

| Signal | What is inspected |
|---|---|
| Application source | `setcookie()` and `setrawcookie()` |
| php.ini / runtime | `session.cookie_httponly`, `session.cookie_secure`, `session.cookie_samesite` |
| Laravel | `config/session.php` + `.env`, only when `artisan` and `bootstrap/app.php` exist |

| Finding | Severity |
|---|---|
| `setcookie('sid', $id)` / `setrawcookie()` with no options array | `WARN` — missing Secure, HttpOnly, and SameSite |
| Options array with `secure => true`, `httponly => true`, `samesite => 'Lax'` (or `Strict`) | clean |
| Legacy 7-argument `setcookie` with Secure and HttpOnly but no SameSite | `WARN` |
| `session.cookie_httponly=0` | `CRITICAL` — JavaScript can read the session cookie |
| `session.cookie_secure=0` | `WARN` — cookie can be sent over HTTP |
| `session.cookie_samesite` unset | `WARN` |
| `SameSite=None` without `Secure` | `CRITICAL` — browsers reject it |
| Laravel `http_only => false` | `WARN` |
| Laravel `same_site => null` (or empty) | `WARN` |
| Laravel `secure` explicitly `false` | `WARN` |
| Laravel `SESSION_SECURE_COOKIE` unset / null | not a finding — Laravel may enable Secure on HTTPS |

A third argument that is a **variable** (`setcookie('sid', $id, $opts)`) is skipped on this pass; assignments are not followed. `SameSite=None` is accepted only when Secure is also true.

#### File upload

Saving an upload under `public/` with the original client filename lets an attacker plant executable PHP (or HTML) and request it later. This is a first-pass `token_get_all()` scan of `move_uploaded_file()` destinations — not a full upload pipeline. Nested assignments are not followed. `vendor/`, `node_modules/`, `.git/`, `storage/framework/`, and `bootstrap/cache/` are skipped.

| Finding | Severity |
|---|---|
| Destination is under `public/` or `public_path()` **and** uses `$_FILES[...]['name']` | `CRITICAL` |
| Destination is under `public/` / `public_path()` | `CRITICAL` |
| Destination uses the client filename (`$_FILES[...]['name']`) | `CRITICAL` |
| No extension or MIME allow-list in the same file | `WARN` |
| `storage_path()` (or non-public path) + generated name (`random_bytes` / `bin2hex` / `uniqid`) + allow-list (`in_array` of extensions, `mimes:`, `finfo_*`, `mime_content_type`, `getimagesize`) | clean |

`$_FILES[...]['tmp_name']` is the PHP temp path and is **not** treated as a client filename. `copy()` / `$_FILES` without `move_uploaded_file()` are out of scope on this pass.

#### XSS output

Unescaped user input in HTML is a classic stored/reflected XSS path. This is a first-pass `token_get_all()` + Blade scan — not a DOM XSS engine. Nested assignments are not followed. `vendor/`, `node_modules/`, `.git/`, `storage/framework/`, and `bootstrap/cache/` are skipped.

Untrusted input for this check: `$_GET`, `$_POST`, `$_REQUEST`, `$_COOKIE`.

| Finding | Severity |
|---|---|
| `echo $_GET['q']` / `print` / `<?=` of untrusted input | `CRITICAL` |
| Same output wrapped in `htmlspecialchars`, `htmlentities`, or Laravel `e()` | clean |
| Blade `{{ $q }}` (auto-escaped) | clean |
| Blade `{!! $_GET['q'] !!}` | `CRITICAL` |
| Blade `{!! $q !!}` (raw HTML, no superglobal on this pass) | `WARN` |
| File sets `Content-Type: application/json` | out of scope (avoids JSON API false positives) |
| `echo json_encode($_GET)` | out of scope for this pass |

A concatenated mix (`htmlspecialchars($_GET['a']) . $_GET['b']`) is still `CRITICAL` because part of the output is unescaped.

### Laravel-Specific Checks
Auto-detected when `artisan` and `bootstrap/app.php` are present. Session **driver/path/encrypt** extras live on **Session Security**; session **cookie flags** live on **Cookie Flags**. Both run only in this case:

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
        "total": 9,
        "critical": 6,
        "warn": 3,
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
            "message": "public/.git is inside the document root and can be downloaded. Move repository metadata out of the web root.",
            "check": "DirectoryExposureCheck"
        },
        {
            "severity": "WARN",
            "message": "session.use_strict_mode is disabled. Enable it so PHP rejects uninitialized session IDs (session fixation).",
            "check": "SessionSecurityCheck"
        },
        {
            "severity": "WARN",
            "message": "setcookie() in login.php:1 is missing Secure, HttpOnly, and SameSite.",
            "check": "CookieFlagsCheck"
        },
        {
            "severity": "CRITICAL",
            "message": "move_uploaded_file() in upload.php:1 writes the client filename into a web-accessible directory.",
            "check": "FileUploadCheck"
        },
        {
            "severity": "CRITICAL",
            "message": "echo in view.php:2 outputs untrusted input without HTML escaping.",
            "check": "XssOutputCheck"
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

[COOKIE FLAGS]
[WARN] setcookie() in login.php:1 is missing Secure, HttpOnly, and SameSite.

[FILE UPLOAD]
[CRITICAL] move_uploaded_file() in upload.php:1 writes the client filename into a web-accessible directory.

[XSS OUTPUT]
[CRITICAL] echo in view.php:2 outputs untrusted input without HTML escaping.

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
use Aquilinoflores\PhpSecCheck\Checks\CookieFlagsCheck;
use Aquilinoflores\PhpSecCheck\Checks\FileUploadCheck;
use Aquilinoflores\PhpSecCheck\Checks\XssOutputCheck;
use Aquilinoflores\PhpSecCheck\Checks\Laravel\EnvCredentialsCheck;
use Aquilinoflores\PhpSecCheck\Checks\Laravel\VendorCheck;

$projectRoot = base_path();

$checks = [
    new PhpVersionCheck(),
    new DangerousFunctionsCheck(),              // php.ini disable_functions
    new UnsafeFunctionUsageCheck(),             // token_get_all() source scan
    new DirectoryExposureCheck(),               // document-root .git / vendor / dumps
    new SessionSecurityCheck(),                 // runtime php.ini; pass an ini map in tests
    new CookieFlagsCheck(),                     // Secure / HttpOnly / SameSite
    new FileUploadCheck(),                      // move_uploaded_file() dest heuristics
    new XssOutputCheck(),                       // unescaped echo / Blade {!! !!}
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

Tests live in `tests/Checks/` and `tests/Checks/Laravel/`, mirroring the `src/` structure. Token-scanner tests are in `tests/Scan/`. PHP support-calendar tests are in `tests/Php/`. Git working-tree helpers are covered in `tests/Git/`. Directory-exposure, session-security, and cookie-flags tests are in `tests/Checks/`. Integration tests for programmatic usage, JSON output, and exit codes are in `tests/Integration/`.

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
