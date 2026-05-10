# php-sec-check

> A lightweight CLI tool to scan PHP and Laravel projects for common security risks.

[![Packagist Version](https://img.shields.io/packagist/v/iamariezflores/php-sec-check)](https://packagist.org/packages/iamariezflores/php-sec-check)
[![Packagist Downloads](https://img.shields.io/packagist/dt/iamariezflores/php-sec-check)](https://packagist.org/packages/iamariezflores/php-sec-check)
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
| `.env` Credentials | Scans for exposed sensitive keys (e.g. `APP_KEY`, `DB_PASSWORD`) |
| Vendor in Git | Warns if `vendor/` is not excluded in `.gitignore` |

---

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

### Example Output

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
[WARN] Dangerous function enabled: curl_exec

Laravel project detected!
[WARNING] Sensitive key 'APP_KEY' found in .env!
[WARNING] vendor/ directory exists and is not ignored in .gitignore!

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

### Programmatic Usage (Laravel)

You can invoke individual checks directly in your code. This is useful for building custom security dashboards or audit routes:

```php
use Aquilinoflores\PhpSecCheck\Checks\Laravel\EnvCredentialsCheck;

Route::get('/security-audit', function () {
    $customKeys = ['CUSTOM_SECRET', 'ANOTHER_KEY'];
    $check = new EnvCredentialsCheck($customKeys);
    $results = $check->run(base_path());

    return response()->json($results);
});
```

### Adding Custom Checks

All checks implement the `CheckInterface` contract:

```php
interface CheckInterface {
    public function run(string $projectRoot): array;
}
```

To add a new check, create a class in `src/Checks/` that implements `CheckInterface`, then register it in `bin/sec-check`.

---

## Running Tests

The test suite uses PHPUnit and covers all PHP and Laravel checks:

```bash
composer test
```

Tests live in `tests/Checks/` and `tests/Checks/Laravel/`, mirroring the `src/` structure.

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
- Every new check class must have a corresponding `*Test.php` file
- Every bug fix must include a regression test that would have caught the bug
- Tests must pass before a PR will be reviewed

---

## License

This project is open-source software licensed under the [MIT License](LICENSE).
