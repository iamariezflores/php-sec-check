# php-sec-check

Security auditor for traditional PHP: plain scripts, custom MVC, and PHP with MySQL. The target does not need Composer, Laravel, or Symfony.

The scanner itself requires PHP 8.2 or newer and has no runtime dependencies. It reads the project. It does not execute it, and `scan` does not write into it.

Packagist is the primary install. A PHAR is the second channel, for a machine where you do not want a global Composer package.

[![Packagist Version](https://img.shields.io/packagist/v/iamariezflores/php-sec-check)](https://packagist.org/packages/iamariezflores/php-sec-check)
[![PHP Version](https://img.shields.io/badge/php-%3E%3D8.2-blue)](https://packagist.org/packages/iamariezflores/php-sec-check)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

## Install

```bash
composer global require iamariezflores/php-sec-check
php-sec-check scan /path/to/project
```

`sec-check` is the same command.

Build the PHAR from a checkout:

```bash
composer install
composer phar
php php-sec-check.phar rules
```

A host whose only PHP is 7.x cannot run the scanner in place. Copy the tree to a PHP 8.2+ machine, or run the PHAR there, and point it at the old source.

## Commands

```text
php-sec-check scan [path] [--profile=legacy] [--format=text|json] [--min-severity=high] [--exclude=dir]
php-sec-check rules
php-sec-check init [path]
```

`scan` with no path reads the current directory. `--exclude` may be repeated. `init` writes `php-sec-check-config.php` and refuses to overwrite it. `rules` prints the rule ids.

### Profiles

| Profile | What it adds |
|---|---|
| `legacy` | Default. Project PHP settings, document root, secrets in the working tree, and same-expression source rules. |
| `production` | Missing `.htaccess` denials are high. |
| `host` | Production, plus world-writable files in the document root. Use this on the server. It does nothing about permissions on Windows. |
| `dependencies` | Legacy, plus `composer audit` when `composer.lock` is present. |
| `laravel` | Legacy, plus `APP_DEBUG`, default database credentials, `vendor/` gitignore, and Laravel session config. |

`composer audit` and the Laravel checks are not part of the default scan.

### Exit codes

| Code | Meaning |
|---|---|
| 0 | Nothing at or above the threshold. |
| 1 | A finding meets the threshold. |
| 2 | Invalid arguments, or `init` would overwrite a config file. |
| 3 | The path cannot be read. |

The default threshold is `high`. `medium`, `low`, and `info` are counted and hidden. `warn` is an alias of `medium`.

## What a scan looks at

Document roots are `public/` when that directory exists, and `public_html`, `www`, `web`, `html`, `htdocs`, `httpdocs`, or `webroot` when the directory contains `index.php` or `.htaccess`. The project root is a document root when `index.php` is there and none of those directories has its own `index.php`.

PHP settings come from the project's `.user.ini`, `php.ini`, `.htaccess` `php_flag` / `php_value`, and literal `ini_set()` / `ini_alter()` calls. The scanner process `php.ini` is not the application's configuration. A directive the project never sets is not a finding.

Source rules stay inside one expression or one statement. There is no cross-function taint analysis.

| Rule | Severity | What it reports |
|---|---|---|
| PSC-RUN-001 | critical | PHP branch past security support, nearing it, or a pin that does not match the scanner |
| PSC-RUN-010 | medium | `display_errors` enabled in the project |
| PSC-RUN-011 | critical | `allow_url_include` enabled |
| PSC-RUN-012 | low | `expose_php` enabled |
| PSC-RUN-020 | medium | The project sets `disable_functions` and leaves out a shell function |
| PSC-RUN-030 | critical | Session settings written by the project |
| PSC-RUN-040 | critical | Cookie flags on `setcookie()` or in project session config |
| PSC-WEB-001 | high | `Options Indexes` |
| PSC-WEB-002 | medium | An `.htaccess` file does not mention `.env`, `.git`, or `.sql` |
| PSC-WEB-003 | info | An `.htaccess` file sets none of the usual security headers |
| PSC-SRC-001 | critical | Command execution or `eval`, critical when a superglobal is in the same call |
| PSC-SRC-010 | critical | `move_uploaded_file()` keeps the client name or writes into a public directory |
| PSC-SRC-020 | critical | HTML output of a superglobal without `htmlspecialchars` in the same expression |
| PSC-SRC-030 | critical | SQL built by concatenating a superglobal |
| PSC-SRC-040 | critical | `unserialize()` of a superglobal, or any `unserialize()` as a heuristic |
| PSC-SRC-050 | high | `md5()` or `sha1()` of a password-like value |
| PSC-SRC-060 | medium | `rand()`, `mt_rand()`, or `uniqid()` in the same statement as a token |
| PSC-SRC-070 | high | `CURLOPT_SSL_VERIFYPEER` or `verify_peer` set false |
| PSC-SRC-080 | critical | `include` or `require` of `$_GET`, `$_POST`, `$_REQUEST`, or `$_COOKIE` |
| PSC-FILE-001 | critical | Sensitive file or directory inside a document root |
| PSC-SEC-001 | critical | Secret in the working tree, a template, a config assignment, or a document root |
| PSC-FILE-020 | high | World-writable file in a document root. Host profile, Unix only |
| PSC-DEP-001 | medium | `composer audit` could not be completed. Dependencies profile |
| PSC-DEP-002 | critical | `composer audit` advisory. Dependencies profile |
| PSC-LAR-001 | critical | `APP_DEBUG` enabled. Laravel profile |
| PSC-LAR-002 | critical | Default or empty database credentials. Laravel profile |
| PSC-FILE-010 | medium | `vendor/` is not ignored by git. Laravel profile |

Confidence is `confirmed` when a file or directive was read, `likely` when a request value is in the same expression as the sink, and `heuristic` when the pattern is risky and taint was not shown.

`allow_url_fopen` is PHP's default and is not reported. `md5()` of a file checksum is not a password finding. `rand()` by itself is not a token finding.

## What this is not

This is not a taint engine. Psalm, Semgrep, SonarQube, and Progpilot already do inter-procedural analysis, and they need a project they can parse and type. php-sec-check does not compete with them.

`composer audit` runs only on the `dependencies` profile. Git history is out of scope: secrets are read from the working tree and the index. The scan never rewrites the target.

## Config

`php-sec-check init` writes `php-sec-check-config.php`:

```php
return [
    'sensitive_keys' => ['APP_KEY', 'DB_PASSWORD'],
    'profile' => 'legacy',
    'exclude' => ['cache', 'storage/framework'],
    'disabled_rules' => ['PSC-WEB-003'],
];
```

A CLI `--profile`, `--min-severity`, or `--exclude` overrides the file for that run. `sensitive_keys` replaces the default list when the key is present.

## JSON

`--format=json` prints one document:

```json
{
  "summary": {
    "total": 1,
    "critical": 1,
    "high": 0,
    "medium": 0,
    "low": 0,
    "info": 0,
    "hidden": 2,
    "threshold": "high"
  },
  "findings": [
    {
      "ruleId": "PSC-SRC-080",
      "severity": "critical",
      "confidence": "likely",
      "title": "include uses $_GET in index.php:12. The request chooses which file PHP loads.",
      "message": "include uses $_GET in index.php:12. The request chooses which file PHP loads.",
      "recommendation": "Include a fixed file. If a page name has to vary, map it through an allow-list the application owns.",
      "path": "index.php",
      "line": 12,
      "check": "IncludeRequestCheck"
    }
  ]
}
```

## Programmatic use

```php
use Aquilinoflores\PhpSecCheck\Config\ScanOptions;
use Aquilinoflores\PhpSecCheck\Scan\ProjectScanner;

$findings = (new ProjectScanner())->scan('/path/to/project', new ScanOptions(
    profile: 'legacy',
    minSeverity: 'high',
));
```

`ProjectScanner::scan()` returns every finding. The CLI applies the threshold when it prints. Each check implements `CheckInterface` and returns `Issue` objects, which are `Finding` objects.

## Tests

```bash
composer install
composer test
```

PHPUnit 11. CI runs PHP 8.2, 8.3, and 8.4.

## License

MIT. See [LICENSE](LICENSE).
