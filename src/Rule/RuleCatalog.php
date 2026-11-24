<?php

namespace Aquilinoflores\PhpSecCheck\Rule;

/**
 * Stable ids for `php-sec-check rules`.
 */
final class RuleCatalog
{
    /**
     * @return list<array{id: string, severity: string, summary: string}>
     */
    public static function all(): array
    {
        return [
            ['id' => 'PSC-RUN-001', 'severity' => 'critical', 'summary' => 'PHP branch is past security support, or nearing it, or the scanner PHP differs from a pin.'],
            ['id' => 'PSC-RUN-010', 'severity' => 'medium', 'summary' => 'display_errors is enabled in .user.ini, .htaccess, or ini_set().'],
            ['id' => 'PSC-RUN-011', 'severity' => 'critical', 'summary' => 'allow_url_include is enabled in the project configuration.'],
            ['id' => 'PSC-RUN-012', 'severity' => 'low', 'summary' => 'expose_php is enabled in the project configuration.'],
            ['id' => 'PSC-RUN-020', 'severity' => 'medium', 'summary' => 'The project sets disable_functions and leaves out a shell-execution function.'],
            ['id' => 'PSC-RUN-030', 'severity' => 'critical', 'summary' => 'Session ini written by the project allows session ids in URLs or a weak session id.'],
            ['id' => 'PSC-RUN-040', 'severity' => 'critical', 'summary' => 'Cookie Secure, HttpOnly, or SameSite is missing on setcookie() or in project session config.'],
            ['id' => 'PSC-WEB-001', 'severity' => 'high', 'summary' => 'Apache Options Indexes is enabled.'],
            ['id' => 'PSC-WEB-002', 'severity' => 'medium', 'summary' => 'An .htaccess file does not deny .env, .git, or .sql.'],
            ['id' => 'PSC-WEB-003', 'severity' => 'info', 'summary' => 'An .htaccess file does not set common security headers.'],
            ['id' => 'PSC-SRC-001', 'severity' => 'critical', 'summary' => 'Command execution or eval, critical when a superglobal is in the same call.'],
            ['id' => 'PSC-SRC-010', 'severity' => 'critical', 'summary' => 'move_uploaded_file() keeps the client name or writes into a public directory.'],
            ['id' => 'PSC-SRC-020', 'severity' => 'critical', 'summary' => 'HTML output of a superglobal without htmlspecialchars in the same expression.'],
            ['id' => 'PSC-SRC-030', 'severity' => 'critical', 'summary' => 'SQL built by concatenating a superglobal in the same expression.'],
            ['id' => 'PSC-SRC-040', 'severity' => 'critical', 'summary' => 'unserialize() of a superglobal, or any unserialize() as a heuristic.'],
            ['id' => 'PSC-SRC-050', 'severity' => 'high', 'summary' => 'md5() or sha1() of a password-like value.'],
            ['id' => 'PSC-SRC-060', 'severity' => 'medium', 'summary' => 'rand(), mt_rand(), or uniqid() used to build a token in the same statement.'],
            ['id' => 'PSC-SRC-070', 'severity' => 'high', 'summary' => 'TLS certificate verification disabled on curl or a stream context.'],
            ['id' => 'PSC-SRC-080', 'severity' => 'critical', 'summary' => 'include or require of a request superglobal in the same expression.'],
            ['id' => 'PSC-FILE-001', 'severity' => 'critical', 'summary' => 'Sensitive file or directory inside a document root.'],
            ['id' => 'PSC-FILE-010', 'severity' => 'medium', 'summary' => 'vendor/ is not ignored by git. Laravel profile only.'],
            ['id' => 'PSC-FILE-020', 'severity' => 'high', 'summary' => 'World-writable file in a document root. Host profile, Unix only.'],
            ['id' => 'PSC-SEC-001', 'severity' => 'critical', 'summary' => 'Secret tracked, copied into a template, hardcoded, or left in a document root.'],
            ['id' => 'PSC-DEP-001', 'severity' => 'medium', 'summary' => 'composer audit could not be completed. Dependencies profile only.'],
            ['id' => 'PSC-DEP-002', 'severity' => 'critical', 'summary' => 'composer audit reported an advisory. Dependencies profile only.'],
            ['id' => 'PSC-LAR-001', 'severity' => 'critical', 'summary' => 'APP_DEBUG is enabled. Laravel profile only.'],
            ['id' => 'PSC-LAR-002', 'severity' => 'critical', 'summary' => 'Default or empty database credentials. Laravel profile only.'],
        ];
    }
}
