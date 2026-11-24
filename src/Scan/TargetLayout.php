<?php

namespace Aquilinoflores\PhpSecCheck\Scan;

/**
 * Document roots for a traditional PHP application.
 *
 * `public/` is always a document root when the directory exists.
 * The other names are document roots when they contain index.php or .htaccess,
 * so a folder of templates named html/ is not treated as the web root.
 * The project root is a document root when index.php is there and no named
 * web directory has its own index.php.
 */
final class TargetLayout
{
    /** @var list<string> */
    public const NAMES = [
        'public',
        'public_html',
        'www',
        'web',
        'html',
        'htdocs',
        'httpdocs',
        'webroot',
    ];

    /**
     * @return array<string, string> project-relative directory => absolute path
     */
    public static function documentRoots(string $projectRoot): array
    {
        if ($projectRoot === '' || !is_dir($projectRoot)) {
            return [];
        }

        $root  = rtrim(str_replace('\\', '/', $projectRoot), '/');
        $roots = [];
        $namedIndex = false;

        foreach (self::NAMES as $name) {
            $absolute = $root . '/' . $name;
            if (!is_dir($absolute)) {
                continue;
            }

            $hasIndex = is_file($absolute . '/index.php');
            $hasAccess = is_file($absolute . '/.htaccess');
            if ($name !== 'public' && !$hasIndex && !$hasAccess) {
                continue;
            }

            $roots[$name] = $absolute;
            if ($hasIndex) {
                $namedIndex = true;
            }
        }

        $rootIndex = is_file($root . '/index.php');
        if ($rootIndex && !$namedIndex) {
            $roots[''] = $root;
        }

        return $roots;
    }
}
