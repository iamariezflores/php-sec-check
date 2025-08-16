# PHP Security Check (php-sec-check)

A lightweight CLI tool to **scan PHP and Laravel projects for common security risks**.  
Runs as `vendor/bin/sec-check` after installation via Composer.

---

## ✨ Features

- ✅ **Generic PHP Checks**
  - PHP version check
  - Detect if `display_errors` is enabled
  - Dangerous function detection (`exec`, `shell_exec`, `system`, `eval`, etc.)
  - Composer dependency audit (`composer audit`)

- 🚀 **Laravel-Specific Checks**
  - Auto-detects Laravel projects
  - Scans `.env` for sensitive credentials
  - Warns if `vendor/` is **committed to Git**

- ⚙️ **Configurable**
  - Creates a `php-sec-check-config.php` file on first run
  - Add your **own sensitive keys** for `.env` scanning
  - Example:
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

## 📦 Installation

Require it via Composer (recommended for dev):

```bash
composer require iamariezflores/php-sec-check --dev
```

## 📖 Usage

### Run the scanner
```bash
vendor/bin/sec-check
```

### Example output

```bash
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
...

Laravel project detected!
[WARNING] Sensitive key 'APP_KEY' found in .env!
[WARNING] vendor/ directory exists and is not ignored in .gitignore!
Scan complete.
```
## 🔧 Advanced Usage

### Custom Keys via Config
After the first run, edit `php-sec-check-config.php` in your project root to add new sensitive keys.

### Custom Keys via Code (Laravel)
You can also inject custom keys programmatically:

```php
use Aquilinoflores\PhpSecCheck\Checks\Laravel\EnvCredentialsCheck;

Route::get('/test-security', function () {
    $customKeys = ['CUSTOM_SECRET', 'ANOTHER_KEY'];
    $envCheck = new EnvCredentialsCheck($customKeys);
    return json_encode($envCheck->run(base_path()));
});
```
## 🤝 Contributing

Contributions are welcome!  

1. Fork the repo  
2. Create your feature branch:  
3. Commit your changes.
4. Push to the branch.
5. Create a Pull request.
6. Please ensure new checks follow the modular structure in src/Checks/.




