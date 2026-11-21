<?php
// filepath: c:\xampp\htdocs\SecuredAuth\db.php
declare(strict_types=1);

require_once __DIR__ . '/db_connect.php';

try {
    $conn = db_connect();
} catch (mysqli_sql_exception $e) {
    // Diagnostic snapshot: never log the password, but record which variables
    // PHP could actually see so deployment config problems are identifiable.
    $visibility = static function (string $key): string {
        if (isset($_ENV[$key])) {
            return '$_ENV';
        }
        if (isset($_SERVER[$key])) {
            return '$_SERVER';
        }
        if (getenv($key) !== false) {
            return 'getenv';
        }
        return 'missing';
    };
    $setState = static function (string $key): string {
        $value = envValue($key, null);
        return ($value === null || $value === '') ? 'missing' : 'set';
    };
    $keys = [
        'DB_HOST',
        'DB_PORT',
        'DB_NAME',
        'DB_USERNAME',
        'DB_PASSWORD',
        'DB_SSL',
        'DB_SSL_CA',
    ];

    $values = [];
    $sources = [];
    foreach ($keys as $key) {
        $values[] = $key . '=' . $setState($key);
        $sources[] = $key . '=' . $visibility($key);
    }

    error_log(sprintf(
        'Database connection error: %s (code %s) | target=%s:%s db=%s user=%s | '
        . 'values: %s | sources: %s',
        $e->getMessage(),
        $e->getCode(),
        envValue('DB_HOST', '127.0.0.1'),
        envValue('DB_PORT', '3306'),
        envValue('DB_NAME', 'secured_auth'),
        envValue('DB_USERNAME', 'root'),
        implode(' ', $values),
        implode(' ', $sources)
    ));

    http_response_code(500);
    exit('Database connection failed. Please check the server configuration.');
}
