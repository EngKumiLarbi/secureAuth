<?php
// filepath: c:\xampp\htdocs\SecuredAuth\db.php
declare(strict_types=1);

require_once __DIR__ . '/config.php';

$host = envValue('DB_HOST', '127.0.0.1');
$port = (int) envValue('DB_PORT', '3306');
$database = envValue('DB_NAME', 'secured_auth');
$username = envValue('DB_USERNAME', 'root');
$password = envValue('DB_PASSWORD', '');

mysqli_report(MYSQLI_REPORT_ERROR | MYSQLI_REPORT_STRICT);

try {
    $conn = new mysqli($host, $username, $password, $database, $port);
    $conn->set_charset('utf8mb4');
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

    error_log(sprintf(
        'Database connection error: %s (code %s) | target=%s:%s db=%s user=%s | '
        . 'values: DB_HOST=%s DB_PORT=%s DB_NAME=%s DB_USERNAME=%s DB_PASSWORD=%s | '
        . 'sources: DB_HOST=%s DB_PORT=%s DB_NAME=%s DB_USERNAME=%s DB_PASSWORD=%s',
        $e->getMessage(),
        $e->getCode(),
        $host,
        $port,
        $database,
        $username,
        $setState('DB_HOST'),
        $setState('DB_PORT'),
        $setState('DB_NAME'),
        $setState('DB_USERNAME'),
        $setState('DB_PASSWORD'),
        $visibility('DB_HOST'),
        $visibility('DB_PORT'),
        $visibility('DB_NAME'),
        $visibility('DB_USERNAME'),
        $visibility('DB_PASSWORD')
    ));

    http_response_code(500);
    exit('Database connection failed. Please check the server configuration.');
}