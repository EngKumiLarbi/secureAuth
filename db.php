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
    error_log('Database connection error: ' . $e->getMessage());
    http_response_code(500);
    exit('Database connection failed. Please check the server configuration.');
}