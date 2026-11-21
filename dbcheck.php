<?php
/**
 * Temporary deployment diagnostic.
 *
 * Open in a browser with ?token=<ADMIN_SETUP_TOKEN or APP_PEPPER>.
 * It never prints DB_PASSWORD or any other secret value. Delete this file
 * once the database connection is working.
 */
declare(strict_types=1);

require_once __DIR__ . '/config.php';

header('Content-Type: text/plain; charset=utf-8');

$provided = (string)($_GET['token'] ?? '');
$accepted = false;

foreach (['ADMIN_SETUP_TOKEN', 'APP_PEPPER'] as $secretKey) {
    $secret = envValue($secretKey, '');
    if ($secret !== '' && $provided !== '' && hash_equals((string)$secret, $provided)) {
        $accepted = true;
        break;
    }
}

if (!$accepted) {
    http_response_code(403);
    echo "Forbidden.\nOpen dbcheck.php?token=<ADMIN_SETUP_TOKEN or APP_PEPPER>\n";
    exit;
}

echo 'PHP ' . PHP_VERSION . ' (' . PHP_SAPI . ")\n\n";

echo "Environment visibility (values hidden):\n";
foreach (['DB_HOST', 'DB_PORT', 'DB_NAME', 'DB_USERNAME', 'DB_PASSWORD'] as $key) {
    $value = envValue($key, null);
    $state = ($value === null || $value === '') ? 'MISSING' : 'set';
    $source = isset($_ENV[$key])
        ? '$_ENV'
        : (isset($_SERVER[$key])
            ? '$_SERVER'
            : (getenv($key) !== false ? 'getenv' : '-'));
    printf("  %-14s %-8s %s\n", $key, $state, $source);
}

$host = envValue('DB_HOST', '127.0.0.1');
$port = (int)envValue('DB_PORT', '3306');
$database = envValue('DB_NAME', 'secured_auth');
$username = envValue('DB_USERNAME', 'root');

echo "\nEffective config (non-secret values):\n";
echo "  host=$host port=$port database=$database user=$username\n\n";

$socket = @fsockopen($host, $port, $errno, $errstr, 5);
if ($socket) {
    fclose($socket);
    echo "TCP connect $host:$port: OK\n";
} else {
    echo "TCP connect $host:$port: FAILED ($errno: $errstr)\n";
}

mysqli_report(MYSQLI_REPORT_ERROR | MYSQLI_REPORT_STRICT);
try {
    $conn = new mysqli($host, $username, envValue('DB_PASSWORD', ''), $database, $port);
    $conn->set_charset('utf8mb4');
    echo "MySQL login: OK\n";
    $result = $conn->query('SHOW TABLES');
    $tables = array_column($result->fetch_all(MYSQLI_NUM), 0);
    echo 'Tables: ' . ($tables ? implode(', ', $tables) : '(none - schema not imported)') . "\n";
    $conn->close();
} catch (mysqli_sql_exception $e) {
    echo 'MySQL login: FAILED (' . $e->getCode() . ') ' . $e->getMessage() . "\n";
}
