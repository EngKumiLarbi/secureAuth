<?php
/**
 * Temporary deployment helper: imports schema.sql into the configured DB.
 * Open with ?token=<ADMIN_SETUP_TOKEN or APP_PEPPER>. Delete after use.
 */
declare(strict_types=1);

require_once __DIR__ . '/db_connect.php';

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
    echo "Forbidden.\nOpen install_schema.php?token=<ADMIN_SETUP_TOKEN or APP_PEPPER>\n";
    exit;
}

$sqlFile = __DIR__ . '/schema.sql';
if (!is_file($sqlFile)) {
    echo "schema.sql is missing.\n";
    exit;
}

$sql = file_get_contents($sqlFile);
if ($sql === false) {
    echo "Could not read schema.sql.\n";
    exit;
}

// Only whole-line comments are present in schema.sql.
$sql = (string)preg_replace('/^\s*--.*$/m', '', $sql);
$statements = array_filter(
    array_map('trim', preg_split('/;\s*(?:\r?\n|$)/', $sql) ?: []),
    static fn(string $statement): bool => $statement !== ''
);

try {
    $conn = db_connect();
} catch (mysqli_sql_exception $e) {
    echo 'Database connection failed: ' . $e->getMessage() . "\n";
    exit;
}

foreach ($statements as $statement) {
    $summary = preg_replace('/\s+/', ' ', $statement) ?: $statement;
    try {
        $conn->query($statement);
        echo 'OK: ' . mb_substr($summary, 0, 80) . "\n";
    } catch (mysqli_sql_exception $e) {
        echo 'FAILED: ' . $e->getMessage() . ' | ' . mb_substr($summary, 0, 80) . "\n";
    }
}

$result = $conn->query('SHOW TABLES');
$tables = array_column($result->fetch_all(MYSQLI_NUM), 0);
echo "\nTables now: " . ($tables ? implode(', ', $tables) : '(none)') . "\n";
$conn->close();
