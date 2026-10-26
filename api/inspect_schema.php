<?php
declare(strict_types=1);

require_once __DIR__ . '/bootstrap.php';

requireApiMethod('GET');

$conn = apiDatabase();

try {
    $result = $conn->query("SHOW COLUMNS FROM users");
    $columns = [];

    while ($row = $result->fetch_assoc()) {
        $columns[] = [
            'field' => $row['Field'],
            'type' => $row['Type'],
            'nullable' => $row['Null'],
            'key' => $row['Key'],
            'default' => $row['Default']
        ];
    }

    $result->free();

    if (!$columns) {
        apiResponse(500, [
            'success' => false,
            'message' => 'The users table has no visible columns.'
        ]);
    }

    apiResponse(200, [
        'success' => true,
        'table' => 'users',
        'columns' => $columns
    ]);
} catch (Throwable $e) {
    error_log('CarePoint schema inspection failed: ' . $e->getMessage());

    apiResponse(500, [
        'success' => false,
        'message' => 'Could not inspect the users table.'
    ]);
}