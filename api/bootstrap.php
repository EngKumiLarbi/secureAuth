<?php
declare(strict_types=1);

header('Content-Type: application/json; charset=utf-8');
header('Cache-Control: no-store');
header('X-Content-Type-Options: nosniff');

function apiResponse(int $status, array $data): never
{
    http_response_code($status);
    echo json_encode($data, JSON_UNESCAPED_SLASHES);
    exit;
}

function requireApiMethod(string $method): void
{
    if (($_SERVER['REQUEST_METHOD'] ?? '') !== $method) {
        header('Allow: ' . $method);
        apiResponse(405, [
            'success' => false,
            'message' => 'Method not allowed.'
        ]);
    }
}

function apiDatabase(): mysqli
{
    // Load the existing database connection from the main project.
    require_once dirname(__DIR__) . '/db.php';

    if (!isset($conn) || !($conn instanceof mysqli)) {
        apiResponse(500, [
            'success' => false,
            'message' => 'Database connection is unavailable.'
        ]);
    }

    return $conn;
}

function apiReadJson(): array
{
    $raw = file_get_contents('php://input');

    if ($raw === false || trim($raw) === '') {
        apiResponse(400, [
            'success' => false,
            'message' => 'A JSON request body is required.'
        ]);
    }

    $data = json_decode($raw, true);

    if (!is_array($data)) {
        apiResponse(400, [
            'success' => false,
            'message' => 'Invalid JSON request.'
        ]);
    }

    return $data;
}