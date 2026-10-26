<?php
declare(strict_types=1);

require_once __DIR__ . '/bootstrap.php';
requireApiMethod('GET');

$conn = apiDatabase();

$authorization = $_SERVER['HTTP_AUTHORIZATION'] ?? '';

if (!preg_match('/^Bearer\s+([a-f0-9]{64})$/i', $authorization, $matches)) {
    apiResponse(401, [
        'success' => false,
        'message' => 'A valid authentication token is required.'
    ]);
}

$tokenHash = hash('sha256', $matches[1]);

try {
    $stmt = $conn->prepare(
        'SELECT u.id, u.username, u.email, u.full_name, u.role,
                u.account_status, t.expires_at
         FROM mobile_api_tokens t
         INNER JOIN users u ON u.id = t.user_id
         WHERE t.token_hash = ?
         LIMIT 1'
    );

    $stmt->bind_param('s', $tokenHash);
    $stmt->execute();
    $user = $stmt->get_result()->fetch_assoc();
    $stmt->close();

    if (
        !$user ||
        strtotime((string)$user['expires_at']) <= time() ||
        (string)$user['account_status'] !== 'active'
    ) {
        apiResponse(401, [
            'success' => false,
            'message' => 'Your session is invalid or expired. Please sign in again.'
        ]);
    }

    $role = strtolower(trim((string)$user['role']));

    if ($role === 'user') {
        $role = 'candidate';
    }

    apiResponse(200, [
        'success' => true,
        'user' => [
            'id' => (int)$user['id'],
            'username' => (string)$user['username'],
            'email' => (string)$user['email'],
            'full_name' => (string)($user['full_name'] ?? ''),
            'role' => $role
        ]
    ]);

} catch (Throwable $e) {
    error_log('CarePoint profile API error: ' . $e->getMessage());

    apiResponse(500, [
        'success' => false,
        'message' => 'Unable to retrieve your profile.'
    ]);
}