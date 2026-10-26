<?php
declare(strict_types=1);

require_once __DIR__ . '/bootstrap.php';
requireApiMethod('POST');

$conn = apiDatabase();
$data = apiReadJson();

$username = trim((string)($data['username'] ?? ''));
$code = trim((string)($data['code'] ?? ''));

if (
    $username === '' ||
    !preg_match('/^\d{6}$/', $code)
) {
    apiResponse(400, [
        'success' => false,
        'message' => 'Enter your username and six-digit verification code.'
    ]);
}

try {
    $conn->begin_transaction();

    $stmt = $conn->prepare(
        'SELECT o.id, o.user_id, o.code_hash, o.expires_at, o.attempts,
                u.username, u.email, u.role, u.account_status
         FROM mobile_login_otps o
         INNER JOIN users u ON u.id = o.user_id
         WHERE u.username = ?
         ORDER BY o.id DESC
         LIMIT 1
         FOR UPDATE'
    );

    $stmt->bind_param('s', $username);
    $stmt->execute();
    $otp = $stmt->get_result()->fetch_assoc();
    $stmt->close();

    if (!$otp) {
        $conn->rollback();
        apiResponse(401, [
            'success' => false,
            'message' => 'The code is invalid or has expired. Sign in again to request a new code.'
        ]);
    }

    $otpId = (int)$otp['id'];
    $userId = (int)$otp['user_id'];

    if (
        strtotime((string)$otp['expires_at']) <= time() ||
        (int)$otp['attempts'] >= 5
    ) {
        $stmt = $conn->prepare(
            'DELETE FROM mobile_login_otps WHERE id = ?'
        );
        $stmt->bind_param('i', $otpId);
        $stmt->execute();
        $stmt->close();
        $conn->commit();

        apiResponse(401, [
            'success' => false,
            'message' => 'The code has expired or too many attempts were made. Sign in again to request a new code.'
        ]);
    }

    if (!hash_equals((string)$otp['code_hash'], hash('sha256', $code))) {
        $stmt = $conn->prepare(
            'UPDATE mobile_login_otps SET attempts = attempts + 1 WHERE id = ?'
        );
        $stmt->bind_param('i', $otpId);
        $stmt->execute();
        $stmt->close();
        $conn->commit();

        apiResponse(401, [
            'success' => false,
            'message' => 'Incorrect verification code.'
        ]);
    }

    if ((string)$otp['account_status'] !== 'active') {
        $conn->rollback();
        apiResponse(403, [
            'success' => false,
            'message' => 'This account is not active.'
        ]);
    }

    // Map only existing website roles here. Hospital roles need a
    // deliberate account/role migration before hospital access is granted.
    $role = strtolower(trim((string)$otp['role']));
    if ($role === 'user') {
        $role = 'candidate';
    }

    if (!in_array($role, ['candidate', 'manager', 'admin'], true)) {
        $conn->rollback();
        apiResponse(403, [
            'success' => false,
            'message' => 'This account role is not authorized.'
        ]);
    }

    // Create a high-entropy bearer token; store only its SHA-256 hash.
    $token = bin2hex(random_bytes(32));
    $tokenHash = hash('sha256', $token);
    $expiresAt = date('Y-m-d H:i:s', time() + 60 * 60 * 24 * 7);

    $stmt = $conn->prepare(
        'INSERT INTO mobile_api_tokens (user_id, token_hash, expires_at)
         VALUES (?, ?, ?)'
    );
    $stmt->bind_param('iss', $userId, $tokenHash, $expiresAt);
    $stmt->execute();
    $stmt->close();

    // Consume the OTP so it cannot be reused.
    $stmt = $conn->prepare(
        'DELETE FROM mobile_login_otps WHERE id = ?'
    );
    $stmt->bind_param('i', $otpId);
    $stmt->execute();
    $stmt->close();

    $conn->commit();

    apiResponse(200, [
        'success' => true,
        'message' => 'Verification successful.',
        'token' => $token,
        'expires_at' => $expiresAt,
        'user' => [
            'id' => $userId,
            'username' => (string)$otp['username'],
            'email' => (string)$otp['email'],
            'role' => $role
        ]
    ]);

} catch (Throwable $e) {
    try {
        $conn->rollback();
    } catch (Throwable $ignored) {
        // The transaction may already be closed.
    }

    error_log('CarePoint OTP verification error: ' . $e->getMessage());

    apiResponse(500, [
        'success' => false,
        'message' => 'Unable to verify the code right now.'
    ]);
}