<?php
declare(strict_types=1);

session_start();

function endSessionAndRedirect(): never
{
    $_SESSION = [];

    if (ini_get('session.use_cookies')) {
        $cookie = session_get_cookie_params();

        setcookie(session_name(), '', [
            'expires'  => time() - 42000,
            'path'     => $cookie['path'],
            'domain'   => $cookie['domain'],
            'secure'   => $cookie['secure'],
            'httponly' => $cookie['httponly'],
            'samesite' => $cookie['samesite'] ?? 'Lax',
        ]);
    }

    session_destroy();
    header('Location: login.php');
    exit;
}

// Require an administrator who has completed 2FA.
if (
    !isset($_SESSION['user_id'], $_SESSION['username']) ||
    strtolower((string)($_SESSION['role'] ?? '')) !== 'admin' ||
    ($_SESSION['two_factor_verified'] ?? false) !== true
) {
    endSessionAndRedirect();
}

require_once __DIR__ . '/db.php';

$adminId = (int)$_SESSION['user_id'];

// Verify the administrator is still active and authorized.
try {
    $auth = $conn->prepare(
        'SELECT username, role, account_status
         FROM users WHERE id = ? LIMIT 1'
    );
    $auth->bind_param('i', $adminId);
    $auth->execute();
    $admin = $auth->get_result()->fetch_assoc();
    $auth->close();

    if (
        !$admin ||
        strtolower((string)$admin['role']) !== 'admin' ||
        strtolower((string)$admin['account_status']) !== 'active'
    ) {
        endSessionAndRedirect();
    }

    $_SESSION['username'] = $admin['username'];
} catch (Throwable $ex) {
    error_log('Disable-user authorization error: ' . $ex->getMessage());
    http_response_code(500);
    exit('Unable to verify your administrator account.');
}

// Account changes must use POST.
if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    header('Allow: POST');
    http_response_code(405);
    exit('Use the account management page to perform this action.');
}

// Validate the CSRF token.
$token = $_POST['csrf_token'] ?? '';

if (
    !is_string($token) ||
    !hash_equals((string)($_SESSION['csrf_token'] ?? ''), $token)
) {
    http_response_code(403);
    exit('Security check failed. Return to the users page and try again.');
}

$targetId = filter_input(INPUT_POST, 'id', FILTER_VALIDATE_INT);

if (!$targetId || $targetId < 1) {
    http_response_code(400);
    exit('Invalid user ID.');
}

if ($targetId === $adminId) {
    http_response_code(403);
    exit('You cannot disable your own administrator account.');
}

try {
    $conn->begin_transaction();

    // Lock the target record while changing its status.
    $stmt = $conn->prepare(
        'SELECT id, username, role, account_status
         FROM users WHERE id = ? FOR UPDATE'
    );
    $stmt->bind_param('i', $targetId);
    $stmt->execute();
    $target = $stmt->get_result()->fetch_assoc();
    $stmt->close();

    if (!$target) {
        throw new RuntimeException('User account not found.');
    }

    $oldStatus = strtolower((string)$target['account_status']);

    if ($oldStatus === 'disabled') {
        throw new RuntimeException('This account is already disabled.');
    }

    $newStatus = 'disabled';

    $stmt = $conn->prepare(
        'UPDATE users SET account_status = ? WHERE id = ?'
    );
    $stmt->bind_param('si', $newStatus, $targetId);
    $stmt->execute();
    $stmt->close();

    // Record who disabled the account and when.
    $actorUsername = (string)$_SESSION['username'];
    $targetUsername = (string)$target['username'];
    $action = 'USER_DISABLED';
    $details = 'Account status changed from ' . $oldStatus . ' to disabled.';

    $stmt = $conn->prepare(
        'INSERT INTO audit_logs
            (actor_user_id, actor_username, action,
             target_user_id, target_username, details)
         VALUES (?, ?, ?, ?, ?, ?)'
    );

    $stmt->bind_param(
        'ississ',
        $adminId,
        $actorUsername,
        $action,
        $targetId,
        $targetUsername,
        $details
    );
    $stmt->execute();
    $stmt->close();

    // Both the status change and audit record must succeed.
    $conn->commit();

    header('Location: manage_users.php?message=disabled');
    exit;

} catch (Throwable $ex) {
    try {
        $conn->rollback();
    } catch (Throwable $rollbackError) {
        error_log('Disable-user rollback failed: ' . $rollbackError->getMessage());
    }

    error_log('Account disable failed: ' . $ex->getMessage());

    if ($ex instanceof RuntimeException) {
        http_response_code(409);
        exit(eSafeMessage($ex->getMessage()));
    }

    http_response_code(500);
    exit('Unable to disable the account. Check the application error log.');
}

function eSafeMessage(string $message): string
{
    return htmlspecialchars($message, ENT_QUOTES, 'UTF-8');
}