<?php
declare(strict_types=1);

session_start();

function e($value): string
{
    return htmlspecialchars((string)($value ?? ''), ENT_QUOTES, 'UTF-8');
}

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

// Require a logged-in administrator who completed 2FA.
if (
    !isset($_SESSION['user_id'], $_SESSION['username']) ||
    strtolower((string)($_SESSION['role'] ?? '')) !== 'admin' ||
    ($_SESSION['two_factor_verified'] ?? false) !== true
) {
    endSessionAndRedirect();
}

require_once __DIR__ . '/db.php';

$adminId = (int)$_SESSION['user_id'];

// Verify the administrator's current role and status in the database.
try {
    $auth = $conn->prepare(
        "SELECT username, role, account_status
         FROM users WHERE id = ? LIMIT 1"
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
    error_log('Edit user authentication error: ' . $ex->getMessage());
    http_response_code(500);
    exit('Unable to verify your administrator account. Please try again later.');
}

if (empty($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}

$adminId = (int)$_SESSION['user_id'];
$userId = filter_input(INPUT_GET, 'id', FILTER_VALIDATE_INT);
$message = '';
$error = '';

$roles = ['admin', 'manager', 'candidate'];
$statuses = ['active', 'pending', 'disabled'];

if (!$userId || $userId < 1) {
    http_response_code(400);
    exit('Invalid user ID.');
}

// Load the target user.
try {
    $stmt = $conn->prepare(
        'SELECT id, full_name, username, email, role, account_status
         FROM users WHERE id = ? LIMIT 1'
    );
    $stmt->bind_param('i', $userId);
    $stmt->execute();
    $user = $stmt->get_result()->fetch_assoc();
    $stmt->close();
} catch (Throwable $ex) {
    error_log('Edit user lookup error: ' . $ex->getMessage());
    http_response_code(500);
    exit('Unable to load this account.');
}

if (!$user) {
    http_response_code(404);
    exit('User not found.');
}

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $postedId = filter_input(INPUT_POST, 'id', FILTER_VALIDATE_INT);
    $token = $_POST['csrf_token'] ?? '';

    if (!$postedId || $postedId !== $userId) {
        $error = 'Invalid user ID.';
    } elseif (
        !is_string($token) ||
        !hash_equals((string)$_SESSION['csrf_token'], $token)
    ) {
        $error = 'Security check failed. Refresh the page and try again.';
    } else {
        $fullName = trim((string)($_POST['full_name'] ?? ''));
        $email = trim((string)($_POST['email'] ?? ''));
        $role = strtolower(trim((string)($_POST['role'] ?? '')));
        $status = strtolower(trim((string)($_POST['account_status'] ?? '')));

        // Do not allow the administrator to change their own role or status.
        if ($postedId === $adminId) {
            $role = 'admin';
            $status = (string)$user['account_status'];
        }

        if ($fullName === '' || strlen($fullName) > 150) {
            $error = 'Enter a full name of no more than 150 characters.';
        } elseif (
            !filter_var($email, FILTER_VALIDATE_EMAIL) ||
            strlen($email) > 254
        ) {
            $error = 'Enter a valid email address.';
        } elseif (!in_array($role, $roles, true)) {
            $error = 'Select a valid role.';
        } elseif (!in_array($status, $statuses, true)) {
            $error = 'Select a valid account status.';
        } else {
            try {
                // Check that no other account uses this email.
                $check = $conn->prepare(
                    'SELECT id FROM users
                     WHERE email = ? AND id <> ? LIMIT 1'
                );
                $check->bind_param('si', $email, $postedId);
                $check->execute();
                $duplicate = $check->get_result()->fetch_assoc();
                $check->close();

                if ($duplicate) {
                    $error = 'That email address is already in use.';
                } else {
                    $conn->begin_transaction();

                    try {
                        // Lock the target record before changing it.
                        $lock = $conn->prepare(
                            'SELECT id FROM users WHERE id = ? FOR UPDATE'
                        );
                        $lock->bind_param('i', $postedId);
                        $lock->execute();
                        $target = $lock->get_result()->fetch_assoc();
                        $lock->close();

                        if (!$target) {
                            throw new RuntimeException('Target account not found.');
                        }

                        $update = $conn->prepare(
                            'UPDATE users
                             SET full_name = ?, email = ?, role = ?,
                                 account_status = ?
                             WHERE id = ?'
                        );
                        $update->bind_param(
                            'ssssi',
                            $fullName,
                            $email,
                            $role,
                            $status,
                            $postedId
                        );
                        $update->execute();
                        $update->close();

                        // Record the administrator's change when audit_logs exists.
                        $audit = $conn->prepare(
                            "INSERT INTO audit_logs
                                (actor_user_id, actor_username, action,
                                 target_user_id, target_username, details)
                             VALUES (?, ?, 'USER_UPDATED', ?, ?, ?)"
                        );

                        $actorUsername = (string)$_SESSION['username'];
                        $targetUsername = (string)$user['username'];
                        $details = 'Updated full name, email, role, and/or account status.';

                        $audit->bind_param(
                            'isiss',
                            $adminId,
                            $actorUsername,
                            $postedId,
                            $targetUsername,
                            $details
                        );
                        $audit->execute();
                        $audit->close();

                        $conn->commit();

                        // Refresh the displayed user data.
                        $stmt = $conn->prepare(
                            'SELECT id, full_name, username, email, role, account_status
                             FROM users WHERE id = ? LIMIT 1'
                        );
                        $stmt->bind_param('i', $userId);
                        $stmt->execute();
                        $user = $stmt->get_result()->fetch_assoc();
                        $stmt->close();

                        $message = 'User account updated successfully.';
                    } catch (Throwable $ex) {
                        $conn->rollback();
                        throw $ex;
                    }
                }
            } catch (Throwable $ex) {
                error_log('User update failed: ' . $ex->getMessage());

                if ($error === '') {
                    $error = 'Unable to update this account. Check the database and audit log table.';
                }
            }
        }
    }
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Edit User | SecuredAuth</title>
<style>
* { box-sizing: border-box; }

body {
    margin: 0;
    padding: 24px;
    background: #f1f5f9;
    font-family: Arial, sans-serif;
    color: #172033;
}

main {
    max-width: 650px;
    margin: 20px auto;
    background: white;
    padding: 26px;
    border-radius: 12px;
    box-shadow: 0 4px 16px #0000000b;
}

h1 { margin-top: 0; }

label {
    display: block;
    font-weight: bold;
    margin: 17px 0 7px;
}

input, select {
    width: 100%;
    padding: 12px;
    border: 1px solid #cbd5e1;
    border-radius: 7px;
    font-size: 15px;
}

button {
    margin-top: 22px;
    padding: 12px 18px;
    background: #1d4ed8;
    color: white;
    border: 0;
    border-radius: 7px;
    cursor: pointer;
}

a { color: #1d4ed8; }

.notice, .error {
    padding: 12px;
    border-radius: 7px;
    margin: 14px 0;
}

.notice { background: #dcfce7; color: #166534; }
.error { background: #fee2e2; color: #991b1b; }

small { color: #64748b; }
</style>
</head>
<body>
<main>
    <h1>Edit User Account</h1>
    <p>Username: <strong><?= e($user['username']) ?></strong></p>
    <p>User ID: <?= (int)$user['id'] ?></p>

    <?php if ($message !== ''): ?>
        <div class="notice"><?= e($message) ?></div>
    <?php endif; ?>

    <?php if ($error !== ''): ?>
        <div class="error"><?= e($error) ?></div>
    <?php endif; ?>

    <form method="POST" action="edit_user.php?id=<?= (int)$user['id'] ?>">
        <input type="hidden" name="id" value="<?= (int)$user['id'] ?>">
        <input type="hidden" name="csrf_token"
               value="<?= e($_SESSION['csrf_token']) ?>">

        <label for="full_name">Full Name</label>
        <input id="full_name" name="full_name" maxlength="150" required
               value="<?= e($user['full_name']) ?>">

        <label for="email">Email Address</label>
        <input id="email" type="email" name="email" maxlength="254" required
               value="<?= e($user['email']) ?>">

        <label for="role">Role</label>
        <select id="role" name="role" required
            <?= (int)$user['id'] === $adminId ? 'disabled' : '' ?>>
            <?php foreach ($roles as $role): ?>
                <option value="<?= e($role) ?>"
                    <?= strtolower((string)$user['role']) === $role ? 'selected' : '' ?>>
                    <?= e(ucfirst($role)) ?>
                </option>
            <?php endforeach; ?>
        </select>

        <?php if ((int)$user['id'] === $adminId): ?>
            <input type="hidden" name="role" value="admin">
        <?php endif; ?>

        <label for="account_status">Account Status</label>
        <select id="account_status" name="account_status" required
            <?= (int)$user['id'] === $adminId ? 'disabled' : '' ?>>
            <?php foreach ($statuses as $status): ?>
                <option value="<?= e($status) ?>"
                    <?= strtolower((string)$user['account_status']) === $status ? 'selected' : '' ?>>
                    <?= e(ucfirst($status)) ?>
                </option>
            <?php endforeach; ?>
        </select>

        <?php if ((int)$user['id'] === $adminId): ?>
            <input type="hidden" name="account_status"
                   value="<?= e($user['account_status']) ?>">
            <small>You cannot change your own role or account status here.</small>
        <?php endif; ?>

        <button type="submit">Save Changes</button>
    </form>

    <p><a href="manage_users.php">← Back to User Management</a></p>
</main>
</body>
</html>