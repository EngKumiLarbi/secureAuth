<?php
declare(strict_types=1);

session_start();

function e($value): string
{
    return htmlspecialchars(
        (string)($value ?? ''),
        ENT_QUOTES,
        'UTF-8'
    );
}

function endSessionAndRedirect(): void
{
    $_SESSION = [];

    if (ini_get('session.use_cookies')) {
        $params = session_get_cookie_params();

        setcookie(session_name(), '', [
            'expires' => time() - 42000,
            'path' => $params['path'],
            'domain' => $params['domain'],
            'secure' => $params['secure'],
            'httponly' => $params['httponly'],
            'samesite' => $params['samesite'] ?? 'Lax'
        ]);
    }

    session_destroy();

    header('Location: login.php');
    exit;
}

/* Require an authenticated administrator who completed 2FA. */
if (
    !isset($_SESSION['user_id'], $_SESSION['username']) ||
    strtolower((string)($_SESSION['role'] ?? '')) !== 'admin' ||
    ($_SESSION['two_factor_verified'] ?? false) !== true
) {
    endSessionAndRedirect();
}

require_once __DIR__ . '/db.php';

$error = '';
$logs = [];

try {
    /* Confirm the administrator is still active in the database. */
    $adminId = (int) $_SESSION['user_id'];

    $adminStmt = $conn->prepare(
        'SELECT id, username, role, account_status
         FROM users
         WHERE id = ?
         LIMIT 1'
    );

    $adminStmt->bind_param('i', $adminId);
    $adminStmt->execute();

    $adminResult = $adminStmt->get_result();
    $admin = $adminResult->fetch_assoc();
    $adminStmt->close();

    if (
        !$admin ||
        strtolower((string)$admin['role']) !== 'admin' ||
        strtolower((string)$admin['account_status']) !== 'active'
    ) {
        endSessionAndRedirect();
    }

    /* Refresh the username from the trusted database record. */
    $_SESSION['username'] = $admin['username'];

    /* Load the 300 most recent audit events. */
    $result = $conn->query(
        'SELECT id, actor_user_id, actor_username, action,
                target_user_id, target_username, details, created_at
         FROM audit_logs
         ORDER BY id DESC
         LIMIT 300'
    );

    while ($row = $result->fetch_assoc()) {
        $logs[] = $row;
    }

    $result->free();

} catch (Throwable $ex) {
    error_log('Audit log page error: ' . $ex->getMessage());

    $error = 'Unable to load audit logs. Please check the database configuration and audit_logs table.';
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Audit Logs | SecuredAuth</title>

<style>
* {
    box-sizing: border-box;
}

body {
    margin: 0;
    background: #f1f5f9;
    color: #172033;
    font-family: Arial, sans-serif;
}

.sidebar {
    position: fixed;
    inset: 0 auto 0 0;
    width: 235px;
    background: #172554;
    padding: 25px 16px;
    color: white;
}

.brand {
    font-size: 23px;
    font-weight: bold;
    margin-bottom: 10px;
}

.label {
    font-size: 11px;
    color: #bfdbfe;
    margin-bottom: 25px;
}

.sidebar a {
    display: block;
    color: white;
    text-decoration: none;
    padding: 12px;
    border-radius: 7px;
    margin: 6px 0;
}

.sidebar a:hover,
.sidebar a.active {
    background: #1d4ed8;
}

main {
    margin-left: 235px;
    padding: 28px;
}

header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    flex-wrap: wrap;
    gap: 12px;
    margin-bottom: 22px;
}

h1 {
    margin: 0;
    font-size: 27px;
}

.subtitle {
    color: #64748b;
    line-height: 1.5;
}

.panel {
    background: white;
    padding: 22px;
    border-radius: 12px;
    box-shadow: 0 4px 15px #0000000a;
}

.table-wrap {
    overflow-x: auto;
}

table {
    width: 100%;
    min-width: 850px;
    border-collapse: collapse;
}

th,
td {
    text-align: left;
    padding: 12px;
    border-bottom: 1px solid #e2e8f0;
    font-size: 13px;
    vertical-align: top;
}

th {
    background: #f8fafc;
    color: #475569;
}

.badge {
    display: inline-block;
    padding: 5px 8px;
    border-radius: 12px;
    background: #dbeafe;
    color: #1e40af;
    overflow-wrap: anywhere;
}

.details {
    overflow-wrap: anywhere;
    max-width: 360px;
}

.error {
    background: #fee2e2;
    color: #991b1b;
    padding: 12px;
    border-radius: 7px;
    margin-bottom: 15px;
}

a.logout {
    color: #1d4ed8;
    text-decoration: none;
    font-weight: bold;
}

@media (max-width: 700px) {
    .sidebar {
        position: static;
        width: 100%;
        height: auto;
    }

    .sidebar a {
        display: inline-block;
    }

    main {
        margin: 0;
        padding: 14px;
    }

    .panel {
        padding: 12px;
    }
}
</style>
</head>

<body>

<aside class="sidebar">
    <div class="brand">SecuredAuth</div>
    <div class="label">SYSTEM ADMINISTRATOR</div>

    <a href="admin.php">Dashboard</a>
    <a href="manage_users.php">User Management</a>
    <a href="audit_logs.php" class="active">Audit Logs</a>
    <a href="logout.php">Log out</a>
</aside>

<main>
    <header>
        <div>
            <h1>Audit Logs</h1>
            <p class="subtitle">
                Review recorded account-management activities.
            </p>
        </div>

        <a class="logout" href="logout.php">Log out</a>
    </header>

    <?php if ($error !== ''): ?>
        <div class="error"><?= e($error) ?></div>
    <?php endif; ?>

    <section class="panel">
        <h2>Recent Activities</h2>

        <p class="subtitle">
            Showing up to 300 of the newest recorded events.
            Events appear only when the relevant action records them.
        </p>

        <div class="table-wrap">
            <table>
                <thead>
                    <tr>
                        <th>Log ID</th>
                        <th>Date &amp; Time</th>
                        <th>Administrator</th>
                        <th>Action</th>
                        <th>Target User</th>
                        <th>Details</th>
                    </tr>
                </thead>

                <tbody>
                <?php if (empty($logs)): ?>
                    <tr>
                        <td colspan="6">No audit records found yet.</td>
                    </tr>
                <?php else: ?>
                    <?php foreach ($logs as $log): ?>
                        <tr>
                            <td><?= (int)$log['id'] ?></td>

                            <td><?= e($log['created_at']) ?></td>

                            <td>
                                <?= e($log['actor_username']) ?>
                                (ID <?= (int)($log['actor_user_id'] ?? 0) ?>)
                            </td>

                            <td>
                                <span class="badge">
                                    <?= e($log['action']) ?>
                                </span>
                            </td>

                            <td>
                                <?= e($log['target_username'] ?? '—') ?>

                                <?php if ($log['target_user_id'] !== null): ?>
                                    (ID <?= (int)$log['target_user_id'] ?>)
                                <?php endif; ?>
                            </td>

                            <td class="details">
                                <?= e($log['details'] ?? '') ?>
                            </td>
                        </tr>
                    <?php endforeach; ?>
                <?php endif; ?>
                </tbody>
            </table>
        </div>
    </section>
</main>

</body>
</html>