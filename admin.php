<?php
session_start();
require_once __DIR__ . '/db.php';

function safe($value): string {
    return htmlspecialchars((string) ($value ?? ''), ENT_QUOTES, 'UTF-8');
}

// Require a completed 2FA login and administrator role.
if (
    !isset($_SESSION['user_id'], $_SESSION['username']) ||
    ($_SESSION['two_factor_verified'] ?? false) !== true ||
    strtolower(trim($_SESSION['role'] ?? '')) !== 'admin'
) {
    header('Location: login.php');
    exit;
}

$userId = (int) $_SESSION['user_id'];

try {
    // Re-check the account and role in the database on every request.
    $stmt = $conn->prepare(
        'SELECT username, role, account_status
         FROM users WHERE id = ? LIMIT 1'
    );
    $stmt->bind_param('i', $userId);
    $stmt->execute();
    $admin = $stmt->get_result()->fetch_assoc();
    $stmt->close();

    if (
        !$admin ||
        strtolower(trim($admin['account_status'] ?? '')) !== 'active' ||
        strtolower(trim($admin['role'] ?? '')) !== 'admin'
    ) {
        $_SESSION = [];

        if (ini_get('session.use_cookies')) {
            $params = session_get_cookie_params();
            setcookie(
                session_name(),
                '',
                time() - 42000,
                $params['path'],
                $params['domain'],
                $params['secure'],
                $params['httponly']
            );
        }

        session_destroy();
        header('Location: login.php');
        exit;
    }

    $username = $admin['username'];

    $statsResult = $conn->query("
        SELECT
            COUNT(*) AS total_users,
            COALESCE(SUM(account_status = 'active'), 0) AS active_users,
            COALESCE(SUM(account_status = 'pending'), 0) AS pending_users,
            COALESCE(SUM(account_status = 'disabled'), 0) AS disabled_users,
            COALESCE(SUM(two_factor_enabled = 1), 0) AS two_factor_users
        FROM users
    ");

    $stats = $statsResult->fetch_assoc();

    $totalUsers = (int) $stats['total_users'];
    $activeUsers = (int) $stats['active_users'];
    $pendingUsers = (int) $stats['pending_users'];
    $disabledUsers = (int) $stats['disabled_users'];
    $twoFactorUsers = (int) $stats['two_factor_users'];

    $usersResult = $conn->query("
        SELECT id, full_name, username, email, role,
               account_status, two_factor_enabled, created_at
        FROM users
        ORDER BY id DESC
    ");

    $users = [];
    while ($row = $usersResult->fetch_assoc()) {
        $users[] = $row;
    }

} catch (Throwable $e) {
    error_log('Admin dashboard error: ' . $e->getMessage());
    http_response_code(500);
    exit('Unable to load the administrator dashboard. Please try again later.');
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Admin Dashboard | SecuredAuth</title>
<style>
* { box-sizing: border-box; }
body {
    margin: 0;
    font-family: Arial, sans-serif;
    background: #f1f5f9;
    color: #172033;
}
.sidebar {
    position: fixed;
    inset: 0 auto 0 0;
    width: 245px;
    padding: 28px 18px;
    background: #172554;
    color: white;
    overflow-y: auto;
}
.brand { font-size: 23px; font-weight: bold; margin-bottom: 8px; }
.admin-label { font-size: 12px; color: #bfdbfe; margin-bottom: 30px; }
.sidebar a {
    display: block;
    color: #e2e8f0;
    text-decoration: none;
    padding: 13px;
    margin: 7px 0;
    border-radius: 8px;
}
.sidebar a:hover, .sidebar a.active { background: #1d4ed8; color: white; }
.main { margin-left: 245px; padding: 30px; }
.topbar {
    display: flex;
    justify-content: space-between;
    align-items: center;
    gap: 15px;
    flex-wrap: wrap;
    margin-bottom: 25px;
}
h1 { margin: 0; font-size: 28px; }
.subtitle { color: #64748b; margin-top: 8px; }
.logout { color: #1d4ed8; font-weight: bold; text-decoration: none; }
.cards {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(175px, 1fr));
    gap: 17px;
    margin-bottom: 25px;
}
.card, .panel {
    background: white;
    border-radius: 12px;
    padding: 22px;
    box-shadow: 0 4px 15px #0000000a;
}
.card { border-top: 4px solid #2563eb; }
.card:nth-child(2) { border-color: #16a34a; }
.card:nth-child(3) { border-color: #d97706; }
.card:nth-child(4) { border-color: #dc2626; }
.card:nth-child(5) { border-color: #7c3aed; }
.card h3 { color: #64748b; font-size: 13px; margin: 0 0 14px; }
.number { font-size: 29px; font-weight: bold; }
.panel { margin-bottom: 24px; }
.panel h2 { margin-top: 0; font-size: 20px; }
.table-wrap { overflow-x: auto; }
table { width: 100%; border-collapse: collapse; min-width: 850px; }
th, td {
    text-align: left;
    padding: 13px 11px;
    border-bottom: 1px solid #e2e8f0;
    font-size: 13px;
}
th { background: #f8fafc; color: #475569; }
.badge {
    display: inline-block;
    padding: 5px 9px;
    border-radius: 20px;
    font-size: 11px;
    font-weight: bold;
    background: #e2e8f0;
}
.badge.active { background: #dcfce7; color: #166534; }
.badge.pending { background: #fef3c7; color: #92400e; }
.badge.disabled { background: #fee2e2; color: #991b1b; }
.badge.security { background: #dbeafe; color: #1e40af; }
@media(max-width: 700px) {
    .sidebar { position: static; width: 100%; height: auto; }
    .sidebar a { display: inline-block; }
    .main { margin-left: 0; padding: 18px; }
}
</style>
</head>
<body>

<aside class="sidebar">
    <div class="brand">SecuredAuth</div>
    <div class="admin-label">SYSTEM ADMINISTRATOR</div>
    <a class="active" href="admin.php">Dashboard</a>
    <a href="manage_users.php">User Management</a>
    <a href="audit_logs.php">Audit Logs</a>
    <a href="security_overview.php">Security Overview</a>
    <a href="#reports">Reports</a>
    <a href="logout.php">Log out</a>
</aside>

<main class="main">
    <div class="topbar">
        <div>
            <h1>Welcome, <?= safe($username) ?>!</h1>
            <p class="subtitle">Administrator control centre</p>
        </div>
        <a class="logout" href="logout.php">Log out</a>
    </div>

    <div class="cards">
        <section class="card">
            <h3>Total Users</h3>
            <div class="number"><?= $totalUsers ?></div>
        </section>
        <section class="card">
            <h3>Active Accounts</h3>
            <div class="number"><?= $activeUsers ?></div>
        </section>
        <section class="card">
            <h3>Pending Accounts</h3>
            <div class="number"><?= $pendingUsers ?></div>
        </section>
        <section class="card">
            <h3>Disabled Accounts</h3>
            <div class="number"><?= $disabledUsers ?></div>
        </section>
        <section class="card" id="security">
            <h3>2FA Enabled</h3>
            <div class="number"><?= $twoFactorUsers ?></div>
        </section>
    </div>

    <section class="panel" id="users">
        <h2>User Management</h2>
        <p class="subtitle">Registered accounts and their current access status.</p>
        <p><a href="manage_users.php">Open Manage Users</a></p>

        <div class="table-wrap">
            <table>
                <thead>
                <tr>
                    <th>ID</th>
                    <th>Full Name</th>
                    <th>Username</th>
                    <th>Email</th>
                    <th>Role</th>
                    <th>Status</th>
                    <th>2FA</th>
                    <th>Created</th>
                </tr>
                </thead>
                <tbody>
                <?php if (!$users): ?>
                    <tr><td colspan="8">No users found.</td></tr>
                <?php else: ?>
                    <?php foreach ($users as $user): ?>
                        <?php
                        $status = strtolower((string) $user['account_status']);
                        $allowedStatus = in_array(
                            $status,
                            ['active', 'pending', 'disabled'],
                            true
                        ) ? $status : '';
                        ?>
                        <tr>
                            <td><?= (int) $user['id'] ?></td>
                            <td><?= safe($user['full_name']) ?></td>
                            <td><?= safe($user['username']) ?></td>
                            <td><?= safe($user['email']) ?></td>
                            <td><?= safe(ucfirst($user['role'])) ?></td>
                            <td>
                                <span class="badge <?= safe($allowedStatus) ?>">
                                    <?= safe(ucfirst($status)) ?>
                                </span>
                            </td>
                            <td>
                                <span class="badge security">
                                    <?= (int) $user['two_factor_enabled'] === 1
                                        ? 'Enabled' : 'Disabled' ?>
                                </span>
                            </td>
                            <td><?= safe($user['created_at']) ?></td>
                        </tr>
                    <?php endforeach; ?>
                <?php endif; ?>
                </tbody>
            </table>
        </div>
    </section>

    <section class="panel" id="reports">
        <h2>Reports &amp; Security</h2>
        <p>Review account totals and two-factor authentication coverage.</p>
        <p><strong>Accounts with 2FA enabled:</strong>
            <?= $twoFactorUsers ?> of <?= $totalUsers ?>
        </p>
        <p class="subtitle">
            Password hashes, salts, and authentication secrets are not displayed here.
        </p>
    </section>
</main>
</body>
</html>