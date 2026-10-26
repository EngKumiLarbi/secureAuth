<?php
session_start();
require_once __DIR__ . '/db.php';

if (
    !isset($_SESSION['user_id'], $_SESSION['username']) ||
    ($_SESSION['two_factor_verified'] ?? false) !== true ||
    strtolower(trim((string)($_SESSION['role'] ?? ''))) !== 'admin'
) {
    header('Location: login.php');
    exit;
}

function securitySafe($value): string {
    return htmlspecialchars(
        (string)($value ?? ''),
        ENT_QUOTES,
        'UTF-8'
    );
}

$username = $_SESSION['username'];

$sql = "SELECT
    COUNT(*) AS total_users,
    COALESCE(SUM(account_status = 'active'), 0) AS active_users,
    COALESCE(SUM(account_status = 'pending'), 0) AS pending_users,
    COALESCE(SUM(account_status = 'disabled'), 0) AS disabled_users,
    COALESCE(SUM(two_factor_enabled = 1), 0) AS two_factor_users
    FROM users";

$result = $conn->query($sql);

if (!$result) {
    exit('Unable to load security statistics. Please check the database configuration.');
}

$stats = $result->fetch_assoc();

$totalUsers = (int)$stats['total_users'];
$activeUsers = (int)$stats['active_users'];
$pendingUsers = (int)$stats['pending_users'];
$disabledUsers = (int)$stats['disabled_users'];
$twoFactorUsers = (int)$stats['two_factor_users'];

$coverage = $totalUsers > 0
    ? (int)round(($twoFactorUsers / $totalUsers) * 100)
    : 0;
?>
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Security Overview | SecuredAuth</title>
<style>
* { box-sizing: border-box; }

body {
    margin: 0;
    font-family: Arial, Helvetica, sans-serif;
    background: #f3f6fc;
    color: #1d2b42;
}

.sidebar {
    position: fixed;
    top: 0;
    bottom: 0;
    left: 0;
    width: 245px;
    padding: 28px 18px;
    background: #14233f;
    color: #fff;
    overflow-y: auto;
}

.brand {
    font-size: 25px;
    font-weight: 700;
    margin-bottom: 30px;
}

.admin-label {
    color: #aebbd1;
    font-size: 11px;
    letter-spacing: 1.2px;
    margin-bottom: 18px;
}

.sidebar a {
    display: block;
    padding: 13px 14px;
    margin-bottom: 7px;
    color: #e4ebf7;
    text-decoration: none;
    border-radius: 8px;
    font-size: 14px;
}

.sidebar a:hover,
.sidebar a.active {
    background: #30476d;
    color: #fff;
}

.main {
    margin-left: 245px;
    padding: 32px;
}

.topbar {
    display: flex;
    justify-content: space-between;
    align-items: center;
    gap: 16px;
    margin-bottom: 28px;
}

h1 {
    margin: 0 0 9px;
    font-size: 28px;
}

.subtitle {
    margin: 0;
    color: #738097;
    line-height: 1.6;
}

.logout {
    text-decoration: none;
    color: #273751;
    background: white;
    border: 1px solid #dfe5ee;
    padding: 11px 15px;
    border-radius: 8px;
}

.cards {
    display: grid;
    grid-template-columns: repeat(2, minmax(0, 1fr));
    gap: 18px;
    margin-bottom: 22px;
}

.card, .panel {
    background: white;
    padding: 23px;
    border: 1px solid #e8edf5;
    border-radius: 13px;
    box-shadow: 0 4px 16px rgba(20, 35, 63, .04);
}

.card h3 {
    margin: 0 0 15px;
    font-size: 14px;
    font-weight: 500;
    color: #69778d;
}

.number {
    font-size: 32px;
    font-weight: 700;
}

.panel {
    margin-bottom: 22px;
}

.panel h2 {
    margin: 0 0 15px;
    font-size: 20px;
}

.panel p {
    line-height: 1.7;
}

.progress-track {
    height: 12px;
    width: 100%;
    margin: 17px 0 10px;
    background: #e9eef6;
    border-radius: 20px;
    overflow: hidden;
}

.progress-fill {
    height: 100%;
    background: #27845b;
    border-radius: 20px;
}

.status {
    display: inline-block;
    margin-top: 12px;
    padding: 8px 12px;
    border-radius: 20px;
    background: #e4f7ec;
    color: #176b3a;
    font-size: 13px;
    font-weight: 600;
}

.warning {
    padding: 14px;
    background: #fff4dc;
    color: #785619;
    border-radius: 8px;
}

.actions {
    display: flex;
    flex-wrap: wrap;
    gap: 12px;
    margin-top: 18px;
}

.actions a {
    display: inline-block;
    padding: 11px 14px;
    background: #edf3ff;
    color: #234f9b;
    border-radius: 8px;
    text-decoration: none;
}

.actions a:hover {
    background: #dce8ff;
}

@media (max-width: 760px) {
    .sidebar {
        position: static;
        width: 100%;
    }

    .main {
        margin-left: 0;
        padding: 20px;
    }

    .topbar {
        align-items: flex-start;
        flex-wrap: wrap;
    }

    .cards {
        grid-template-columns: 1fr;
    }
}
</style>
</head>
<body>

<aside class="sidebar">
    <div class="brand">SecuredAuth</div>
    <div class="admin-label">SYSTEM ADMINISTRATOR</div>
    <a href="admin.php">Dashboard</a>
    <a href="manage_users.php">User Management</a>
    <a href="audit_logs.php">Audit Logs</a>
    <a class="active" href="security_overview.php">Security Overview</a>
    <a href="admin.php#reports">Reports</a>
    <a href="backup.php">Backup &amp; Restore</a>
    <a href="logout.php">Log out</a>
</aside>

<main class="main">
    <header class="topbar">
        <div>
            <h1>Security Overview</h1>
            <p class="subtitle">
                Welcome, <?= securitySafe($username) ?>.
                Monitor account protection and access status.
            </p>
        </div>
        <a class="logout" href="logout.php">Log out</a>
    </header>

    <div class="cards">
        <section class="card">
            <h3>Total Accounts</h3>
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
    </div>

    <section class="panel">
        <h2>Two-Factor Authentication</h2>
        <p>
            <?= $twoFactorUsers ?> out of <?= $totalUsers ?>
            accounts have two-factor authentication enabled.
        </p>

        <div class="progress-track">
            <div class="progress-fill"
                 style="width: <?= $coverage ?>%"></div>
        </div>

        <strong><?= $coverage ?>% coverage</strong>

        <?php if ($totalUsers > 0 && $twoFactorUsers === $totalUsers): ?>
            <div class="status">All accounts have 2FA enabled</div>
        <?php elseif ($totalUsers === 0): ?>
            <p>No registered accounts were found.</p>
        <?php else: ?>
            <p class="warning">
                Some accounts do not have 2FA enabled.
                Review those accounts in User Management.
            </p>
        <?php endif; ?>
    </section>

    <section class="panel">
        <h2>Security Administration</h2>
        <p>Choose a section to continue managing system security.</p>

        <div class="actions">
            <a href="manage_users.php">Manage Accounts</a>
            <a href="audit_logs.php">Review Audit Logs</a>
            <a href="backup.php">Backup &amp; Restore</a>
        </div>
    </section>
</main>

</body>
</html>