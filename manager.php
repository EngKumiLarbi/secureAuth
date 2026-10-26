<?php
session_start();
require_once __DIR__ . '/db.php';

// Require a completed 2FA login and the manager role.
if (
    !isset($_SESSION['user_id'], $_SESSION['username']) ||
    ($_SESSION['two_factor_verified'] ?? false) !== true ||
    strtolower(trim($_SESSION['role'] ?? '')) !== 'manager'
) {
    header('Location: login.php');
    exit;
}

$userId = (int) $_SESSION['user_id'];

try {
    // Confirm the account still exists, is active, and remains a manager.
    $stmt = $conn->prepare(
        'SELECT id, username, full_name, email, role, account_status
         FROM users WHERE id = ? LIMIT 1'
    );
    $stmt->bind_param('i', $userId);
    $stmt->execute();
    $profile = $stmt->get_result()->fetch_assoc();
    $stmt->close();

    if (
        !$profile ||
        strtolower(trim($profile['account_status'] ?? '')) !== 'active' ||
        strtolower(trim($profile['role'] ?? '')) !== 'manager'
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

    $username = $profile['username'];
    $fullName = $profile['full_name'] ?: $username;
    $email = $profile['email'] ?? '';

    $result = $conn->query(
        "SELECT
            COUNT(*) AS total_users,
            COALESCE(SUM(CASE WHEN account_status = 'pending'
                THEN 1 ELSE 0 END), 0) AS pending_users,
            COALESCE(SUM(CASE WHEN account_status = 'active'
                THEN 1 ELSE 0 END), 0) AS active_users
         FROM users"
    );

    $stats = $result->fetch_assoc();
    $totalUsers = (int) $stats['total_users'];
    $pendingUsers = (int) $stats['pending_users'];
    $activeUsers = (int) $stats['active_users'];

} catch (Throwable $e) {
    error_log('Manager dashboard error: ' . $e->getMessage());
    http_response_code(500);
    exit('Unable to load the manager dashboard. Please try again later.');
}

$safeUsername = htmlspecialchars($username, ENT_QUOTES, 'UTF-8');
$safeFullName = htmlspecialchars($fullName, ENT_QUOTES, 'UTF-8');
$safeEmail = htmlspecialchars($email, ENT_QUOTES, 'UTF-8');
?>
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Manager Dashboard | SecuredAuth</title>
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
    left: 0;
    top: 0;
    width: 245px;
    height: 100vh;
    padding: 28px 18px;
    background: #14532d;
    color: white;
}
.brand { font-size: 23px; font-weight: bold; margin-bottom: 35px; }
.sidebar a {
    display: block;
    color: white;
    text-decoration: none;
    padding: 13px;
    margin: 7px 0;
    border-radius: 8px;
}
.sidebar a:hover, .sidebar a.active { background: #267345; }
.main { margin-left: 245px; padding: 30px; }
.topbar {
    display: flex;
    justify-content: space-between;
    align-items: center;
    flex-wrap: wrap;
    gap: 15px;
    margin-bottom: 25px;
}
.topbar h1 { margin: 0; font-size: 27px; }
.subtitle { color: #64748b; margin-top: 8px; }
.logout { color: #14532d; text-decoration: none; font-weight: bold; }
.cards {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(190px, 1fr));
    gap: 18px;
}
.card, .panel {
    background: white;
    border-radius: 12px;
    padding: 23px;
    box-shadow: 0 4px 15px #0000000b;
    margin-bottom: 22px;
}
.card h3 { margin-top: 0; color: #64748b; font-size: 14px; }
.value { font-size: 28px; font-weight: bold; }
.panel h2 { margin-top: 0; }
.notice {
    border-left: 4px solid #15803d;
    background: #f0fdf4;
    padding: 15px;
    margin: 12px 0;
    border-radius: 5px;
}
.profile-row { margin: 12px 0; overflow-wrap: anywhere; }
@media (max-width: 700px) {
    .sidebar { position: static; width: 100%; height: auto; }
    .sidebar a { display: inline-block; }
    .brand { margin-bottom: 12px; }
    .main { margin-left: 0; padding: 18px; }
}
</style>
</head>
<body>

<aside class="sidebar">
    <div class="brand">SecuredAuth</div>
    <a class="active" href="manager.php">Dashboard</a>
    <a href="#overview">User Overview</a>
    <a href="#profile">My Profile</a>
    <a href="#notifications">Notifications</a>
    <a href="logout.php">Log out</a>
</aside>

<div class="main">
    <div class="topbar">
        <div>
            <h1>Welcome, <?= $safeUsername ?>!</h1>
            <p class="subtitle">Here's an overview of your management workspace.</p>
        </div>
        <a class="logout" href="logout.php">Log out</a>
    </div>

    <div class="cards" id="overview">
        <section class="card">
            <h3>Total Registered Users</h3>
            <div class="value"><?= $totalUsers ?></div>
        </section>
        <section class="card">
            <h3>Active Accounts</h3>
            <div class="value"><?= $activeUsers ?></div>
        </section>
        <section class="card">
            <h3>Pending Accounts</h3>
            <div class="value"><?= $pendingUsers ?></div>
        </section>
    </div>

    <section class="panel">
        <h2>User Overview</h2>
        <p>These figures summarize accounts in the SecuredAuth users table.</p>
        <p>Use your authorized account-management tools to review or update accounts.</p>
    </section>

    <section class="panel" id="profile">
        <h2>My Profile</h2>
        <div class="profile-row"><strong>Full name:</strong> <?= $safeFullName ?></div>
        <div class="profile-row"><strong>Username:</strong> <?= $safeUsername ?></div>
        <div class="profile-row"><strong>Email:</strong> <?= $safeEmail ?></div>
        <div class="profile-row"><strong>Role:</strong> Manager</div>
    </section>

    <section class="panel" id="notifications">
        <h2>Notifications</h2>
        <div class="notice">
            <strong>Welcome to your management workspace</strong>
            <p>Review account summaries and keep your account credentials secure.</p>
        </div>
    </section>
</div>
</body>
</html>