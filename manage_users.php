<?php
session_start();

if (
    !isset($_SESSION['user_id']) ||
    !isset($_SESSION['username']) ||
    strtolower($_SESSION['role'] ?? '') !== 'admin'
) {
    header('Location: login.php');
    exit;
}

require_once __DIR__ . '/db.php';

function e($value): string {
    return htmlspecialchars(
        (string)($value ?? ''),
        ENT_QUOTES,
        'UTF-8'
    );
}

if (empty($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}

$adminId = (int)$_SESSION['user_id'];
$search = trim($_GET['search'] ?? '');
$filterRole = strtolower(trim($_GET['role'] ?? ''));
$filterStatus = strtolower(trim($_GET['status'] ?? ''));
$message = '';

if (($_GET['message'] ?? '') === 'disabled') {
    $message = 'The account was disabled and the action was recorded.';
}

$allowedRoles = ['admin', 'manager', 'candidate'];
$allowedStatuses = ['active', 'pending', 'disabled'];

$sql = "SELECT id, full_name, username, email, role,
               account_status, two_factor_enabled, created_at
        FROM users
        WHERE 1=1";

$types = '';
$params = [];

if ($search !== '') {
    $sql .= " AND (full_name LIKE ? OR username LIKE ? OR email LIKE ?)";
    $term = '%' . $search . '%';

    $params[] = $term;
    $params[] = $term;
    $params[] = $term;
    $types .= 'sss';
}

if (in_array($filterRole, $allowedRoles, true)) {
    $sql .= " AND role = ?";
    $params[] = $filterRole;
    $types .= 's';
}

if (in_array($filterStatus, $allowedStatuses, true)) {
    $sql .= " AND account_status = ?";
    $params[] = $filterStatus;
    $types .= 's';
}

$sql .= " ORDER BY id DESC";

$users = [];
$errorMessage = '';

try {
    $stmt = $conn->prepare($sql);

    if (!empty($params)) {
        $stmt->bind_param($types, ...$params);
    }

    $stmt->execute();
    $result = $stmt->get_result();

    while ($row = $result->fetch_assoc()) {
        $users[] = $row;
    }

    $stmt->close();
} catch (Throwable $ex) {
    error_log('User management error: ' . $ex->getMessage());
    $errorMessage = 'Unable to load users. Check the database connection.';
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>User Management | SecuredAuth</title>

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
    width: 240px;
    padding: 27px 17px;
    background: #172554;
    color: white;
    overflow-y: auto;
}

.brand {
    font-size: 23px;
    font-weight: bold;
    margin-bottom: 9px;
}

.subtitle {
    color: #64748b;
    line-height: 1.5;
}

.admin-label {
    color: #bfdbfe;
    font-size: 11px;
    letter-spacing: 1px;
    margin-bottom: 28px;
}

.sidebar a {
    display: block;
    padding: 13px;
    margin: 7px 0;
    border-radius: 8px;
    color: #e2e8f0;
    text-decoration: none;
}

.sidebar a:hover,
.sidebar a.active {
    background: #1d4ed8;
    color: white;
}

.main {
    margin-left: 240px;
    padding: 28px;
}

.topbar {
    display: flex;
    justify-content: space-between;
    align-items: center;
    flex-wrap: wrap;
    gap: 14px;
    margin-bottom: 24px;
}

h1 {
    margin: 0;
    font-size: 28px;
}

h2 {
    margin-top: 0;
    font-size: 21px;
}

.logout {
    color: #1d4ed8;
    text-decoration: none;
    font-weight: bold;
}

.topbar-actions {
    display: flex;
    align-items: center;
    gap: 9px;
    flex-wrap: wrap;
}

.action-link {
    display: inline-flex;
    min-height: 40px;
    align-items: center;
    padding: 9px 13px;
    border: 1px solid #1d4ed8;
    border-radius: 7px;
    background: #1d4ed8;
    color: #fff;
    font-weight: bold;
    text-decoration: none;
}

.action-link.secondary {
    background: #fff;
    color: #1d4ed8;
}

.panel {
    background: white;
    padding: 23px;
    border-radius: 12px;
    box-shadow: 0 4px 15px #0000000a;
    margin-bottom: 22px;
}

.filters {
    display: flex;
    flex-wrap: wrap;
    gap: 10px;
    margin: 20px 0;
}

input,
select,
button {
    font: inherit;
    padding: 11px 12px;
    border-radius: 7px;
}

input,
select {
    border: 1px solid #cbd5e1;
    background: white;
}

input[type="search"] {
    flex: 1;
    min-width: 190px;
}

button {
    border: 0;
    cursor: pointer;
    font-weight: bold;
}

.search-button {
    background: #1d4ed8;
    color: white;
}

.reset {
    display: inline-flex;
    align-items: center;
    color: #1d4ed8;
    text-decoration: none;
    padding: 10px;
}

.table-wrap {
    overflow-x: auto;
}

table {
    width: 100%;
    min-width: 1120px;
    border-collapse: collapse;
}

th,
td {
    text-align: left;
    padding: 13px 11px;
    border-bottom: 1px solid #e2e8f0;
    font-size: 13px;
}

th {
    background: #f8fafc;
    color: #475569;
    white-space: nowrap;
}

.badge {
    display: inline-block;
    padding: 5px 9px;
    border-radius: 15px;
    font-size: 11px;
    font-weight: bold;
    background: #e2e8f0;
}

.status-active {
    background: #dcfce7;
    color: #166534;
}

.status-pending {
    background: #fef3c7;
    color: #92400e;
}

.status-disabled {
    background: #fee2e2;
    color: #991b1b;
}

.twofa {
    background: #dbeafe;
    color: #1e40af;
}

.edit-link {
    color: #1d4ed8;
    text-decoration: none;
    font-weight: bold;
}

.disable-button {
    background: #dc2626;
    color: white;
}

.disabled-label {
    color: #64748b;
}

.alert {
    padding: 13px 15px;
    border-radius: 8px;
    margin-bottom: 18px;
}

.success {
    background: #dcfce7;
    color: #166534;
}

.error {
    background: #fee2e2;
    color: #991b1b;
}

.disable-form {
    margin: 0;
}

.retention-note {
    color: #64748b;
    font-size: 13px;
    line-height: 1.5;
}

@media (max-width: 760px) {
    .sidebar {
        position: static;
        width: 100%;
        height: auto;
    }

    .sidebar a {
        display: inline-block;
        margin: 4px;
    }

    .main {
        margin-left: 0;
        padding: 15px;
    }

    .panel {
        padding: 15px;
    }
}
</style>
</head>

<body>

<aside class="sidebar">
    <div class="brand">SecuredAuth</div>
    <div class="admin-label">SYSTEM ADMINISTRATOR</div>

    <a href="admin.php">Dashboard</a>
    <a href="manage_users.php" class="active">User Management</a>
    <a href="#security">Security Overview</a>
    <a href="backup.php">Database Backups</a>
    <a href="audit_logs.php">Audit Logs</a>
    <a href="logout.php">Log out</a>
</aside>

<main class="main">

    <div class="topbar">
        <div>
            <h1>User Management</h1>
            <p class="subtitle">
                Search, review, and manage registered accounts.
            </p>
        </div>

        <div class="topbar-actions">
            <a class="action-link" href="backup.php">Backups</a>
            <a class="action-link secondary" href="audit_logs.php">Audit history</a>
            <a class="logout" href="logout.php">Log out</a>
        </div>
    </div>

    <?php if ($message !== ''): ?>
        <div class="alert success"><?= e($message) ?></div>
    <?php endif; ?>

    <?php if ($errorMessage !== ''): ?>
        <div class="alert error"><?= e($errorMessage) ?></div>
    <?php endif; ?>

    <section class="panel">
        <h2>Registered Accounts</h2>

        <p class="subtitle">
            <?= count($users) ?> account(s) match your current filters.
        </p>
        <p class="retention-note">
            Disabled accounts remain in the user list and audit history. Choose
            “Disabled” in the status filter to review them.
        </p>

        <form class="filters" method="GET" action="manage_users.php">

            <input
                type="search"
                name="search"
                placeholder="Search name, username or email"
                value="<?= e($search) ?>"
            >

            <select name="role">
                <option value="">All roles</option>

                <?php foreach ($allowedRoles as $role): ?>
                    <option
                        value="<?= e($role) ?>"
                        <?= $filterRole === $role ? 'selected' : '' ?>
                    >
                        <?= e(ucfirst($role)) ?>
                    </option>
                <?php endforeach; ?>
            </select>

            <select name="status">
                <option value="">All statuses</option>

                <?php foreach ($allowedStatuses as $status): ?>
                    <option
                        value="<?= e($status) ?>"
                        <?= $filterStatus === $status ? 'selected' : '' ?>
                    >
                        <?= e(ucfirst($status)) ?>
                    </option>
                <?php endforeach; ?>
            </select>

            <button class="search-button" type="submit">
                Search
            </button>

            <a class="reset" href="manage_users.php">Reset</a>
        </form>

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
                        <th>Edit</th>
                        <th>Account Control</th>
                    </tr>
                </thead>

                <tbody>
                <?php if (empty($users)): ?>
                    <tr>
                        <td colspan="10">No matching users found.</td>
                    </tr>
                <?php else: ?>

                    <?php foreach ($users as $user): ?>
                        <?php
                        $status = strtolower(
                            (string)$user['account_status']
                        );

                        $statusClass = in_array(
                            $status,
                            $allowedStatuses,
                            true
                        ) ? 'status-' . $status : '';
                        ?>

                        <tr>
                            <td><?= (int)$user['id'] ?></td>

                            <td><?= e($user['full_name']) ?></td>

                            <td><?= e($user['username']) ?></td>

                            <td><?= e($user['email']) ?></td>

                            <td><?= e(ucfirst($user['role'])) ?></td>

                            <td>
                                <span class="badge <?= e($statusClass) ?>">
                                    <?= e(ucfirst($status)) ?>
                                </span>
                            </td>

                            <td>
                                <span class="badge twofa">
                                    <?= (int)$user['two_factor_enabled'] === 1
                                        ? 'Enabled'
                                        : 'Disabled' ?>
                                </span>
                            </td>

                            <td><?= e($user['created_at']) ?></td>

                            <td>
                                <a
                                    class="edit-link"
                                    href="edit_user.php?id=<?= (int)$user['id'] ?>"
                                >
                                    Edit
                                </a>
                            </td>

                            <td>
                                <?php if (
                                    (int)$user['id'] !== $adminId &&
                                    $status !== 'disabled'
                                ): ?>
                                    <form
                                        class="disable-form"
                                        method="POST"
                                        action="delete_user.php"
                                        onsubmit="return confirm('Disable this account? The user will no longer be able to access the system if login checks account status.');"
                                    >
                                        <input
                                            type="hidden"
                                            name="id"
                                            value="<?= (int)$user['id'] ?>"
                                        >

                                        <input
                                            type="hidden"
                                            name="csrf_token"
                                            value="<?= e($_SESSION['csrf_token']) ?>"
                                        >

                                        <button
                                            class="disable-button"
                                            type="submit"
                                        >
                                            Disable
                                        </button>
                                    </form>
                                <?php else: ?>
                                    <span class="disabled-label">
                                        <?= $status === 'disabled'
                                            ? 'Disabled'
                                            : 'Your account' ?>
                                    </span>
                                <?php endif; ?>
                            </td>
                        </tr>
                    <?php endforeach; ?>

                <?php endif; ?>
                </tbody>
            </table>
        </div>
    </section>

    <section class="panel" id="security">
        <h2>Security Reminder</h2>
        <p class="subtitle">
            Only authorized administrators can access this page.
            Disabling an account must also be enforced by the login process.
            Account actions should be recorded in the audit log.
        </p>
    </section>

</main>
</body>
</html>