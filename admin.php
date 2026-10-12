<?php
session_start();

require_once "db.php";

// Require a completed login and verified OTP.
if (
    !isset($_SESSION["user_id"]) ||
    ($_SESSION["two_factor_verified"] ?? false) !== true
) {
    header("Location: login.php");
    exit;
}

// Only an administrator can access this page.
$role = strtolower(trim($_SESSION["role"] ?? ""));

if ($role !== "admin") {
    http_response_code(403);
    exit("Access denied. Administrator permission required.");
}

// Create a CSRF protection token.
if (empty($_SESSION["csrf_token"])) {
    $_SESSION["csrf_token"] = bin2hex(random_bytes(32));
}

$message = "";
$messageType = "";

// Process approval or rejection requests.
if ($_SERVER["REQUEST_METHOD"] === "POST") {
    $token = $_POST["csrf_token"] ?? "";

    if (
        !is_string($token) ||
        !hash_equals($_SESSION["csrf_token"], $token)
    ) {
        http_response_code(403);
        exit("Invalid security token. Refresh the page and try again.");
    }

    $action = $_POST["action"] ?? "";
    $userId = filter_input(INPUT_POST, "user_id", FILTER_VALIDATE_INT);

    if (!$userId || !in_array($action, ["approve", "reject"], true)) {
        $message = "Invalid request.";
        $messageType = "error";
    } else {
        if ($action === "approve") {
            // Assign only the role the person requested.
            $stmt = $conn->prepare(
                "UPDATE users
                 SET role = requested_role,
                     account_status = 'active'
                 WHERE id = ?
                   AND account_status = 'pending'
                   AND requested_role IN ('manager', 'admin')"
            );
        } else {
            // Rejected accounts cannot log in.
            $stmt = $conn->prepare(
                "UPDATE users
                 SET account_status = 'rejected'
                 WHERE id = ?
                   AND account_status = 'pending'
                   AND requested_role IN ('manager', 'admin')"
            );
        }

        $stmt->bind_param("i", $userId);
        $stmt->execute();

        if ($stmt->affected_rows === 1) {
            $message = $action === "approve"
                ? "Account approved successfully."
                : "Account request rejected successfully.";

            $messageType = "success";
        } else {
            $message = "No pending request was changed. It may already have been processed.";
            $messageType = "error";
        }

        $stmt->close();
    }
}

// Get real dashboard statistics.
$totalResult = $conn->query(
    "SELECT COUNT(*) AS total FROM users"
);
$totalUsers = (int) $totalResult->fetch_assoc()["total"];

$managerResult = $conn->query(
    "SELECT COUNT(*) AS total
     FROM users
     WHERE role = 'manager'
       AND account_status = 'active'"
);
$totalManagers = (int) $managerResult->fetch_assoc()["total"];

$candidateResult = $conn->query(
    "SELECT COUNT(*) AS total
     FROM users
     WHERE role IN ('candidate', 'user')
       AND account_status = 'active'"
);
$totalCandidates = (int) $candidateResult->fetch_assoc()["total"];

// Get pending Manager and Admin requests.
$pendingResult = $conn->query(
    "SELECT id, full_name, username, email, requested_role, created_at
     FROM users
     WHERE account_status = 'pending'
       AND requested_role IN ('manager', 'admin')
     ORDER BY created_at ASC"
);

$pendingRequests = $pendingResult->fetch_all(MYSQLI_ASSOC);

function e($value) {
    return htmlspecialchars((string) $value, ENT_QUOTES, "UTF-8");
}
?>

<!doctype html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Admin Dashboard - SecuredAuth</title>
    <link rel="stylesheet" href="css/dashboard.css">

    <style>
        .approval-section {
            background: #fff;
            padding: 24px;
            margin-top: 25px;
            border-radius: 12px;
            box-shadow: 0 3px 12px rgba(0, 0, 0, 0.06);
            overflow-x: auto;
        }

        .approval-section h2 {
            margin-top: 0;
        }

        .approval-table {
            width: 100%;
            border-collapse: collapse;
            margin-top: 18px;
            min-width: 650px;
        }

        .approval-table th,
        .approval-table td {
            padding: 12px;
            text-align: left;
            border-bottom: 1px solid #e5e7eb;
        }

        .approval-table th {
            background: #f3f4f6;
        }

        .approval-actions {
            display: flex;
            gap: 8px;
        }

        .approval-actions button {
            padding: 8px 12px;
            border: none;
            border-radius: 6px;
            cursor: pointer;
            color: white;
        }

        .approve-button {
            background: #15803d;
        }

        .reject-button {
            background: #b91c1c;
        }

        .notice {
            padding: 12px;
            margin: 15px 0;
            border-radius: 6px;
        }

        .notice.success {
            background: #dcfce7;
            color: #166534;
        }

        .notice.error {
            background: #fee2e2;
            color: #991b1b;
        }

        .empty-message {
            padding: 15px 0;
        }
    </style>
</head>

<body>
<div class="dashboard">

    <aside class="sidebar">
        <div class="logo">Secured<span>Auth</span></div>

        <ul class="sidebar-menu">
            <li><a href="admin.php" class="active">Dashboard</a></li>
            <li><a href="manager.php">Manager</a></li>
            <li><a href="candidate.php">Candidate</a></li>
            <li><a href="logout.php">Logout</a></li>
        </ul>
    </aside>

    <main class="main-content">
        <div class="topbar">
            <h2>Admin Dashboard</h2>
            <div class="user-info">Administrator</div>
        </div>

        <section class="welcome">
            <h1>Welcome, Admin!</h1>
            <p>Manage users, account requests and access permissions.</p>
        </section>

        <?php if ($message !== ""): ?>
            <div class="notice <?= e($messageType) ?>">
                <?= e($message) ?>
            </div>
        <?php endif; ?>

        <section class="stats">
            <div class="stat-card">
                <h3>Total Accounts</h3>
                <p><?= $totalUsers ?></p>
            </div>

            <div class="stat-card">
                <h3>Active Managers</h3>
                <p><?= $totalManagers ?></p>
            </div>

            <div class="stat-card">
                <h3>Active Candidates</h3>
                <p><?= $totalCandidates ?></p>
            </div>
        </section>

        <section class="approval-section">
            <h2>Account Approval Requests</h2>
            <p>Review requests for Manager and Admin access.</p>

            <?php if (count($pendingRequests) === 0): ?>
                <p class="empty-message">
                    There are currently no pending Manager or Admin requests.
                </p>
            <?php else: ?>
                <table class="approval-table">
                    <thead>
                        <tr>
                            <th>Full Name</th>
                            <th>Username</th>
                            <th>Email</th>
                            <th>Requested Role</th>
                            <th>Actions</th>
                        </tr>
                    </thead>

                    <tbody>
                    <?php foreach ($pendingRequests as $request): ?>
                        <tr>
                            <td><?= e($request["full_name"]) ?></td>
                            <td><?= e($request["username"]) ?></td>
                            <td><?= e($request["email"]) ?></td>
                            <td><?= e(ucfirst($request["requested_role"])) ?></td>
                            <td>
                                <div class="approval-actions">
                                    <form method="post">
                                        <input type="hidden" name="csrf_token"
                                            value="<?= e($_SESSION["csrf_token"]) ?>">
                                        <input type="hidden" name="user_id"
                                            value="<?= (int) $request["id"] ?>">
                                        <input type="hidden" name="action"
                                            value="approve">
                                        <button class="approve-button" type="submit">
                                            Approve
                                        </button>
                                    </form>

                                    <form method="post"
                                        onsubmit="return confirm('Reject this account request?');">
                                        <input type="hidden" name="csrf_token"
                                            value="<?= e($_SESSION["csrf_token"]) ?>">
                                        <input type="hidden" name="user_id"
                                            value="<?= (int) $request["id"] ?>">
                                        <input type="hidden" name="action"
                                            value="reject">
                                        <button class="reject-button" type="submit">
                                            Reject
                                        </button>
                                    </form>
                                </div>
                            </td>
                        </tr>
                    <?php endforeach; ?>
                    </tbody>
                </table>
            <?php endif; ?>
        </section>

        <section class="dashboard-grid">
            <div class="dashboard-card">
                <h3>User Management</h3>
                <p>Review account requests and manage authorized roles.</p>
            </div>

            <div class="dashboard-card">
                <h3>Security</h3>
                <p>SecuredAuth requires verified two-factor authentication
                   and checks permissions before granting access.</p>
            </div>
        </section>
    </main>
</div>
</body>
</html>