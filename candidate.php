<?php
session_start();

if (!isset($_SESSION["user_id"])) {
    header("Location: login.php");
    exit;
}

$role = strtolower(trim($_SESSION["role"] ?? ""));

if ($role !== "user" && $role !== "candidate") {
    http_response_code(403);
    die("Access denied.");
}

require_once "db.php";

$userId = (int) $_SESSION["user_id"];
$message = "";
$messageType = "success";

// Create a CSRF token for form protection.
if (empty($_SESSION["csrf_token"])) {
    $_SESSION["csrf_token"] = bin2hex(random_bytes(32));
}

// Load the candidate's profile.
$stmt = $conn->prepare(
    "SELECT username, full_name, email
     FROM users
     WHERE id = ?"
);
$stmt->bind_param("i", $userId);
$stmt->execute();
$user = $stmt->get_result()->fetch_assoc();
$stmt->close();

if (!$user) {
    session_destroy();
    header("Location: login.php");
    exit;
}

// Handle form submissions.
if ($_SERVER["REQUEST_METHOD"] === "POST") {

    $token = $_POST["csrf_token"] ?? "";

    if (!hash_equals($_SESSION["csrf_token"], $token)) {
        http_response_code(403);
        die("Invalid form request. Refresh the page and try again.");
    }

    $action = $_POST["action"] ?? "";

    // Update profile.
    if ($action === "update_profile") {

        $fullName = trim($_POST["full_name"] ?? "");
        $email = trim($_POST["email"] ?? "");

        if ($fullName === "" || !filter_var($email, FILTER_VALIDATE_EMAIL)) {
            $message = "Enter your full name and a valid email address.";
            $messageType = "error";
        } else {
            $stmt = $conn->prepare(
                "UPDATE users
                 SET full_name = ?, email = ?
                 WHERE id = ?"
            );
            $stmt->bind_param("ssi", $fullName, $email, $userId);

            if ($stmt->execute()) {
                $message = "Your profile has been updated.";
                $user["full_name"] = $fullName;
                $user["email"] = $email;
            } else {
                $message = "Unable to update your profile.";
                $messageType = "error";
            }

            $stmt->close();
        }
    }

    // Submit an application.
    if ($action === "submit_application") {

        $details = trim($_POST["application_details"] ?? "");

        if ($details === "") {
            $message = "Please enter your application details.";
            $messageType = "error";
        } else {

            // A candidate can have only one application in this workflow.
            $stmt = $conn->prepare(
                "SELECT id FROM applications WHERE user_id = ? LIMIT 1"
            );
            $stmt->bind_param("i", $userId);
            $stmt->execute();
            $existing = $stmt->get_result()->fetch_assoc();
            $stmt->close();

            if ($existing) {
                $message = "You have already submitted an application. Contact the manager if you need to change it.";
                $messageType = "error";
            } else {
                $status = "pending";

                $stmt = $conn->prepare(
                    "INSERT INTO applications
                     (user_id, application_details, application_status)
                     VALUES (?, ?, ?)"
                );
                $stmt->bind_param("iss", $userId, $details, $status);

                if ($stmt->execute()) {
                    $message = "Application submitted successfully!";
                } else {
                    $message = "Unable to submit your application. Please try again.";
                    $messageType = "error";
                }

                $stmt->close();
            }
        }
    }
}

// Get this candidate's application.
$stmt = $conn->prepare(
    "SELECT id, application_details, application_status, created_at
     FROM applications
     WHERE user_id = ?
     ORDER BY id DESC
     LIMIT 1"
);
$stmt->bind_param("i", $userId);
$stmt->execute();
$application = $stmt->get_result()->fetch_assoc();
$stmt->close();

$status = strtolower($application["application_status"] ?? "not submitted");

$statusClass = "pending";

if ($status === "approved") {
    $statusClass = "approved";
} elseif ($status === "rejected") {
    $statusClass = "rejected";
}

$csrfToken = $_SESSION["csrf_token"];
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">

    <title>Candidate Dashboard - SecuredAuth</title>
    <link rel="stylesheet" href="css/dashboard.css">
</head>

<body>
<div class="dashboard">

    <aside class="sidebar">
        <div class="logo">Secured<span>Auth</span></div>

        <ul class="sidebar-menu">
            <li><a href="candidate.php" class="active">Dashboard</a></li>
            <li><a href="logout.php">Logout</a></li>
        </ul>
    </aside>

    <main class="main-content">

        <div class="topbar">
            <h2>Candidate Dashboard</h2>
            <div class="user-info">
                <?= htmlspecialchars($user["username"]) ?>
            </div>
        </div>

        <section class="welcome">
            <h1>Welcome, Candidate!</h1>
            <p>Manage your profile and track your application.</p>
        </section>

        <?php if ($message !== ""): ?>
            <p role="status"
               style="padding:12px; border-radius:8px; background:#eeeeee;">
                <?= htmlspecialchars($message) ?>
            </p>
        <?php endif; ?>

        <section class="stats">

            <div class="stat-card">
                <h3>Application Status</h3>
                <p>
                    <span class="status <?= htmlspecialchars($statusClass) ?>">
                        <?= htmlspecialchars(ucwords($status)) ?>
                    </span>
                </p>
            </div>

            <div class="stat-card">
                <h3>Profile</h3>
                <p>Active</p>
            </div>

            <div class="stat-card">
                <h3>Application ID</h3>
                <p>
                    <?= $application ? (int) $application["id"] : "—" ?>
                </p>
            </div>

        </section>

        <section class="dashboard-grid">

            <div class="dashboard-card">
                <h3>My Profile</h3>

                <form class="dashboard-form" method="post" action="candidate.php">
                    <input type="hidden" name="csrf_token"
                           value="<?= htmlspecialchars($csrfToken) ?>">
                    <input type="hidden" name="action" value="update_profile">

                    <label for="username">Username</label>
                    <input type="text" id="username"
                           value="<?= htmlspecialchars($user["username"]) ?>"
                           disabled>

                    <label for="full_name">Full Name</label>
                    <input type="text" id="full_name" name="full_name"
                           value="<?= htmlspecialchars($user["full_name"] ?? "") ?>"
                           required>

                    <label for="email">Email</label>
                    <input type="email" id="email" name="email"
                           value="<?= htmlspecialchars($user["email"] ?? "") ?>"
                           required>

                    <button type="submit" class="dashboard-button">
                        Update Profile
                    </button>
                </form>
            </div>

            <div class="dashboard-card">
                <h3>My Application</h3>

                <?php if ($application): ?>

                    <p><strong>Status:</strong>
                        <?= htmlspecialchars(ucwords($status)) ?>
                    </p>

                    <p><strong>Submitted:</strong>
                        <?= htmlspecialchars($application["created_at"]) ?>
                    </p>

                    <p><strong>Details:</strong></p>

                    <p>
                        <?= nl2br(htmlspecialchars(
                            $application["application_details"] ?? ""
                        )) ?>
                    </p>

                    <?php if ($status === "pending"): ?>
                        <p>Your application is waiting for manager review.</p>
                    <?php elseif ($status === "approved"): ?>
                        <p>Your application has been approved.</p>
                    <?php elseif ($status === "rejected"): ?>
                        <p>Your application was rejected. Contact the manager for further information.</p>
                    <?php endif; ?>

                <?php else: ?>

                    <p>You have not submitted an application yet.</p>

                    <form class="dashboard-form" method="post" action="candidate.php">
                        <input type="hidden" name="csrf_token"
                               value="<?= htmlspecialchars($csrfToken) ?>">
                        <input type="hidden" name="action"
                               value="submit_application">

                        <label for="application_details">
                            Application Details
                        </label>

                        <textarea id="application_details"
                                  name="application_details"
                                  rows="6"
                                  placeholder="Enter the details of your application..."
                                  required></textarea>

                        <button type="submit" class="dashboard-button">
                            Submit Application
                        </button>
                    </form>

                <?php endif; ?>
            </div>

        </section>
    </main>
</div>
</body>
</html>