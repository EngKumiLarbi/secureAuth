<?php
session_start();
require_once __DIR__ . '/db.php';

// Require a completed login and two-factor verification.
if (
    !isset($_SESSION['user_id'], $_SESSION['username']) ||
    ($_SESSION['two_factor_verified'] ?? false) !== true ||
    strtolower(trim($_SESSION['role'] ?? '')) !== 'candidate'
) {
    header('Location: login.php');
    exit;
}

$userId = (int) $_SESSION['user_id'];

try {
    // Never rely on session role or account status alone.
    $stmt = $conn->prepare(
        'SELECT id, username, full_name, email, requested_role, account_status, role
         FROM users WHERE id = ? LIMIT 1'
    );
    $stmt->bind_param('i', $userId);
    $stmt->execute();
    $user = $stmt->get_result()->fetch_assoc();
    $stmt->close();
} catch (Throwable $e) {
    error_log('Candidate account check error: ' . $e->getMessage());
    http_response_code(500);
    exit('Unable to load your account. Please try again later.');
}

if (
    !$user ||
    strtolower(trim($user['account_status'] ?? '')) !== 'active' ||
    strtolower(trim($user['role'] ?? '')) !== 'candidate'
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

$username = $user['username'];
$fullName = $user['full_name'] ?: $username;
$email = $user['email'] ?? '';
$requestedRole = $user['requested_role'] ?: 'Candidate';

// Application status is still a placeholder until an application
// status field or separate applications table is connected.
$applicationStatus = 'Pending';
$message = '';
$messageType = 'info';

// Create a token for the profile update form.
if (empty($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}

if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['update_profile'])) {
    $submittedToken = $_POST['csrf_token'] ?? '';

    if (
        !is_string($submittedToken) ||
        !hash_equals($_SESSION['csrf_token'], $submittedToken)
    ) {
        http_response_code(403);
        exit('Invalid form request. Refresh the page and try again.');
    }

    $newFullName = trim($_POST['full_name'] ?? '');
    $newEmail = trim($_POST['email'] ?? '');

    if (
        $newFullName === '' ||
        strlen($newFullName) > 150 ||
        !filter_var($newEmail, FILTER_VALIDATE_EMAIL) ||
        strlen($newEmail) > 254
    ) {
        $message = 'Please enter a valid name and email address.';
        $messageType = 'error';
    } else {
        try {
            $check = $conn->prepare(
                'SELECT id FROM users WHERE email = ? AND id <> ? LIMIT 1'
            );
            $check->bind_param('si', $newEmail, $userId);
            $check->execute();
            $duplicate = $check->get_result()->fetch_assoc();
            $check->close();

            if ($duplicate) {
                $message = 'That email address is already in use.';
                $messageType = 'error';
            } else {
                $update = $conn->prepare(
                    'UPDATE users
                     SET full_name = ?, email = ?
                     WHERE id = ? AND account_status = ? AND role = ?'
                );
                $activeStatus = 'active';
                $candidateRole = 'candidate';

                $update->bind_param(
                    'ssiss',
                    $newFullName,
                    $newEmail,
                    $userId,
                    $activeStatus,
                    $candidateRole
                );
                $update->execute();
                $updated = $update->affected_rows;
                $update->close();

                // affected_rows may be zero if the values did not change.
                $fullName = $newFullName;
                $email = $newEmail;
                $message = 'Your profile was updated successfully.';
                $messageType = 'info';

                // Refresh the profile from the database.
                $refresh = $conn->prepare(
                    'SELECT full_name, email FROM users
                     WHERE id = ? AND account_status = ? AND role = ? LIMIT 1'
                );
                $refresh->bind_param(
                    'iss',
                    $userId,
                    $activeStatus,
                    $candidateRole
                );
                $refresh->execute();
                $freshUser = $refresh->get_result()->fetch_assoc();
                $refresh->close();

                if (!$freshUser) {
                    $_SESSION = [];
                    session_destroy();
                    header('Location: login.php');
                    exit;
                }

                $fullName = $freshUser['full_name'] ?: $username;
                $email = $freshUser['email'] ?? '';
            }
        } catch (Throwable $e) {
            error_log('Candidate profile update error: ' . $e->getMessage());
            $message = 'Could not update your profile. Please try again.';
            $messageType = 'error';
        }
    }
}

$safeUsername = htmlspecialchars($username, ENT_QUOTES, 'UTF-8');
$safeFullName = htmlspecialchars($fullName, ENT_QUOTES, 'UTF-8');
$safeEmail = htmlspecialchars($email, ENT_QUOTES, 'UTF-8');
$safeRequestedRole = htmlspecialchars($requestedRole, ENT_QUOTES, 'UTF-8');
$safeMessage = htmlspecialchars($message, ENT_QUOTES, 'UTF-8');
$safeCsrf = htmlspecialchars($_SESSION['csrf_token'], ENT_QUOTES, 'UTF-8');
?>
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Candidate Dashboard | SecuredAuth</title>
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
    background: #173b75;
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
.sidebar a:hover, .sidebar a.active { background: #2b5593; }
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
.logout { color: #173b75; text-decoration: none; font-weight: bold; }
.subtitle { color: #64748b; margin-top: 8px; }
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
.value { font-size: 23px; font-weight: bold; overflow-wrap: anywhere; }
.pending {
    display: inline-block;
    background: #fef3c7;
    color: #92400e;
    border-radius: 20px;
    padding: 7px 12px;
    font-weight: bold;
    font-size: 13px;
}
.panel h2 { margin-top: 0; }
label { display: block; margin: 14px 0 7px; font-weight: bold; }
input {
    width: 100%;
    padding: 12px;
    border: 1px solid #cbd5e1;
    border-radius: 7px;
    font-size: 15px;
}
button {
    margin-top: 18px;
    padding: 12px 18px;
    background: #173b75;
    color: white;
    border: 0;
    border-radius: 7px;
    cursor: pointer;
}
.message {
    padding: 12px;
    border-radius: 8px;
    background: #dbeafe;
    margin-bottom: 20px;
}
.message.error { background: #fee2e2; color: #991b1b; }
.notice {
    border-left: 4px solid #2563eb;
    background: #eff6ff;
    padding: 15px;
    margin: 12px 0;
    border-radius: 5px;
}
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
    <a class="active" href="candidate.php">Dashboard</a>
    <a href="#application">My Application</a>
    <a href="#profile">My Profile</a>
    <a href="#notifications">Notifications</a>
    <a href="logout.php">Log out</a>
</aside>

<div class="main">
    <div class="topbar">
        <div>
            <h1>Welcome, <?= $safeUsername ?>!</h1>
            <p class="subtitle">Here's an overview of your candidate account.</p>
        </div>
        <a class="logout" href="logout.php">Log out</a>
    </div>

    <?php if ($message !== ''): ?>
        <div class="message <?= $messageType === 'error' ? 'error' : '' ?>">
            <?= $safeMessage ?>
        </div>
    <?php endif; ?>

    <div class="cards">
        <section class="card">
            <h3>Username</h3>
            <div class="value"><?= $safeUsername ?></div>
        </section>
        <section class="card">
            <h3>Account Role</h3>
            <div class="value">Candidate</div>
        </section>
        <section class="card">
            <h3>Application Status</h3>
            <span class="pending"><?= htmlspecialchars($applicationStatus, ENT_QUOTES, 'UTF-8') ?></span>
        </section>
    </div>

    <section class="panel" id="application">
        <h2>My Application</h2>
        <p><strong>Applicant:</strong> <?= $safeFullName ?></p>
        <p><strong>Requested role:</strong> <?= $safeRequestedRole ?></p>
        <p><strong>Status:</strong> <span class="pending">Pending</span></p>
        <p>Your application status will change when an authorized manager updates it.</p>
    </section>

    <section class="panel" id="profile">
        <h2>My Profile</h2>
        <form method="POST" action="candidate.php">
            <input type="hidden" name="csrf_token" value="<?= $safeCsrf ?>">

            <label for="full_name">Full name</label>
            <input id="full_name" name="full_name" type="text"
                   maxlength="150" required value="<?= $safeFullName ?>">

            <label for="email">Email address</label>
            <input id="email" name="email" type="email"
                   maxlength="254" required value="<?= $safeEmail ?>">

            <button type="submit" name="update_profile" value="1">
                Update Profile
            </button>
        </form>
    </section>

    <section class="panel" id="notifications">
        <h2>Notifications</h2>
        <div class="notice">
            <strong>Welcome to SecuredAuth</strong>
            <p>Your account is ready. Keep your login information private.</p>
        </div>
        <div class="notice">
            <strong>Application status</strong>
            <p>Check this dashboard for updates to your application.</p>
        </div>
    </section>
</div>
</body>
</html>