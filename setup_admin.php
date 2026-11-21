<?php
declare(strict_types=1);

session_start();
require_once __DIR__ . '/db.php';

function setupEscape(mixed $value): string
{
    return htmlspecialchars((string)($value ?? ''), ENT_QUOTES, 'UTF-8');
}

if (empty($_SESSION['admin_setup_csrf'])) {
    $_SESSION['admin_setup_csrf'] = bin2hex(random_bytes(32));
}

$message = '';
$databaseAvailable = true;
$adminExists = false;
$setupToken = envValue('ADMIN_SETUP_TOKEN', '');
$pepper = envValue('APP_PEPPER', '');
$tokenConfigured = is_string($setupToken) && strlen($setupToken) === 32;

try {
    $existingAdmin = $conn->query(
        "SELECT id FROM users WHERE LOWER(role) = 'admin' LIMIT 1"
    )->fetch_assoc();
    $adminExists = (bool)$existingAdmin;
} catch (Throwable $e) {
    error_log('Admin setup check failed: ' . $e->getMessage());
    $databaseAvailable = false;
    $message = 'Admin setup is temporarily unavailable. Check the database connection.';
}

$setupCompleted = false;

if ($_SERVER['REQUEST_METHOD'] === 'POST' && $databaseAvailable && !$adminExists) {
    $csrfToken = $_POST['csrf_token'] ?? '';
    $email = trim((string)($_POST['email'] ?? ''));
    $password = (string)($_POST['password'] ?? '');
    $submittedToken = (string)($_POST['admin_token'] ?? '');

    if (
        !is_string($csrfToken) ||
        !hash_equals((string)$_SESSION['admin_setup_csrf'], $csrfToken)
    ) {
        $message = 'This setup form expired. Reload the page and try again.';
    } elseif (!$tokenConfigured) {
        $message = 'Admin setup is disabled until a valid setup token is configured.';
    } elseif (!is_string($pepper) || $pepper === '') {
        $message = 'Security configuration is missing. Contact the administrator.';
    } elseif (!filter_var($email, FILTER_VALIDATE_EMAIL) || $password === '') {
        $message = 'Enter your registered email address and password.';
    } elseif (
        strlen($submittedToken) !== 32 ||
        !hash_equals($setupToken, $submittedToken)
    ) {
        $message = 'The setup details could not be verified.';
    } else {
        $lockAcquired = false;

        try {
            $lockResult = $conn->query(
                "SELECT GET_LOCK('securedauth_admin_bootstrap', 5) AS acquired"
            )->fetch_assoc();

            if ((int)($lockResult['acquired'] ?? 0) !== 1) {
                $message = 'Admin setup is busy. Please try again.';
            } else {
                $lockAcquired = true;
                $conn->begin_transaction();

                try {
                    $existingAdmin = $conn->query(
                        "SELECT id FROM users WHERE LOWER(role) = 'admin' LIMIT 1"
                    )->fetch_assoc();

                    if ($existingAdmin) {
                        $conn->rollback();
                        $adminExists = true;
                        $message = 'An administrator is already set up. Use the existing admin account to manage roles.';
                    } else {
                        $stmt = $conn->prepare(
                            'SELECT id, password_hash, salt, account_status
                             FROM users WHERE email = ? LIMIT 1'
                        );
                        $stmt->bind_param('s', $email);
                        $stmt->execute();
                        $user = $stmt->get_result()->fetch_assoc();
                        $stmt->close();

                        $validAccount = $user
                            && strtolower((string)$user['account_status']) === 'active'
                            && password_verify(
                                $password . $user['salt'] . $pepper,
                                $user['password_hash']
                            );

                        if (!$validAccount) {
                            $conn->rollback();
                            $message = 'The setup details could not be verified.';
                        } else {
                            $userId = (int)$user['id'];
                            $update = $conn->prepare(
                                "UPDATE users
                                 SET role = 'admin', requested_role = 'admin'
                                 WHERE id = ? AND account_status = 'active'"
                            );
                            $update->bind_param('i', $userId);
                            $update->execute();
                            $update->close();
                            $conn->commit();
                            $setupCompleted = true;
                        }
                    }
                } catch (Throwable $e) {
                    $conn->rollback();
                    throw $e;
                }
            }
        } catch (Throwable $e) {
            error_log('Admin bootstrap failed: ' . $e->getMessage());
            $message = 'Admin setup could not be completed. Please try again.';
        } finally {
            if ($lockAcquired) {
                try {
                    $conn->query(
                        "SELECT RELEASE_LOCK('securedauth_admin_bootstrap')"
                    );
                } catch (Throwable $e) {
                    error_log('Admin setup lock release failed: ' . $e->getMessage());
                }
            }
        }

        if ($setupCompleted) {
            header('Location: login.php?admin_setup=1');
            exit;
        }
    }
}

$canSetup = $databaseAvailable && !$adminExists && $tokenConfigured;
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Initial Admin Setup | SecuredAuth</title>
    <style>
        * { box-sizing: border-box; }
        body {
            margin: 0;
            min-height: 100vh;
            display: grid;
            place-items: center;
            padding: 24px;
            background: #f7f5ef;
            color: #1d2925;
            font-family: "Trebuchet MS", "Segoe UI", sans-serif;
        }
        main {
            width: 100%;
            max-width: 520px;
            padding: clamp(26px, 6vw, 48px);
            border: 1px solid rgba(29, 41, 37, 0.08);
            border-radius: 8px;
            background: #fff;
            box-shadow: 0 24px 70px rgba(33, 48, 41, 0.14);
        }
        .brand {
            margin: 0 0 28px;
            color: #244b3d;
            font-weight: bold;
            text-decoration: none;
        }
        .kicker {
            margin: 0 0 10px;
            color: #244b3d;
            font-size: 12px;
            font-weight: bold;
            text-transform: uppercase;
        }
        h1 {
            margin: 0 0 12px;
            font-family: Georgia, "Times New Roman", serif;
            font-size: 34px;
            font-weight: normal;
        }
        .intro, .notice {
            color: #64736d;
            line-height: 1.6;
        }
        label {
            display: block;
            margin: 18px 0 7px;
            font-size: 14px;
            font-weight: bold;
        }
        input {
            width: 100%;
            min-height: 48px;
            padding: 12px 13px;
            border: 1px solid #cbd8d0;
            border-radius: 6px;
            background: #fcfdfb;
            color: #1d2925;
            font: inherit;
        }
        input:focus {
            outline: none;
            border-color: #244b3d;
            box-shadow: 0 0 0 3px rgba(36, 75, 61, 0.15);
        }
        button {
            width: 100%;
            min-height: 50px;
            margin-top: 24px;
            border: 0;
            border-radius: 6px;
            background: #244b3d;
            color: #fff;
            font: inherit;
            font-weight: bold;
            cursor: pointer;
        }
        button:hover { background: #17362d; }
        .message {
            margin: 18px 0;
            padding: 12px 14px;
            border-left: 3px solid #b64236;
            background: #fff1ed;
            color: #85352e;
            line-height: 1.5;
        }
        .footer {
            margin: 22px 0 0;
            color: #64736d;
            text-align: center;
        }
        a { color: #244b3d; }
        @media (max-width: 480px) {
            body { padding: 16px; }
        }
    </style>
</head>
<body>
    <main>
        <p><a class="brand" href="index.html">SecuredAuth</a></p>
        <p class="kicker">One-time bootstrap</p>
        <h1>Set up the first administrator</h1>
        <p class="intro">
            Register a regular account first. Then verify that account with its password
            and the private setup token to grant administrator access.
        </p>

        <?php if ($message !== ''): ?>
            <div class="message" role="alert">
                <?= htmlspecialchars($message, ENT_QUOTES, 'UTF-8') ?>
            </div>
        <?php endif; ?>

        <?php if ($adminExists): ?>
            <p class="notice">
                An administrator is already configured. Sign in and use User Management
                to assign additional administrator roles.
            </p>
        <?php elseif (!$databaseAvailable): ?>
            <p class="notice">Admin setup cannot continue until the database is available.</p>
        <?php elseif (!$tokenConfigured): ?>
            <p class="notice">
                Setup is disabled. Configure a 32-character <code>ADMIN_SETUP_TOKEN</code>
                in the private <code>.env</code> file first.
            </p>
        <?php else: ?>
            <form method="post" action="setup_admin.php">
                <input
                    type="hidden"
                    name="csrf_token"
                    value="<?= setupEscape($_SESSION['admin_setup_csrf']) ?>"
                >

                <label for="email">Registered email address</label>
                <input
                    id="email"
                    name="email"
                    type="email"
                    maxlength="254"
                    autocomplete="username"
                    value="<?= setupEscape($_POST['email'] ?? '') ?>"
                    required
                >

                <label for="password">Account password</label>
                <input
                    id="password"
                    name="password"
                    type="password"
                    autocomplete="current-password"
                    required
                >

                <label for="admin_token">32-character setup token</label>
                <input
                    id="admin_token"
                    name="admin_token"
                    type="password"
                    minlength="32"
                    maxlength="32"
                    autocomplete="off"
                    required
                >

                <button type="submit">Enable administrator access</button>
            </form>
        <?php endif; ?>

        <p class="footer"><a href="login.php">Return to sign in</a></p>
    </main>
</body>
</html>
