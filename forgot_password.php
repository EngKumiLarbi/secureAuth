<?php
declare(strict_types=1);

session_start();
require_once __DIR__ . '/db.php';

function resetEscape(mixed $value): string
{
    return htmlspecialchars((string)($value ?? ''), ENT_QUOTES, 'UTF-8');
}

function clearPasswordReset(): void
{
    unset(
        $_SESSION['password_reset_user_id'],
        $_SESSION['password_reset_email'],
        $_SESSION['password_reset_code_hash'],
        $_SESSION['password_reset_expires'],
        $_SESSION['password_reset_attempts']
    );
}

if (empty($_SESSION['password_reset_csrf'])) {
    $_SESSION['password_reset_csrf'] = bin2hex(random_bytes(32));
}

if (isset($_GET['restart'])) {
    clearPasswordReset();
}

$message = '';
$messageType = 'error';
$emailValue = '';
$phase = isset(
    $_SESSION['password_reset_user_id'],
    $_SESSION['password_reset_email'],
    $_SESSION['password_reset_code_hash'],
    $_SESSION['password_reset_expires']
) ? 'verify' : 'request';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $csrfToken = $_POST['csrf_token'] ?? '';

    if (
        !is_string($csrfToken) ||
        !hash_equals((string)$_SESSION['password_reset_csrf'], $csrfToken)
    ) {
        $message = 'This form expired. Reload the page and try again.';
    } elseif (($_POST['action'] ?? '') === 'request') {
        $email = trim((string)($_POST['email'] ?? ''));
        $emailValue = $email;

        if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
            $message = 'Enter a valid email address.';
        } elseif (time() - (int)($_SESSION['password_reset_last_request'] ?? 0) < 60) {
            $message = 'Please wait a minute before requesting another code.';
        } else {
            $_SESSION['password_reset_last_request'] = time();
            clearPasswordReset();

            $genericMessage = 'If an active account matches that email, a verification code has been sent.';
            $pendingUserId = 0;
            $code = (string)random_int(100000, 999999);
            $codeHash = hash('sha256', bin2hex(random_bytes(16)));

            try {
                $stmt = $conn->prepare(
                    'SELECT id, username, email
                     FROM users
                     WHERE email = ? AND account_status = \'active\'
                     LIMIT 1'
                );
                $stmt->bind_param('s', $email);
                $stmt->execute();
                $user = $stmt->get_result()->fetch_assoc();
                $stmt->close();

                if ($user) {
                    require_once __DIR__ . '/send_mail.php';

                    sendMail(
                        (string)$user['email'],
                        (string)$user['username'],
                        'Your SecuredAuth password reset code',
                        "Your password reset code is: {$code}\n\n" .
                        "It expires in 5 minutes. If you did not request a reset, " .
                        "you can ignore this email."
                    );

                    $pendingUserId = (int)$user['id'];
                    $codeHash = hash('sha256', $code);
                }
            } catch (Throwable $e) {
                error_log('Password reset email error: ' . $e->getMessage());
            }

            unset(
                $_SESSION['pending_2fa_user_id'],
                $_SESSION['pending_2fa_username'],
                $_SESSION['pending_2fa_email'],
                $_SESSION['pending_2fa_role'],
                $_SESSION['pending_2fa_code'],
                $_SESSION['pending_2fa_expires']
            );
            session_regenerate_id(true);
            $_SESSION['password_reset_user_id'] = $pendingUserId;
            $_SESSION['password_reset_email'] = $email;
            $_SESSION['password_reset_code_hash'] = $codeHash;
            $_SESSION['password_reset_expires'] = time() + 300;
            $_SESSION['password_reset_attempts'] = 0;

            $phase = 'verify';
            $emailValue = $email;
            $message = $genericMessage;
            $messageType = 'success';
        }
    } elseif (($_POST['action'] ?? '') === 'reset') {
        $phase = 'verify';
        $emailValue = (string)($_SESSION['password_reset_email'] ?? '');
        $enteredCode = trim((string)($_POST['verification_code'] ?? ''));
        $password = (string)($_POST['password'] ?? '');
        $confirmPassword = (string)($_POST['confirm_password'] ?? '');

        if ($phase !== 'verify' || !isset($_SESSION['password_reset_code_hash'])) {
            clearPasswordReset();
            $phase = 'request';
            $message = 'Start a new password reset request.';
        } elseif (time() >= (int)$_SESSION['password_reset_expires']) {
            clearPasswordReset();
            $phase = 'request';
            $message = 'Your code expired. Request a new one.';
        } elseif (strlen($password) < 8) {
            $message = 'Choose a password with at least 8 characters.';
        } elseif ($password !== $confirmPassword) {
            $message = 'The passwords do not match.';
        } elseif (
            !preg_match('/^[0-9]{6}$/', $enteredCode) ||
            !hash_equals(
                (string)$_SESSION['password_reset_code_hash'],
                hash('sha256', $enteredCode)
            )
        ) {
            $_SESSION['password_reset_attempts'] =
                (int)($_SESSION['password_reset_attempts'] ?? 0) + 1;

            if ($_SESSION['password_reset_attempts'] >= 5) {
                clearPasswordReset();
                $phase = 'request';
                $message = 'Too many incorrect codes. Start a new reset request.';
            } else {
                $message = 'The verification code could not be verified.';
            }
        } elseif ((int)$_SESSION['password_reset_user_id'] < 1) {
            clearPasswordReset();
            $phase = 'request';
            $message = 'The verification code could not be verified. Start a new request.';
        } else {
            try {
                $userId = (int)$_SESSION['password_reset_user_id'];
                $stmt = $conn->prepare(
                    'SELECT id, role, account_status
                     FROM users WHERE id = ? LIMIT 1'
                );
                $stmt->bind_param('i', $userId);
                $stmt->execute();
                $user = $stmt->get_result()->fetch_assoc();
                $stmt->close();

                if (!$user || strtolower((string)$user['account_status']) !== 'active') {
                    clearPasswordReset();
                    $phase = 'request';
                    $message = 'This reset request is no longer available.';
                } else {
                    $role = strtolower(trim((string)$user['role']));

                    if ($role === 'admin') {
                        $adminToken = envValue('ADMIN_SETUP_TOKEN', '');
                        $submittedToken = (string)($_POST['admin_token'] ?? '');

                        if (
                            !is_string($adminToken) ||
                            strlen($adminToken) !== 32 ||
                            strlen($submittedToken) !== 32 ||
                            !hash_equals($adminToken, $submittedToken)
                        ) {
                            $message = 'Administrator recovery requires the valid setup token.';
                        }
                    }

                    if ($message === '') {
                        $pepper = envValue('APP_PEPPER', '');

                        if (!is_string($pepper) || $pepper === '') {
                            $message = 'Security configuration is unavailable. Contact the administrator.';
                        } else {
                            $salt = bin2hex(random_bytes(16));
                            $passwordHash = password_hash(
                                $password . $salt . $pepper,
                                PASSWORD_DEFAULT
                            );
                            $update = $conn->prepare(
                                "UPDATE users
                                 SET password_hash = ?, salt = ?
                                 WHERE id = ? AND account_status = 'active'"
                            );
                            $update->bind_param('ssi', $passwordHash, $salt, $userId);
                            $update->execute();
                            $updated = $update->affected_rows === 1;
                            $update->close();

                            if (!$updated) {
                                $message = 'The password could not be updated. Start a new reset request.';
                            } else {
                                clearPasswordReset();
                                $_SESSION = [];
                                session_regenerate_id(true);
                                header('Location: login.php?reset=1');
                                exit;
                            }
                        }
                    }
                }
            } catch (Throwable $e) {
                error_log('Password reset update error: ' . $e->getMessage());
                $message = 'The password could not be updated. Please try again.';
            }
        }
    }
}

$phase = isset(
    $_SESSION['password_reset_user_id'],
    $_SESSION['password_reset_email'],
    $_SESSION['password_reset_code_hash'],
    $_SESSION['password_reset_expires']
) ? 'verify' : 'request';
if ($phase === 'verify') {
    $emailValue = (string)($_SESSION['password_reset_email'] ?? $emailValue);
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Reset Password | SecuredAuth</title>
    <style>
        * { box-sizing: border-box; }
        body {
            margin: 0;
            min-height: 100vh;
            display: grid;
            place-items: center;
            padding: 24px;
            background:
                radial-gradient(ellipse at 12% 18%, rgba(212, 125, 85, 0.13), transparent 34%),
                #f7f5ef;
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
            margin: 0 0 12px;
            color: #244b3d;
            font-size: 12px;
            font-weight: bold;
            text-transform: uppercase;
        }
        h1 {
            margin: 0 0 10px;
            font-family: Georgia, "Times New Roman", serif;
            font-size: 34px;
            font-weight: normal;
        }
        .intro {
            margin: 0 0 24px;
            color: #64736d;
            line-height: 1.6;
        }
        label {
            display: block;
            margin: 17px 0 7px;
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
            margin-top: 23px;
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
            margin: 0 0 18px;
            padding: 12px 14px;
            border-left: 3px solid #b64236;
            background: #fff1ed;
            color: #85352e;
            line-height: 1.5;
        }
        .message.success {
            border-color: #3d765b;
            background: #edf6ef;
            color: #28523d;
        }
        .hint {
            margin: 8px 0 0;
            color: #64736d;
            font-size: 13px;
            line-height: 1.5;
        }
        .footer {
            margin: 22px 0 0;
            color: #64736d;
            text-align: center;
        }
        a { color: #244b3d; }
        @media (max-width: 480px) { body { padding: 16px; } }
    </style>
</head>
<body>
    <main>
        <p><a class="brand" href="index.html">SecuredAuth</a></p>
        <p class="kicker">Account recovery</p>
        <h1><?= $phase === 'request' ? 'Reset your password' : 'Verify and choose a new password' ?></h1>
        <p class="intro">
            <?= $phase === 'request'
                ? 'We’ll send a short-lived verification code to the email address on your account.'
                : 'Enter the code from your email and choose a new password.' ?>
        </p>

        <?php if ($message !== ''): ?>
            <div class="message <?= $messageType === 'success' ? 'success' : '' ?>" role="status">
                <?= htmlspecialchars($message, ENT_QUOTES, 'UTF-8') ?>
            </div>
        <?php endif; ?>

        <?php if ($phase === 'request'): ?>
            <form method="post" action="forgot_password.php">
                <input type="hidden" name="csrf_token" value="<?= resetEscape($_SESSION['password_reset_csrf']) ?>">
                <input type="hidden" name="action" value="request">

                <label for="email">Account email address</label>
                <input
                    id="email"
                    name="email"
                    type="email"
                    maxlength="254"
                    autocomplete="email"
                    value="<?= resetEscape($emailValue) ?>"
                    required
                >

                <button type="submit">Send verification code</button>
            </form>
        <?php else: ?>
            <form method="post" action="forgot_password.php">
                <input type="hidden" name="csrf_token" value="<?= resetEscape($_SESSION['password_reset_csrf']) ?>">
                <input type="hidden" name="action" value="reset">

                <label for="verification_code">Six-digit email code</label>
                <input
                    id="verification_code"
                    name="verification_code"
                    type="text"
                    inputmode="numeric"
                    pattern="[0-9]{6}"
                    minlength="6"
                    maxlength="6"
                    autocomplete="one-time-code"
                    required
                >

                <label for="password">New password</label>
                <input
                    id="password"
                    name="password"
                    type="password"
                    minlength="8"
                    autocomplete="new-password"
                    required
                >

                <label for="confirm_password">Confirm new password</label>
                <input
                    id="confirm_password"
                    name="confirm_password"
                    type="password"
                    minlength="8"
                    autocomplete="new-password"
                    required
                >

                <label for="admin_token">Admin recovery token (admins only)</label>
                <input
                    id="admin_token"
                    name="admin_token"
                    type="password"
                    minlength="32"
                    maxlength="32"
                    autocomplete="off"
                >
                <p class="hint">Admin password resets also require the private 32-character setup token.</p>

                <button type="submit">Reset password</button>
            </form>
            <p class="footer"><a href="forgot_password.php?restart=1">Start over</a></p>
        <?php endif; ?>

        <p class="footer"><a href="login.php">Return to sign in</a></p>
    </main>
</body>
</html>
