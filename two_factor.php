<?php
session_start();
require_once __DIR__ . "/db.php";

function clearPendingVerification(): void
{
    unset(
        $_SESSION["pending_2fa_user_id"],
        $_SESSION["pending_2fa_username"],
        $_SESSION["pending_2fa_email"],
        $_SESSION["pending_2fa_role"],
        $_SESSION["pending_2fa_code"],
        $_SESSION["pending_2fa_expires"]
    );
}

if (
    !isset(
        $_SESSION["pending_2fa_user_id"],
        $_SESSION["pending_2fa_code"],
        $_SESSION["pending_2fa_expires"]
    )
) {
    header("Location: login.php");
    exit;
}

$message = "";
$messageType = "";

if ($_SERVER["REQUEST_METHOD"] === "POST") {
    $enteredCode = trim($_POST["verification_code"] ?? "");

    if (time() >= (int) $_SESSION["pending_2fa_expires"]) {
        clearPendingVerification();
        $message = "Your code has expired. Please log in again.";
        $messageType = "error";
    } elseif (
        !preg_match('/^[0-9]{6}$/', $enteredCode) ||
        !hash_equals(
            (string) $_SESSION["pending_2fa_code"],
            hash("sha256", $enteredCode)
        )
    ) {
        $message = "Invalid verification code. Please try again.";
        $messageType = "error";
    } else {
        try {
            // Re-check the account directly in the database.
            $userId = (int) $_SESSION["pending_2fa_user_id"];

            $stmt = $conn->prepare(
                "SELECT id, username, email, role, account_status
                 FROM users
                 WHERE id = ?
                 LIMIT 1"
            );

            $stmt->bind_param("i", $userId);
            $stmt->execute();
            $user = $stmt->get_result()->fetch_assoc();
            $stmt->close();

            $role = strtolower(trim($user["role"] ?? ""));

            // Support legacy accounts using the role "User".
            if ($role === "user") {
                $role = "candidate";
            }

            if (
                !$user ||
                strtolower(trim($user["account_status"] ?? "")) !== "active" ||
                !in_array($role, ["admin", "manager", "candidate"], true)
            ) {
                clearPendingVerification();
                session_regenerate_id(true);
                $_SESSION = [];

                $message = "This account is unavailable or disabled. Please contact the administrator.";
                $messageType = "error";
            } else {
                // Remove pending OTP data and establish the authenticated session.
                $username = $user["username"];
                $email = $user["email"];
                $authenticatedId = (int) $user["id"];

                clearPendingVerification();
                session_regenerate_id(true);

                $_SESSION["user_id"] = $authenticatedId;
                $_SESSION["username"] = $username;
                $_SESSION["email"] = $email;
                $_SESSION["role"] = $role;
                $_SESSION["two_factor_verified"] = true;

                if ($role === "admin") {
                    header("Location: admin.php");
                } elseif ($role === "manager") {
                    header("Location: manager.php");
                } else {
                    header("Location: candidate.php");
                }

                exit;
            }
        } catch (Throwable $e) {
            error_log("SecuredAuth 2FA error: " . $e->getMessage());
            $message = "We couldn't verify your account. Please try logging in again.";
            $messageType = "error";
        }
    }
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Two-Factor Verification - SecuredAuth</title>
    <style>
        * { box-sizing: border-box; }

        body {
            margin: 0;
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            padding: 20px;
            font-family: Arial, sans-serif;
            background: #10172a;
        }

        .verification-card {
            width: 100%;
            max-width: 420px;
            padding: 35px;
            background: #fff;
            border-radius: 16px;
            box-shadow: 0 15px 40px rgba(0,0,0,.25);
        }

        h1 {
            margin-top: 0;
            color: #10172a;
            text-align: center;
        }

        p {
            color: #64748b;
            line-height: 1.6;
            text-align: center;
        }

        label {
            display: block;
            margin: 22px 0 8px;
            color: #334155;
            font-weight: bold;
        }

        input {
            width: 100%;
            padding: 13px;
            border: 1px solid #cbd5e1;
            border-radius: 8px;
            font-size: 20px;
            text-align: center;
            letter-spacing: 6px;
        }

        button {
            width: 100%;
            margin-top: 20px;
            padding: 14px;
            border: none;
            border-radius: 8px;
            background: #2563eb;
            color: white;
            font-size: 16px;
            font-weight: bold;
            cursor: pointer;
        }

        .error {
            color: #b91c1c;
            background: #fee2e2;
            padding: 12px;
            border-radius: 8px;
        }
    </style>
</head>
<body>
    <main class="verification-card">
        <h1>Secured<span style="color:#2563eb">Auth</span></h1>

        <p>
            Enter the six-digit verification code sent to your email
            to complete your sign-in.
        </p>

        <?php if ($message !== ""): ?>
            <p class="<?= htmlspecialchars($messageType, ENT_QUOTES, 'UTF-8') ?>">
                <?= htmlspecialchars($message, ENT_QUOTES, 'UTF-8') ?>
            </p>
        <?php endif; ?>

        <form method="post" action="two_factor.php">
            <label for="verification_code">Verification code</label>
            <input
                type="text"
                id="verification_code"
                name="verification_code"
                inputmode="numeric"
                pattern="[0-9]{6}"
                maxlength="6"
                minlength="6"
                autocomplete="one-time-code"
                placeholder="000000"
                required
            >
            <button type="submit">Verify and Continue</button>
        </form>
    </main>
</body>
</html>