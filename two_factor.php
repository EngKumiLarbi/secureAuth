<?php
session_start();

if (
    !isset($_SESSION["pending_2fa_user_id"]) ||
    !isset($_SESSION["pending_2fa_code"]) ||
    !isset($_SESSION["pending_2fa_expires"])
) {
    header("Location: login.php");
    exit;
}

$message = "";
$messageType = "";

if ($_SERVER["REQUEST_METHOD"] === "POST") {
    $enteredCode = trim($_POST["verification_code"] ?? "");

    if (time() > $_SESSION["pending_2fa_expires"]) {
        unset(
            $_SESSION["pending_2fa_user_id"],
            $_SESSION["pending_2fa_username"],
            $_SESSION["pending_2fa_email"],
            $_SESSION["pending_2fa_role"],
            $_SESSION["pending_2fa_code"],
            $_SESSION["pending_2fa_expires"]
        );

        $message = "Your code has expired. Please log in again.";
        $messageType = "error";
    } elseif (
        !preg_match('/^[0-9]{6}$/', $enteredCode) ||
        !hash_equals(
            $_SESSION["pending_2fa_code"],
            hash("sha256", $enteredCode)
        )
    ) {
        $message = "Invalid verification code. Please try again.";
        $messageType = "error";
    } else {
        session_regenerate_id(true);

        // Complete authentication only after code verification.
        $_SESSION["user_id"] = $_SESSION["pending_2fa_user_id"];
        $_SESSION["username"] = $_SESSION["pending_2fa_username"];
        $_SESSION["email"] = $_SESSION["pending_2fa_email"];
        $_SESSION["role"] = $_SESSION["pending_2fa_role"];
        $_SESSION["two_factor_verified"] = true;

        unset(
            $_SESSION["pending_2fa_user_id"],
            $_SESSION["pending_2fa_username"],
            $_SESSION["pending_2fa_email"],
            $_SESSION["pending_2fa_role"],
            $_SESSION["pending_2fa_code"],
            $_SESSION["pending_2fa_expires"]
        );

        $role = strtolower(trim($_SESSION["role"]));

        if ($role === "admin") {
            header("Location: admin.php");
        } elseif ($role === "manager") {
            header("Location: manager.php");
        } else {
            header("Location: candidate.php");
        }

        exit;
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
        * {
            box-sizing: border-box;
        }

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
            background: #ffffff;
            border-radius: 16px;
            box-shadow: 0 15px 40px rgba(0, 0, 0, 0.25);
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

        .message {
            margin-top: 15px;
            font-size: 14px;
        }

        .error {
            color: #b91c1c;
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
            <p class="message <?= htmlspecialchars($messageType) ?>">
                <?= htmlspecialchars($message) ?>
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
