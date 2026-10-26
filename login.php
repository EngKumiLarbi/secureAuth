<?php
session_start();
require_once __DIR__ . "/db.php";

$message = "";
$isSuccess = false;

if (isset($_GET["registered"])) {
    $message = "Registration successful! Please log in.";
    $isSuccess = true;
}

if ($_SERVER["REQUEST_METHOD"] === "POST") {
    $username = trim($_POST["username"] ?? "");
    $email = trim($_POST["email"] ?? "");
    $password = $_POST["password"] ?? "";

    if ($username === "" || $email === "" || $password === "") {
        $message = "Please complete all fields.";
    } else {
        $pepper = envValue("APP_PEPPER");

        if ($pepper === false || $pepper === "") {
            $message = "Security configuration is missing. Contact the administrator.";
        } else {
            try {
                $stmt = $conn->prepare(
                    "SELECT id, username, email, password_hash, salt,
                            role, account_status
                     FROM users
                     WHERE username = ?
                     LIMIT 1"
                );

                $stmt->bind_param("s", $username);
                $stmt->execute();
                $user = $stmt->get_result()->fetch_assoc();
                $stmt->close();

                $validCredentials = (
                    $user &&
                    strcasecmp($email, $user["email"]) === 0 &&
                    password_verify(
                        $password . $user["salt"] . $pepper,
                        $user["password_hash"]
                    )
                );

                if (!$validCredentials) {
                    $message = "Username, email, or password is incorrect.";
                } else {
                    // Read the role assigned to this account.
                    $role = strtolower(trim($user["role"]));

                    // Support older accounts saved with the role "User".
                    if ($role === "user") {
                        $role = "candidate";
                    }

                    // Only active accounts with recognized roles may sign in.
                    if (
                        $user["account_status"] !== "active" ||
                        !in_array($role, ["candidate", "manager", "admin"], true)
                    ) {
                        $message = "Your account is awaiting approval.";
                    } else {
                        require_once __DIR__ . "/vendor/autoload.php";
                        require_once __DIR__ . "/mail_config.php";

                        // Generate a six-digit, short-lived verification code.
                        $code = (string) random_int(100000, 999999);

                        $mail = new \PHPMailer\PHPMailer\PHPMailer(true);
                        $mail->isSMTP();
                        $mail->Host = MAIL_HOST;
                        $mail->SMTPAuth = true;
                        $mail->Username = MAIL_USERNAME;
                        $mail->Password = MAIL_PASSWORD;
                        $mail->SMTPSecure =
                            \PHPMailer\PHPMailer\PHPMailer::ENCRYPTION_STARTTLS;
                        $mail->Port = MAIL_PORT;

                        $mail->setFrom(MAIL_USERNAME, MAIL_FROM_NAME);
                        $mail->addAddress($user["email"], $user["username"]);
                        $mail->isHTML(false);
                        $mail->Subject = "Your SecuredAuth verification code";
                        $mail->Body =
                            "Your SecuredAuth verification code is: " . $code .
                            "\n\nThis code expires in 5 minutes. " .
                            "If you did not try to sign in, you can ignore this email.";

                        $mail->send();

                        // Do not authenticate the user until OTP verification.
                        session_regenerate_id(true);

                        unset(
                            $_SESSION["user_id"],
                            $_SESSION["username"],
                            $_SESSION["email"],
                            $_SESSION["role"],
                            $_SESSION["two_factor_verified"]
                        );

                        $_SESSION["pending_2fa_user_id"] = $user["id"];
                        $_SESSION["pending_2fa_username"] = $user["username"];
                        $_SESSION["pending_2fa_email"] = $user["email"];
                        $_SESSION["pending_2fa_role"] = $role;
                        $_SESSION["pending_2fa_code"] = hash("sha256", $code);
                        $_SESSION["pending_2fa_expires"] = time() + 300;

                        header("Location: two_factor.php");
                        exit;
                    }
                }
            } catch (Throwable $e) {
                error_log("SecuredAuth login error: " . $e->getMessage());
                $message = "We couldn't complete your login. Please try again.";
            }
        }
    }
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Login | SecuredAuth</title>

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
            padding: 24px;
            font-family: Arial, sans-serif;
            background: #f1f5f9;
            color: #172033;
        }

        .card {
            width: 100%;
            max-width: 450px;
            padding: 32px;
            background: #ffffff;
            border-radius: 16px;
            box-shadow: 0 12px 35px rgba(15, 23, 42, 0.10);
        }

        h1 {
            margin-top: 0;
            color: #173b75;
        }

        .intro {
            color: #64748b;
            line-height: 1.5;
        }

        label {
            display: block;
            margin: 17px 0 7px;
            font-weight: bold;
        }

        input {
            width: 100%;
            padding: 12px;
            border: 1px solid #cbd5e1;
            border-radius: 8px;
            font-size: 15px;
        }

        input:focus {
            outline: 2px solid #93c5fd;
            border-color: #2563eb;
        }

        button {
            width: 100%;
            margin-top: 24px;
            padding: 13px;
            border: none;
            border-radius: 8px;
            background: #173b75;
            color: white;
            font-size: 16px;
            font-weight: bold;
            cursor: pointer;
        }

        button:hover {
            background: #2454a0;
        }

        .message {
            padding: 12px;
            border-radius: 8px;
            background: #fee2e2;
            color: #991b1b;
            line-height: 1.5;
        }

        .success {
            background: #dcfce7;
            color: #166534;
        }

        .footer {
            text-align: center;
            margin-top: 20px;
            color: #64748b;
        }

        a {
            color: #173b75;
        }
    </style>
</head>

<body>
    <main class="card">
        <h1>SecuredAuth Login</h1>

        <p class="intro">
            Sign in securely. We'll email you a verification code
            before granting access to your account.
        </p>

        <?php if ($message !== ""): ?>
            <p class="message <?= $isSuccess ? "success" : "" ?>">
                <?= htmlspecialchars($message, ENT_QUOTES, "UTF-8") ?>
            </p>
        <?php endif; ?>

        <form method="POST" action="login.php">
            <label for="username">Username</label>
            <input
                id="username"
                name="username"
                type="text"
                autocomplete="username"
                required
            >

            <label for="email">Registered email address</label>
            <input
                id="email"
                name="email"
                type="email"
                autocomplete="email"
                required
            >

            <label for="password">Password</label>
            <input
                id="password"
                name="password"
                type="password"
                autocomplete="current-password"
                required
            >

            <button type="submit">Sign In and Send OTP</button>
        </form>

        <p class="footer">
            Don't have an account?
            <a href="register.php">Register here</a>
        </p>
    </main>
</body>
</html>