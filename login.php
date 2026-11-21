<?php
session_start();
require_once __DIR__ . "/db.php";

$message = "";
$isSuccess = false;

if (isset($_GET["registered"])) {
    $message = "Registration successful! Please log in.";
    $isSuccess = true;
} elseif (isset($_GET["admin_setup"])) {
    $message = "Administrator access is ready. Sign in to continue.";
    $isSuccess = true;
} elseif (isset($_GET["reset"])) {
    $message = "Password updated. Sign in with your new password.";
    $isSuccess = true;
}

if ($_SERVER["REQUEST_METHOD"] === "POST") {
    $email = trim($_POST["email"] ?? "");
    $password = $_POST["password"] ?? "";

    if ($email === "" || $password === "") {
        $message = "Enter your email address and password.";
    } elseif (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
        $message = "Enter a valid email address.";
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
                     WHERE email = ?
                     LIMIT 1"
                );

                $stmt->bind_param("s", $email);
                $stmt->execute();
                $user = $stmt->get_result()->fetch_assoc();
                $stmt->close();

                $validCredentials = (
                    $user &&
                    password_verify(
                        $password . $user["salt"] . $pepper,
                        $user["password_hash"]
                    )
                );

                if (!$validCredentials) {
                    $message = "Email or password is incorrect.";
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
                        $mail->SMTPSecure = MAIL_ENCRYPTION === 'ssl'
                            ? \PHPMailer\PHPMailer\PHPMailer::ENCRYPTION_SMTPS
                            : \PHPMailer\PHPMailer\PHPMailer::ENCRYPTION_STARTTLS;
                        $mail->Port = MAIL_PORT;

                        $mail->setFrom(MAIL_FROM_ADDRESS, MAIL_FROM_NAME);
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
        :root {
            --forest: #244b3d;
            --forest-deep: #17362d;
            --mint: #dcebe1;
            --paper: #f7f5ef;
            --ink: #1d2925;
            --muted: #64736d;
            --accent: #d47d55;
        }

        * {
            box-sizing: border-box;
        }

        body {
            margin: 0;
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            padding: 32px;
            font-family: "Trebuchet MS", "Segoe UI", sans-serif;
            background:
                radial-gradient(ellipse at 12% 18%, rgba(212, 125, 85, 0.14), transparent 34%),
                radial-gradient(ellipse at 92% 84%, rgba(36, 75, 61, 0.12), transparent 36%),
                var(--paper);
            color: var(--ink);
        }

        .auth-shell {
            width: 100%;
            max-width: 1200px;
            min-height: min(780px, calc(100vh - 64px));
            display: grid;
            grid-template-columns: minmax(0, 1.08fr) minmax(0, 0.92fr);
            overflow: hidden;
            border: 1px solid rgba(29, 41, 37, 0.08);
            border-radius: 8px;
            background: #fff;
            box-shadow: 0 28px 80px rgba(33, 48, 41, 0.16);
        }

        .story-panel {
            position: relative;
            display: flex;
            flex-direction: column;
            justify-content: space-between;
            min-height: 620px;
            padding: clamp(32px, 5vw, 64px);
            overflow: hidden;
            isolation: isolate;
            background: var(--forest-deep);
            color: #fff;
        }

        .story-panel::before,
        .story-panel::after {
            content: "";
            position: absolute;
            inset: 0;
            pointer-events: none;
        }

        .story-panel::before {
            z-index: -2;
            background: url("images/iStock-African-student.jpg") 54% center / cover no-repeat;
            transform: scale(1.03);
            animation: story-drift 48s ease-in-out infinite alternate;
        }

        .story-panel::after {
            z-index: -1;
            background:
                radial-gradient(ellipse at 48% 45%, transparent 28%, rgba(0, 0, 0, 0.32) 100%),
                linear-gradient(145deg, rgba(23, 54, 45, 0.86), rgba(31, 72, 57, 0.48));
        }

        @keyframes story-drift {
            from { transform: scale(1.03) translate3d(0, 0, 0); }
            to { transform: scale(1.09) translate3d(-0.4%, 0.3%, 0); }
        }

        .story-brand,
        .story-copy {
            position: relative;
            z-index: 1;
        }

        .story-brand {
            display: inline-flex;
            width: fit-content;
            align-items: center;
            gap: 12px;
            color: #fff;
            font-weight: bold;
            font-size: 19px;
            text-decoration: none;
        }

        .brand-mark {
            width: 44px;
            height: 44px;
            display: grid;
            place-items: center;
            flex: 0 0 44px;
            border-radius: 6px;
            background: var(--accent);
            color: #fff;
        }

        .brand-mark svg {
            width: 38px;
            height: 38px;
        }

        .story-copy {
            max-width: 460px;
            padding-top: 48px;
        }

        .story-copy h1 {
            margin: 0 0 16px;
            font-family: Georgia, "Times New Roman", serif;
            font-size: clamp(38px, 4vw, 58px);
            font-weight: normal;
            line-height: 1.06;
            text-wrap: balance;
        }

        .story-copy p {
            max-width: 350px;
            color: rgba(255, 255, 255, 0.92);
            font-size: 16px;
            line-height: 1.65;
            text-shadow: 0 1px 12px rgba(0, 0, 0, 0.55);
        }

        .form-panel {
            display: flex;
            align-items: center;
            justify-content: center;
            padding: clamp(32px, 5vw, 72px);
            background: #fff;
        }

        .form-content {
            width: 100%;
            max-width: 390px;
        }

        .form-kicker {
            margin: 0 0 14px;
            color: var(--forest);
            font-size: 12px;
            font-weight: bold;
            text-transform: uppercase;
        }

        .form-content h2 {
            margin: 0 0 10px;
            color: var(--ink);
            font-family: Georgia, "Times New Roman", serif;
            font-size: 38px;
            font-weight: normal;
            line-height: 1.15;
        }

        .intro {
            margin: 0 0 28px;
            color: var(--muted);
            line-height: 1.6;
        }

        label {
            display: block;
            margin: 18px 0 8px;
            color: #293a33;
            font-size: 14px;
            font-weight: bold;
        }

        input {
            width: 100%;
            min-height: 50px;
            padding: 12px 14px;
            border: 1px solid #cbd8d0;
            border-radius: 6px;
            background: #fcfdfb;
            color: var(--ink);
            font: inherit;
            font-size: 15px;
            transition: border-color 150ms ease, box-shadow 150ms ease, background 150ms ease;
        }

        input:focus {
            outline: none;
            border-color: var(--forest);
            background: #fff;
            box-shadow: 0 0 0 3px rgba(36, 75, 61, 0.15);
        }

        button {
            width: 100%;
            min-height: 52px;
            margin-top: 26px;
            padding: 13px 18px;
            border: 0;
            border-radius: 6px;
            background: var(--forest);
            color: #fff;
            font: inherit;
            font-size: 16px;
            font-weight: bold;
            cursor: pointer;
            transition: background-color 150ms ease, transform 150ms ease;
        }

        button:hover {
            background: var(--forest-deep);
        }

        button:active {
            transform: translateY(1px);
        }

        button:focus-visible,
        a:focus-visible {
            outline: 3px solid var(--accent);
            outline-offset: 3px;
        }

        .message {
            margin: 0 0 20px;
            padding: 12px 14px;
            border-left: 3px solid #b64236;
            background: #fff1ed;
            color: #85352e;
            font-size: 14px;
            line-height: 1.5;
        }

        .success {
            border-color: #3d765b;
            background: #edf6ef;
            color: #28523d;
        }

        .footer {
            margin: 24px 0 0;
            color: var(--muted);
            font-size: 14px;
            text-align: center;
        }

        .footer a {
            color: var(--forest);
            font-weight: bold;
            text-decoration-thickness: 1px;
            text-underline-offset: 3px;
        }

        @media (max-width: 760px) {
            body {
                min-height: 100vh;
                padding: 0;
            }

            .auth-shell {
                min-height: 100vh;
                grid-template-columns: 1fr;
                border: 0;
                border-radius: 0;
            }

            .story-panel {
                min-height: 280px;
                padding: 28px 26px;
            }

            .story-copy {
                padding-top: 38px;
            }

            .story-copy h1 {
                max-width: 400px;
                font-size: 38px;
            }

            .story-copy p {
                max-width: 390px;
                font-size: 14px;
            }

            .form-panel {
                padding: 36px 26px 48px;
            }
        }

        @media (max-width: 380px) {
            .story-panel {
                min-height: 250px;
                padding: 24px 20px;
            }

            .story-copy h1 {
                font-size: 34px;
            }

            .form-panel {
                padding-right: 20px;
                padding-left: 20px;
            }
        }

        @media (prefers-reduced-motion: reduce) {
            *,
            *::before,
            *::after {
                scroll-behavior: auto !important;
                animation-duration: 0.01ms !important;
                animation-iteration-count: 1 !important;
                transition-duration: 0.01ms !important;
            }
        }
    </style>
</head>

<body>
    <main class="auth-shell">
        <section class="story-panel" aria-label="SecuredAuth for students and schools">
            <a class="story-brand" href="index.html">
                <span class="brand-mark" aria-hidden="true">
                    <svg viewBox="0 0 48 48" fill="none" xmlns="http://www.w3.org/2000/svg">
                        <path d="M24 4 39 10v12c0 10.1-5.8 17.3-15 22-9.2-4.7-15-11.9-15-22V10L24 4Z" stroke="currentColor" stroke-width="2.4" stroke-linejoin="round"/>
                        <path d="M13.5 18.5c4.2-.8 7.6.1 10.5 2.8v12c-2.9-2.7-6.3-3.6-10.5-2.8v-12ZM34.5 18.5c-4.2-.8-7.6.1-10.5 2.8v12c2.9-2.7 6.3-3.6 10.5-2.8v-12Z" stroke="currentColor" stroke-width="2.2" stroke-linejoin="round"/>
                        <path d="M24 21.3v12" stroke="currentColor" stroke-width="2.2" stroke-linecap="round"/>
                    </svg>
                </span>
                <span>SecuredAuth</span>
            </a>

            <div class="story-copy">
                <h1>A safer start to every school day.</h1>
                <p>Secure access for the people who keep learning moving.</p>
            </div>
        </section>

        <section class="form-panel" aria-labelledby="login-heading">
            <div class="form-content">
                <p class="form-kicker">Secure campus access</p>
                <h2 id="login-heading">Welcome back</h2>
                <p class="intro">
                    Sign in with your email and password. We'll email you a verification
                    code before granting access to your account.
                </p>

                <?php if ($message !== ""): ?>
                    <p class="message <?= $isSuccess ? "success" : "" ?>" role="status">
                        <?= htmlspecialchars($message, ENT_QUOTES, "UTF-8") ?>
                    </p>
                <?php endif; ?>

                <form method="POST" action="login.php">
                    <label for="email">Registered email address</label>
                    <input
                        id="email"
                        name="email"
                        type="email"
                        maxlength="254"
                        autocomplete="username"
                        value="<?= htmlspecialchars($email ?? "", ENT_QUOTES, "UTF-8") ?>"
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

                    <button type="submit">Sign in</button>
                </form>

                <p class="footer">
                    <a href="forgot_password.php">Forgot password?</a>
                </p>

                <p class="footer">
                    New to SecuredAuth?
                    <a href="register.php">Create an account</a>
                </p>
            </div>
        </section>
    </main>
</body>
</html>