<?php
session_start();
require_once __DIR__ . "/db.php";

$message = "";
$messageType = "error";
$requestedRole = "";

if ($_SERVER["REQUEST_METHOD"] === "POST") {
    $fullName = trim($_POST["full_name"] ?? "");
    $username = trim($_POST["username"] ?? "");
    $email = trim($_POST["email"] ?? "");
    $password = $_POST["password"] ?? "";
    $confirmPassword = $_POST["confirm_password"] ?? "";
    $requestedRole = strtolower(trim($_POST["role"] ?? ""));
    $adminToken = envValue("ADMIN_SETUP_TOKEN", "");
    $submittedAdminToken = (string)($_POST["admin_token"] ?? "");

    if (
        $fullName === "" ||
        $username === "" ||
        $email === "" ||
        $password === "" ||
        $confirmPassword === ""
    ) {
        $message = "Please complete all fields.";
    } elseif (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
        $message = "Please enter a valid email address.";
    } elseif (!in_array(
        $requestedRole,
        ["candidate", "manager", "admin"],
        true
    )) {
        $message = "Please select a valid role.";
    } elseif (strlen($password) < 8) {
        $message = "Your password must contain at least 8 characters.";
    } elseif ($password !== $confirmPassword) {
        $message = "Your passwords do not match.";
    } elseif ($requestedRole === "admin") {
        if (!is_string($adminToken) || strlen($adminToken) !== 32) {
            $message = "Admin registration is not configured. Contact the administrator.";
        } elseif (
            strlen($submittedAdminToken) !== 32 ||
            !hash_equals($adminToken, $submittedAdminToken)
        ) {
            $message = "The administrator setup token is incorrect.";
        }
    }

    if ($message === "") {
        $pepper = envValue("APP_PEPPER");

        if ($pepper === false || $pepper === "") {
            $message = "Security configuration is missing. Contact the administrator.";
        } else {
            try {
                $check = $conn->prepare(
                    "SELECT id FROM users
                     WHERE username = ? OR email = ?
                     LIMIT 1"
                );

                $check->bind_param("ss", $username, $email);
                $check->execute();
                $existingUser = $check->get_result()->fetch_assoc();
                $check->close();

                if ($existingUser) {
                    $message = "That username or email is already registered.";
                } else {
                    $salt = bin2hex(random_bytes(16));

                    $passwordHash = password_hash(
                        $password . $salt . $pepper,
                        PASSWORD_DEFAULT
                    );

                    // New accounts are active; admins must provide the setup token above.
                    $assignedRole = $requestedRole;
                    $accountStatus = "active";

                    $stmt = $conn->prepare(
                        "INSERT INTO users
                        (
                            username,
                            email,
                            password_hash,
                            role,
                            salt,
                            full_name,
                            requested_role,
                            account_status
                        )
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?)"
                    );

                    $stmt->bind_param(
                        "ssssssss",
                        $username,
                        $email,
                        $passwordHash,
                        $assignedRole,
                        $salt,
                        $fullName,
                        $requestedRole,
                        $accountStatus
                    );

                    $stmt->execute();
                    $stmt->close();

                    header("Location: login.php?registered=1");
                    exit;
                }
            } catch (Throwable $e) {
                error_log(
                    "SecuredAuth registration error: " . $e->getMessage()
                );

                $message = "Registration could not be completed. Please try again.";
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
    <title>Register | SecuredAuth</title>

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

        * { box-sizing: border-box; }

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
            min-height: min(800px, calc(100vh - 64px));
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
            font-size: 19px;
            font-weight: bold;
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
            padding: clamp(32px, 4.5vw, 64px);
            background: #fff;
        }

        .form-content {
            width: 100%;
            max-width: 440px;
        }

        .form-kicker {
            margin: 0 0 12px;
            color: var(--forest);
            font-size: 12px;
            font-weight: bold;
            text-transform: uppercase;
        }

        .form-content h2 {
            margin: 0 0 8px;
            color: var(--ink);
            font-family: Georgia, "Times New Roman", serif;
            font-size: 36px;
            font-weight: normal;
            line-height: 1.15;
        }

        .intro {
            margin: 0 0 20px;
            color: var(--muted);
            line-height: 1.55;
        }

        label {
            display: block;
            margin: 14px 0 7px;
            color: #293a33;
            font-size: 14px;
            font-weight: bold;
        }

        input, select {
            width: 100%;
            min-height: 46px;
            padding: 11px 13px;
            border: 1px solid #cbd8d0;
            border-radius: 6px;
            background: #fcfdfb;
            color: var(--ink);
            font: inherit;
            font-size: 15px;
            transition: border-color 150ms ease, box-shadow 150ms ease, background 150ms ease;
        }

        input:focus, select:focus {
            outline: none;
            border-color: var(--forest);
            background: #fff;
            box-shadow: 0 0 0 3px rgba(36, 75, 61, 0.15);
        }

        button {
            width: 100%;
            min-height: 50px;
            margin-top: 22px;
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

        button:hover { background: var(--forest-deep); }
        button:active { transform: translateY(1px); }

        button:focus-visible, a:focus-visible {
            outline: 3px solid var(--accent);
            outline-offset: 3px;
        }

        .message {
            margin: 0 0 16px;
            padding: 12px 14px;
            border-left: 3px solid #b64236;
            background: #fff1ed;
            color: #85352e;
            font-size: 14px;
            line-height: 1.5;
        }

        .hint {
            margin-top: 7px;
            color: var(--muted);
            font-size: 13px;
            line-height: 1.5;
        }

        .footer {
            margin: 20px 0 0;
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
                min-height: 250px;
                padding: 26px;
            }

            .story-copy {
                padding-top: 32px;
            }

            .story-copy h1 {
                max-width: 400px;
                font-size: 36px;
            }

            .story-copy p {
                max-width: 390px;
                font-size: 14px;
            }

            .form-panel {
                padding: 32px 26px 44px;
            }
        }

        @media (max-width: 380px) {
            .story-panel { padding: 22px 20px; }
            .story-copy h1 { font-size: 33px; }
            .form-panel { padding-right: 20px; padding-left: 20px; }
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
                <h1>One secure account for your next step.</h1>
                <p>Join the school community with confidence.</p>
            </div>
        </section>

        <section class="form-panel" aria-labelledby="register-heading">
            <div class="form-content">
                <p class="form-kicker">Create your account</p>
                <h2 id="register-heading">Get started</h2>
                <p class="intro">Set up your SecuredAuth profile to continue.</p>

                <?php if ($message !== ""): ?>
                    <div class="message" role="alert">
                        <?= htmlspecialchars($message, ENT_QUOTES, "UTF-8") ?>
                    </div>
                <?php endif; ?>

                <form method="POST" action="register.php">
                    <label for="full_name">Full name</label>
                    <input
                        id="full_name"
                        name="full_name"
                        type="text"
                        maxlength="150"
                        autocomplete="name"
                        required
                    >

                    <label for="username">Username</label>
                    <input
                        id="username"
                        name="username"
                        type="text"
                        maxlength="100"
                        autocomplete="username"
                        required
                    >

                    <label for="email">Email address</label>
                    <input
                        id="email"
                        name="email"
                        type="email"
                        maxlength="254"
                        autocomplete="email"
                        required
                    >

                    <label for="password">Password</label>
                    <input
                        id="password"
                        name="password"
                        type="password"
                        minlength="8"
                        autocomplete="new-password"
                        required
                    >

                    <label for="confirm_password">Confirm password</label>
                    <input
                        id="confirm_password"
                        name="confirm_password"
                        type="password"
                        minlength="8"
                        autocomplete="new-password"
                        required
                    >

                    <label for="role">Choose your role</label>
                    <select id="role" name="role" required>
                        <option value="">-- Select a role --</option>
                        <option value="candidate" <?= $requestedRole === "candidate" ? "selected" : "" ?>>Candidate</option>
                        <option value="manager" <?= $requestedRole === "manager" ? "selected" : "" ?>>Manager</option>
                        <option value="admin" <?= $requestedRole === "admin" ? "selected" : "" ?>>Admin</option>
                    </select>

                    <p class="hint">
                        Candidate and Manager accounts activate automatically.
                        Admin registration requires the private 32-character setup token.
                    </p>

                    <div class="admin-token" id="admin-token-field" hidden>
                        <label for="admin_token">Administrator setup token</label>
                        <input
                            id="admin_token"
                            name="admin_token"
                            type="password"
                            minlength="32"
                            maxlength="32"
                            autocomplete="off"
                        >
                    </div>

                    <button type="submit">Create account</button>
                </form>

                <p class="footer">
                    Already registered?
                    <a href="login.php">Log in</a>
                </p>

            </div>
        </section>
    </main>
    <script>
        const roleSelect = document.getElementById("role");
        const adminTokenField = document.getElementById("admin-token-field");
        const adminTokenInput = document.getElementById("admin_token");

        function updateAdminTokenField() {
            const isAdmin = roleSelect.value === "admin";
            adminTokenField.hidden = !isAdmin;
            adminTokenInput.required = isAdmin;
        }

        roleSelect.addEventListener("change", updateAdminTokenField);
        updateAdminTokenField();
    </script>
</body>
</html>