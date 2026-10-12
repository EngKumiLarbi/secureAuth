<?php
session_start();
require_once __DIR__ . "/db.php";

$message = "";
$messageType = "error";

if ($_SERVER["REQUEST_METHOD"] === "POST") {
    $fullName = trim($_POST["full_name"] ?? "");
    $username = trim($_POST["username"] ?? "");
    $email = trim($_POST["email"] ?? "");
    $password = $_POST["password"] ?? "";
    $confirmPassword = $_POST["confirm_password"] ?? "";
    $requestedRole = strtolower(trim($_POST["role"] ?? ""));

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
        $message = "Admin accounts must be created by an authorized administrator.";
    } else {
        $pepper = getenv("APP_PEPPER");

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

                    // Candidate and Manager accounts activate automatically.
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
        * { box-sizing: border-box; }

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
            max-width: 480px;
            background: white;
            padding: 32px;
            border-radius: 16px;
            box-shadow: 0 12px 35px rgba(15, 23, 42, 0.10);
        }

        h1 { margin: 0 0 8px; color: #173b75; }
        .intro { color: #64748b; margin-bottom: 24px; }

        label {
            display: block;
            font-weight: bold;
            margin: 15px 0 7px;
        }

        input, select {
            width: 100%;
            padding: 12px;
            border: 1px solid #cbd5e1;
            border-radius: 8px;
            font-size: 15px;
        }

        input:focus, select:focus {
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

        button:hover { background: #2454a0; }

        .message {
            padding: 12px;
            border-radius: 8px;
            background: #fee2e2;
            color: #991b1b;
            margin-bottom: 15px;
        }

        .hint {
            margin-top: 8px;
            color: #64748b;
            font-size: 13px;
            line-height: 1.5;
        }

        .footer {
            text-align: center;
            margin-top: 20px;
            color: #64748b;
        }

        a { color: #173b75; }
    </style>
</head>
<body>
    <main class="card">
        <h1>Create an account</h1>
        <p class="intro">Join SecuredAuth with a secure account.</p>

        <?php if ($message !== ""): ?>
            <div class="message">
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
                <option value="candidate">Candidate</option>
                <option value="manager">Manager</option>
                <option value="admin">Admin</option>
            </select>

            <p class="hint">
                Candidate and Manager accounts activate automatically.
                Admin accounts require an authorized administrator.
            </p>

            <button type="submit">Create Account</button>
        </form>

        <p class="footer">
            Already registered?
            <a href="login.php">Log in</a>
        </p>
    </main>
</body>
</html>