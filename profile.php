<?php
session_start();
require_once 'db.php';

// Make sure the user is logged in
if (!isset($_SESSION['user_id'])) {
    header("Location: index.php");
    exit;
}

$user_id = $_SESSION['user_id'];
$message = "";

// Get the logged-in user's information
$stmt = $conn->prepare(
    "SELECT id, username, full_name, email FROM users WHERE id = ?"
);
$stmt->bind_param("i", $user_id);
$stmt->execute();
$result = $stmt->get_result();
$user = $result->fetch_assoc();
$stmt->close();

if (!$user) {
    exit("User profile not found.");
}

// Update the user's email
if ($_SERVER["REQUEST_METHOD"] === "POST") {
    $full_name = trim($_POST['full_name'] ?? '');
    $email = trim($_POST['email'] ?? '');

    if ($full_name === '') {
        $message = "Please enter your full name.";
    } elseif (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
        $message = "Please enter a valid email address.";
    } else {
        $stmt = $conn->prepare(
            "UPDATE users SET full_name = ?, email = ? WHERE id = ?"
        );

        $stmt->bind_param("ssi", $full_name, $email, $user_id);

        if ($stmt->execute()) {
            $message = "Profile updated successfully!";
            $user['full_name'] = $full_name;
            $user['email'] = $email;
        } else {
            $message = "Could not update your profile.";
        }

        $stmt->close();
    }
}
        
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>My Profile - SecuredAuth</title>

    <style>
        body {
            font-family: Arial, sans-serif;
            background: #f2f4fa;
            margin: 0;
            padding: 40px 15px;
        }

        .profile-card {
            max-width: 450px;
            margin: auto;
            background: white;
            padding: 30px;
            border-radius: 14px;
            box-shadow: 0 5px 20px #00000012;
        }

        h2 {
            color: #263b80;
        }

        label {
            display: block;
            margin-top: 20px;
            font-weight: bold;
        }

        input {
            width: 100%;
            box-sizing: border-box;
            padding: 12px;
            margin-top: 8px;
            border: 1px solid #ccc;
            border-radius: 7px;
        }

        input[readonly] {
            background: #f1f1f1;
        }

        button {
            width: 100%;
            margin-top: 25px;
            padding: 13px;
            border: none;
            border-radius: 7px;
            background: #263b80;
            color: white;
            cursor: pointer;
        }

        .message {
            margin-top: 18px;
            color: #263b80;
        }
    </style>
</head>

<body>
    <div class="profile-card">
        <h2>My Profile</h2>
        <p>View and update your account information.</p>

        <form method="POST">
            <label for="username">Username</label>
            <input
                id="username"
                type="text"
                value="<?= htmlspecialchars($user['username']) ?>"
                readonly
            >
            
<label for="full_name">Full Name</label>
<input
    id="full_name"
    type="text"
    name="full_name"
    value="<?= htmlspecialchars($user['full_name'] ?? '') ?>"
    placeholder="Enter your full name"
    required
>

            <label for="email">Email</label>
            <input
                id="email"
                type="email"
                name="email"
                value="<?= htmlspecialchars($user['email'] ?? '') ?>"
                required
            >

            <button type="submit">Update Profile</button>
        </form>

        <?php if ($message !== ""): ?>
            <p class="message">
                <?= htmlspecialchars($message) ?>
            </p>
        <?php endif; ?>
    </div>
</body>
</html>


