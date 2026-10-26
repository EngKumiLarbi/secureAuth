<?php
declare(strict_types=1);

require_once __DIR__ . '/bootstrap.php';
requireApiMethod('POST');

$conn = apiDatabase();
$data = apiReadJson();

$username = trim((string)($data['username'] ?? ''));
$email = trim((string)($data['email'] ?? ''));
$password = (string)($data['password'] ?? '');

if ($username === '' || $email === '' || $password === '') {
    apiResponse(400, [
        'success' => false,
        'message' => 'Username, email and password are required.'
    ]);
}

try {
    $pepper = envValue('APP_PEPPER');

    if (!is_string($pepper) || $pepper === '') {
        apiResponse(500, [
            'success' => false,
            'message' => 'Security configuration is unavailable.'
        ]);
    }

    $stmt = $conn->prepare(
        'SELECT id, username, email, password_hash, salt,
                role, account_status
         FROM users
         WHERE username = ?
         LIMIT 1'
    );
    $stmt->bind_param('s', $username);
    $stmt->execute();
    $user = $stmt->get_result()->fetch_assoc();
    $stmt->close();

    $valid = $user
        && filter_var($email, FILTER_VALIDATE_EMAIL)
        && strcasecmp($email, (string)$user['email']) === 0
        && password_verify(
            $password . $user['salt'] . $pepper,
            $user['password_hash']
        );

    if (!$valid) {
        apiResponse(401, [
            'success' => false,
            'message' => 'Username, email or password is incorrect.'
        ]);
    }

    $role = strtolower(trim((string)$user['role']));
    if ($role === 'user') {
        $role = 'candidate';
    }

    if (
        $user['account_status'] !== 'active' ||
        !in_array($role, ['candidate', 'manager', 'admin'], true)
    ) {
        apiResponse(403, [
            'success' => false,
            'message' => 'This account is not active or is awaiting approval.'
        ]);
    }

    require_once dirname(__DIR__) . '/vendor/autoload.php';
    require_once dirname(__DIR__) . '/mail_config.php';

    $code = (string) random_int(100000, 999999);
    $codeHash = hash('sha256', $code);
    $expiresAt = date('Y-m-d H:i:s', time() + 300);
    $userId = (int)$user['id'];

    // Invalidate any earlier mobile OTP for this user.
    $stmt = $conn->prepare(
        'DELETE FROM mobile_login_otps WHERE user_id = ?'
    );
    $stmt->bind_param('i', $userId);
    $stmt->execute();
    $stmt->close();

    $stmt = $conn->prepare(
        'INSERT INTO mobile_login_otps (user_id, code_hash, expires_at)
         VALUES (?, ?, ?)'
    );
    $stmt->bind_param('iss', $userId, $codeHash, $expiresAt);
    $stmt->execute();
    $otpId = (int)$conn->insert_id;
    $stmt->close();

    try {
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
        $mail->addAddress((string)$user['email'], (string)$user['username']);
        $mail->isHTML(false);
        $mail->Subject = 'Your CarePoint verification code';
        $mail->Body =
            "Your CarePoint verification code is: {$code}\n\n" .
            "It expires in 5 minutes. If you did not attempt to sign in, " .
            "please ignore this email.";

        $mail->send();
    } catch (Throwable $mailError) {
        // Do not leave a usable code if email delivery fails.
        $stmt = $conn->prepare(
            'DELETE FROM mobile_login_otps WHERE id = ?'
        );
        $stmt->bind_param('i', $otpId);
        $stmt->execute();
        $stmt->close();
        throw $mailError;
    }

    apiResponse(200, [
        'success' => true,
        'requires_two_factor' => true,
        'message' => 'Verification code sent to your registered email.',
        'username' => (string)$user['username']
    ]);

} catch (Throwable $e) {
    error_log('CarePoint mobile login error: ' . $e->getMessage());

    apiResponse(500, [
        'success' => false,
        'message' => 'Unable to start mobile sign-in. Check the server configuration.'
    ]);
}