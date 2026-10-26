<?php
declare(strict_types=1);

session_start();

// Clear all session data, including pending OTP information.
$_SESSION = [];

// Remove the session cookie using its existing settings.
if (ini_get('session.use_cookies')) {
    $params = session_get_cookie_params();

    setcookie(
        session_name(),
        '',
        [
            'expires'  => time() - 42000,
            'path'     => $params['path'],
            'domain'   => $params['domain'],
            'secure'   => $params['secure'],
            'httponly' => $params['httponly'],
            'samesite' => $params['samesite'] ?? 'Lax',
        ]
    );
}

// Destroy the server-side session.
session_destroy();

// Return to the login page.
header('Location: login.php');
exit;