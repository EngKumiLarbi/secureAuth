<?php
declare(strict_types=1);

require_once __DIR__ . '/mail_config.php';

/**
 * Send a plain-text email.
 *
 * MAIL_PROVIDER=api uses an HTTPS email API (Brevo by default, or Resend).
 * This works on hosts that block outbound SMTP ports, such as Render's
 * free web services. Any other value keeps the original SMTP/PHPMailer path.
 */
function sendMail(
    string $toEmail,
    string $toName,
    string $subject,
    string $body
): void {
    $provider = strtolower((string)envValue('MAIL_PROVIDER', 'smtp'));

    if ($provider === 'api') {
        sendMailViaApi($toEmail, $toName, $subject, $body);
        return;
    }

    sendMailViaSmtp($toEmail, $toName, $subject, $body);
}

function sendMailViaApi(
    string $toEmail,
    string $toName,
    string $subject,
    string $body
): void {
    $apiKey = (string)envValue('MAIL_API_KEY', '');
    if ($apiKey === '') {
        throw new RuntimeException('MAIL_API_KEY is not configured.');
    }

    if (!filter_var(MAIL_FROM_ADDRESS, FILTER_VALIDATE_EMAIL)) {
        throw new RuntimeException(
            'MAIL_FROM_ADDRESS is not a valid email address: ' . MAIL_FROM_ADDRESS
        );
    }

    $apiProvider = strtolower((string)envValue('MAIL_API_PROVIDER', 'brevo'));

    if ($apiProvider === 'resend') {
        $url = 'https://api.resend.com/emails';
        $payload = [
            'from' => MAIL_FROM_ADDRESS,
            'to' => [$toEmail],
            'subject' => $subject,
            'text' => $body,
        ];
        $headers = [
            'Authorization: Bearer ' . $apiKey,
            'Content-Type: application/json',
        ];
    } else {
        $url = 'https://api.brevo.com/v3/smtp/email';
        $payload = [
            'sender' => [
                'name' => MAIL_FROM_NAME,
                'email' => MAIL_FROM_ADDRESS,
            ],
            'to' => [
                ['email' => $toEmail, 'name' => $toName],
            ],
            'subject' => $subject,
            'textContent' => $body,
        ];
        $headers = [
            'api-key: ' . $apiKey,
            'Content-Type: application/json',
        ];
    }

    $json = json_encode($payload, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
    if ($json === false) {
        throw new RuntimeException('Could not encode the mail API request.');
    }

    $context = stream_context_create([
        'http' => [
            'method' => 'POST',
            'header' => implode("\r\n", $headers) . "\r\n",
            'content' => $json,
            'timeout' => 15,
            'ignore_errors' => true,
        ],
    ]);

    $response = @file_get_contents($url, false, $context);
    $statusLine = $http_response_header[0] ?? '';
    if (!preg_match('/HTTP\/\S+\s+(\d{3})/', $statusLine, $matches)) {
        throw new RuntimeException(
            'No response from the mail API. Check DNS and outbound HTTPS access.'
        );
    }

    $status = (int)$matches[1];
    if ($status < 200 || $status >= 300) {
        throw new RuntimeException(
            'Mail API returned HTTP ' . $status . ': '
            . substr((string)$response, 0, 300)
        );
    }
}

function sendMailViaSmtp(
    string $toEmail,
    string $toName,
    string $subject,
    string $body
): void {
    require_once __DIR__ . '/vendor/autoload.php';

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
    $mail->addAddress($toEmail, $toName);
    $mail->isHTML(false);
    $mail->Subject = $subject;
    $mail->Body = $body;
    $mail->send();
}
