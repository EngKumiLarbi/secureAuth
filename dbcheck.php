<?php
/**
 * Temporary deployment diagnostic.
 *
 * Open in a browser with ?token=<ADMIN_SETUP_TOKEN or APP_PEPPER>.
 * It never prints DB_PASSWORD or any other secret value. Delete this file
 * once the database connection is working.
 */
declare(strict_types=1);

require_once __DIR__ . '/db_connect.php';

header('Content-Type: text/plain; charset=utf-8');

$provided = (string)($_GET['token'] ?? '');
$accepted = false;

foreach (['ADMIN_SETUP_TOKEN', 'APP_PEPPER'] as $secretKey) {
    $secret = envValue($secretKey, '');
    if ($secret !== '' && $provided !== '' && hash_equals((string)$secret, $provided)) {
        $accepted = true;
        break;
    }
}

if (!$accepted) {
    http_response_code(403);
    echo "Forbidden.\nOpen dbcheck.php?token=<ADMIN_SETUP_TOKEN or APP_PEPPER>\n";
    exit;
}

$lastErrorFile = sys_get_temp_dir() . '/securedauth_last_login_error.txt';
if (is_file($lastErrorFile)) {
    echo "Last login error:\n  "
        . trim(str_replace(["\r", "\n"], ' ', (string)file_get_contents($lastErrorFile)))
        . "\n\n";
}

echo 'PHP ' . PHP_VERSION . ' (' . PHP_SAPI . ")\n\n";

echo "Environment visibility (values hidden):\n";
foreach (
    ['DB_HOST', 'DB_PORT', 'DB_NAME', 'DB_USERNAME', 'DB_PASSWORD', 'DB_SSL', 'DB_SSL_CA']
    as $key
) {
    $value = envValue($key, null);
    $state = ($value === null || $value === '') ? 'MISSING' : 'set';
    $source = isset($_ENV[$key])
        ? '$_ENV'
        : (isset($_SERVER[$key])
            ? '$_SERVER'
            : (getenv($key) !== false ? 'getenv' : '-'));
    printf("  %-14s %-8s %s\n", $key, $state, $source);
}

echo "\nMail configuration (values hidden):\n";
foreach (
    ['MAIL_HOST', 'MAIL_PORT', 'MAIL_USERNAME', 'MAIL_PASSWORD', 'MAIL_FROM_ADDRESS']
    as $key
) {
    $value = envValue($key, null);
    $state = ($value === null || $value === '') ? 'MISSING' : 'set';
    printf("  %-18s %s\n", $key, $state);
}

$host = envValue('DB_HOST', '127.0.0.1');
$port = (int)envValue('DB_PORT', '3306');
$database = envValue('DB_NAME', 'secured_auth');
$username = envValue('DB_USERNAME', 'root');

echo "\nEffective config (non-secret values):\n";
echo "  host=$host port=$port database=$database user=$username\n";
echo '  TLS=' . (filter_var(envValue('DB_SSL', 'false'), FILTER_VALIDATE_BOOL) ? 'on' : 'off')
    . ' CA=' . (envValue('DB_SSL_CA', '') !== '' ? 'provided' : 'not provided') . "\n\n";

$socket = @fsockopen($host, $port, $errno, $errstr, 5);
if ($socket) {
    fclose($socket);
    echo "TCP connect $host:$port: OK\n";
} else {
    echo "TCP connect $host:$port: FAILED ($errno: $errstr)\n";
}

try {
    $conn = db_connect();
    echo "MySQL login: OK\n";
    $result = $conn->query('SHOW TABLES');
    $tables = array_column($result->fetch_all(MYSQLI_NUM), 0);
    echo 'Tables: ' . ($tables ? implode(', ', $tables) : '(none - schema not imported)') . "\n";
    $conn->close();
} catch (mysqli_sql_exception $e) {
    echo 'MySQL login: FAILED (' . $e->getCode() . ') ' . $e->getMessage() . "\n";
}

if (isset($_GET['mailtest'])) {
    require_once __DIR__ . '/mail_config.php';

    $smtpHost = MAIL_HOST;
    echo "\nSMTP network probes for $smtpHost:\n";
    echo '  DNS: ' . gethostbyname($smtpHost) . "\n";

    foreach ([587, 465, 25] as $probePort) {
        $started = microtime(true);
        $socket = @fsockopen($smtpHost, $probePort, $probeErrno, $probeErrstr, 5);
        if ($socket) {
            fclose($socket);
            printf(
                "  %s:%d TCP OK (%.2fs)\n",
                $smtpHost,
                $probePort,
                microtime(true) - $started
            );
        } else {
            printf(
                "  %s:%d TCP FAILED (%d: %s)\n",
                $smtpHost,
                $probePort,
                $probeErrno,
                $probeErrstr
            );
        }
    }

    $testPort = isset($_GET['mailport']) ? (int)$_GET['mailport'] : MAIL_PORT;
    $testSecure = isset($_GET['mailsecure'])
        ? strtolower((string)$_GET['mailsecure'])
        : MAIL_ENCRYPTION;

    echo "\nMail self-test (port=$testPort secure=$testSecure):\n";
    $mail = new \PHPMailer\PHPMailer\PHPMailer(true);
    try {
        $mail->isSMTP();
        $mail->Host = $smtpHost;
        $mail->SMTPAuth = true;
        $mail->Username = MAIL_USERNAME;
        $mail->Password = MAIL_PASSWORD;
        $mail->SMTPSecure = $testSecure === 'ssl'
            ? \PHPMailer\PHPMailer\PHPMailer::ENCRYPTION_SMTPS
            : \PHPMailer\PHPMailer\PHPMailer::ENCRYPTION_STARTTLS;
        $mail->Port = $testPort;
        $mail->setFrom(MAIL_FROM_ADDRESS, MAIL_FROM_NAME);
        $mail->addAddress(MAIL_USERNAME);
        $mail->isHTML(false);
        $mail->Subject = 'SecuredAuth mail self-test';
        $mail->Body = 'If you can read this, SMTP is configured correctly.';

        if (isset($_GET['maildebug'])) {
            $mail->SMTPDebug = 2;
            $mail->Debugoutput = static function (string $line, int $level): void {
                echo '    [' . $level . '] ' . trim($line) . "\n";
            };
        }

        $mail->send();
        echo '  SMTP send to ' . MAIL_USERNAME . ": OK\n";
    } catch (Throwable $e) {
        echo '  SMTP send FAILED: ' . $e->getMessage() . "\n";
    }
}
