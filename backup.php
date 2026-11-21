<?php
declare(strict_types=1);

session_start();

require_once __DIR__ . '/db.php';

/* Escape output safely. */
function e(mixed $value): string
{
    return htmlspecialchars(
        (string)($value ?? ''),
        ENT_QUOTES,
        'UTF-8'
    );
}

/* Require an authenticated Admin who has completed OTP verification. */
if (
    !isset($_SESSION['user_id'], $_SESSION['username'], $_SESSION['role']) ||
    strtolower((string)$_SESSION['role']) !== 'admin' ||
    ($_SESSION['two_factor_verified'] ?? false) !== true
) {
    header('Location: login.php');
    exit;
}

$adminId = (int) $_SESSION['user_id'];

$success = '';
$error = '';
$backupFiles = [];

$backupDirectory = 'C:\\SecuredAuthBackups';

try {
    /* Confirm the Admin still exists and has an active account. */
    $stmt = $conn->prepare(
        'SELECT username, role, account_status
         FROM users
         WHERE id = ?
         LIMIT 1'
    );

    $stmt->bind_param('i', $adminId);
    $stmt->execute();
    $admin = $stmt->get_result()->fetch_assoc();
    $stmt->close();

    if (
        !$admin ||
        strtolower((string)$admin['role']) !== 'admin' ||
        strtolower((string)$admin['account_status']) !== 'active'
    ) {
        $_SESSION = [];
        session_destroy();

        header('Location: login.php');
        exit;
    }

    $_SESSION['username'] = $admin['username'];

    /* Prepare the backup folder outside the website directory. */
    if (!is_dir($backupDirectory)) {
        if (!mkdir($backupDirectory, 0700, true) && !is_dir($backupDirectory)) {
            throw new RuntimeException(
                'The backup folder could not be created.'
            );
        }
    }

    if (!is_writable($backupDirectory)) {
        throw new RuntimeException(
            'PHP cannot write to C:\\SecuredAuthBackups. Check the folder permissions.'
        );
    }

    /* Locate mysqldump.exe. */
    $candidates = [
    'C:\\Program Files\\MySQL\\MySQL Server 8.0\\bin\\mysqldump.exe',
    'C:\\xampp\\mysql\\bin\\mysqldump.exe',
    'C:\\Program Files\\MySQL\\MySQL Server 8.4\\bin\\mysqldump.exe'
];
    $mysqldump = null;

    foreach ($candidates as $candidate) {
        if (is_file($candidate)) {
            $mysqldump = $candidate;
            break;
        }
    }

    /* Create a backup only when the form is submitted. */
    if (
        $_SERVER['REQUEST_METHOD'] === 'POST' &&
        ($_POST['action'] ?? '') === 'backup'
    ) {
        $postedToken = $_POST['csrf_token'] ?? '';
        $sessionToken = $_SESSION['csrf_token'] ?? '';

        if (
            !is_string($postedToken) ||
            !is_string($sessionToken) ||
            $sessionToken === '' ||
            !hash_equals($sessionToken, $postedToken)
        ) {
            throw new RuntimeException(
                'Security check failed. Refresh this page and try again.'
            );
        }

        if ($mysqldump === null) {
            throw new RuntimeException(
                'mysqldump.exe was not found. Check C:\\xampp\\mysql\\bin.'
            );
        }


$dbHost = envValue('DB_HOST', '127.0.0.1');
$dbPort = (int) envValue('DB_PORT', '3306');
$dbName = envValue('DB_NAME', 'secured_auth');
$dbUser = envValue('DB_USERNAME', 'root');
$dbPassword = envValue('DB_PASSWORD', '');

        if (!$dbHost || !$dbName || !$dbUser || $dbPort < 1) {
            throw new RuntimeException(
                'Database settings are incomplete. Check your .env file.'
            );
        }

        /* Create a temporary MySQL credentials file. */
        $defaultsFile = tempnam(sys_get_temp_dir(), 'sa_db_');

        if ($defaultsFile === false) {
            throw new RuntimeException(
                'Could not create temporary database credentials.'
            );
        }

        $destination = '';
        $output = [];
        $exitCode = 1;

        try {
            $escapeOption = static function (string $value): string {
                return str_replace(
                    ["\\", "\"", "\n", "\r"],
                    ["\\\\", "\\\"", "\\n", "\\r"],
                    $value
                );
            };

            $defaultsContent =
                "[client]\n" .
                'user="' . $escapeOption((string)$dbUser) . '"' . "\n" .
                'password="' . $escapeOption((string)$dbPassword) . '"' . "\n" .
                'host="' . $escapeOption((string)$dbHost) . '"' . "\n" .
                'port=' . $dbPort . "\n";

            if (
                file_put_contents(
                    $defaultsFile,
                    $defaultsContent,
                    LOCK_EX
                ) === false
            ) {
                throw new RuntimeException(
                    'Could not write temporary database credentials.'
                );
            }

            @chmod($defaultsFile, 0600);

            $filename = 'secured_auth_' .
                date('Y-m-d_H-i-s') . '_' .
                bin2hex(random_bytes(3)) . '.sql';

            $destination = $backupDirectory .
                DIRECTORY_SEPARATOR . $filename;

            $command =
                escapeshellarg($mysqldump) .
                ' --defaults-extra-file=' . escapeshellarg($defaultsFile) .
                ' --single-transaction --routines --triggers --events --no-tablespaces' .
                ' --result-file=' . escapeshellarg($destination) .
                ' ' . escapeshellarg((string)$dbName) .
                ' 2>&1';

            exec($command, $output, $exitCode);

        } finally {
            if (is_file($defaultsFile)) {
                @unlink($defaultsFile);
            }
        }

        if (
            $exitCode !== 0 ||
            !is_file($destination) ||
            filesize($destination) === 0
        ) {
            if ($destination !== '' && is_file($destination)) {
                @unlink($destination);
            }

           $errorDetails = implode("\n", $output);

if ($errorDetails === '') {
    $errorDetails = 'No error details were returned. Exit code: ' . $exitCode;
}

throw new RuntimeException(
    'MySQL backup diagnostic: ' . $errorDetails
);

            throw new RuntimeException(
                'Backup failed. Check MySQL configuration and permissions.'
            );
        }

        /* Record the successful backup in the audit log. */
        try {
            $actorUsername = (string)$admin['username'];
            $action = 'DATABASE_BACKUP';
            $details = 'Created database backup: ' . basename($destination);

            $audit = $conn->prepare(
                'INSERT INTO audit_logs
                (actor_user_id, actor_username, action, target_user_id,
                 target_username, details, created_at)
                VALUES (?, ?, ?, NULL, NULL, ?, NOW())'
            );

            $audit->bind_param(
                'isss',
                $adminId,
                $actorUsername,
                $action,
                $details
            );

            $audit->execute();
            $audit->close();

        } catch (Throwable $auditError) {
            error_log(
                'Backup audit logging failed: ' . $auditError->getMessage()
            );
        }

        $success = 'Backup created successfully: ' . basename($destination);
    }

    /* Generate a CSRF token for the form. */
    if (
        !isset($_SESSION['csrf_token']) ||
        !is_string($_SESSION['csrf_token'])
    ) {
        $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
    }

    /* List existing SQL backups. */
    foreach (glob($backupDirectory . DIRECTORY_SEPARATOR . '*.sql') ?: [] as $file) {
        if (is_file($file)) {
            $backupFiles[] = [
                'name' => basename($file),
                'size' => filesize($file),
                'modified' => filemtime($file)
            ];
        }
    }

    usort(
        $backupFiles,
        static fn(array $a, array $b): int =>
            $b['modified'] <=> $a['modified']
    );

} catch (Throwable $ex) {
    error_log('SecuredAuth backup page error: ' . $ex->getMessage());
    $error = $ex->getMessage();
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Database Backup | SecuredAuth</title>

<style>
*{box-sizing:border-box}
body{margin:0;background:#f1f5f9;color:#172033;font-family:Arial,sans-serif}
.sidebar{position:fixed;inset:0 auto 0 0;width:235px;background:#172554;padding:25px 16px;color:white}
.brand{font-size:23px;font-weight:bold;margin-bottom:10px}
.label{font-size:11px;color:#bfdbfe;margin-bottom:25px}
.sidebar a{display:block;color:white;text-decoration:none;padding:12px;border-radius:7px;margin:6px 0}
.sidebar a:hover,.sidebar a.active{background:#1d4ed8}
main{margin-left:235px;padding:28px;max-width:1200px}
h1{margin-top:0}
.subtitle{color:#64748b;line-height:1.6}
.panel{background:white;padding:22px;border-radius:12px;margin-bottom:20px;box-shadow:0 4px 15px #0000000a}
button{background:#1d4ed8;color:white;border:0;padding:12px 18px;border-radius:7px;font-weight:bold;cursor:pointer}
button:hover{background:#1e40af}
.success{background:#dcfce7;color:#166534;padding:12px;border-radius:7px;margin-bottom:15px;overflow-wrap:anywhere}
.error{background:#fee2e2;color:#991b1b;padding:12px;border-radius:7px;margin-bottom:15px;overflow-wrap:anywhere}
.table-wrap{overflow-x:auto}
table{width:100%;border-collapse:collapse;min-width:500px}
th,td{text-align:left;padding:12px;border-bottom:1px solid #e2e8f0;font-size:13px}
th{background:#f8fafc;color:#475569}
@media(max-width:700px){
.sidebar{position:static;width:100%;height:auto}
.sidebar a{display:inline-block}
main{margin:0;padding:14px}
.panel{padding:14px}
}
</style>
</head>

<body>
<aside class="sidebar">
    <div class="brand">SecuredAuth</div>
    <div class="label">SYSTEM ADMINISTRATOR</div>
    <a href="admin.php">Dashboard</a>
    <a href="manage_users.php">User Management</a>
    <a href="audit_logs.php">Audit Logs</a>
    <a href="backup.php" class="active">Database Backup</a>
    <a href="restore.php">Test Restore</a>
    <a href="logout.php">Log out</a>
</aside>

<main>
    <h1>Database Backup</h1>
    <p class="subtitle">
        Create and review database backups. Backup files are stored outside
        the website folder.
    </p>

    <p class="subtitle">
        Successful backups are recorded in Audit Logs. Restores are limited
        to the isolated test database.
    </p>

    <?php if ($success !== ''): ?>
        <div class="success"><?= e($success) ?></div>
    <?php endif; ?>

    <?php if ($error !== ''): ?>
        <div class="error"><?= e($error) ?></div>
    <?php endif; ?>

    <section class="panel">
        <h2>Create New Backup</h2>
        <p class="subtitle">
            Destination: <strong>C:\SecuredAuthBackups</strong>
        </p>

        <form method="post" action="backup.php">
            <input
                type="hidden"
                name="csrf_token"
                value="<?= e($_SESSION['csrf_token'] ?? '') ?>"
            >
            <input type="hidden" name="action" value="backup">
            <button type="submit">Create Database Backup</button>
        </form>
    </section>

    <section class="panel">
        <h2>Existing Backups</h2>
        <p class="subtitle">
            SQL files currently found in the backup folder.
        </p>

        <div class="table-wrap">
            <table>
                <thead>
                    <tr>
                        <th>Backup File</th>
                        <th>Modified</th>
                        <th>File Size</th>
                    </tr>
                </thead>
                <tbody>
                <?php if (!$backupFiles): ?>
                    <tr>
                        <td colspan="3">No SQL backup files found.</td>
                    </tr>
                <?php else: ?>
                    <?php foreach ($backupFiles as $file): ?>
                        <tr>
                            <td><?= e($file['name']) ?></td>
                            <td>
                                <?= e(date('d F Y, H:i:s', (int)$file['modified'])) ?>
                            </td>
                            <td>
                                <?= e(number_format((int)$file['size'] / 1024, 2)) ?> KB
                            </td>
                        </tr>
                    <?php endforeach; ?>
                <?php endif; ?>
                </tbody>
            </table>
        </div>
    </section>
</main>
</body>
</html>