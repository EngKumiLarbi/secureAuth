<?php
declare(strict_types=1);

session_start();

function e($value): string
{
    return htmlspecialchars((string)($value ?? ''), ENT_QUOTES, 'UTF-8');
}

function redirectToLogin(): never
{
    $_SESSION = [];
    session_destroy();
    header('Location: login.php');
    exit;
}

if (
    !isset($_SESSION['user_id'], $_SESSION['username']) ||
    strtolower((string)($_SESSION['role'] ?? '')) !== 'admin' ||
    ($_SESSION['two_factor_verified'] ?? false) !== true
) {
    redirectToLogin();
}

require_once __DIR__ . '/db.php';

$backupDirectory = envValue(
    'BACKUP_DIR',
    DIRECTORY_SEPARATOR === '\\'
        ? 'C:\\SecuredAuthBackups'
        : sys_get_temp_dir() . '/SecuredAuthBackups'
);
$testDatabase = 'secured_auth_restore_test';
$mysqlExe = envValue('MYSQL_PATH', DIRECTORY_SEPARATOR === '\\'
    ? 'C:\\Program Files\\MySQL\\MySQL Server 8.0\\bin\\mysql.exe'
    : '/usr/bin/mysql');
$dumpExe = envValue('MYSQLDUMP_PATH', DIRECTORY_SEPARATOR === '\\'
    ? 'C:\\Program Files\\MySQL\\MySQL Server 8.0\\bin\\mysqldump.exe'
    : '/usr/bin/mysqldump');

$error = '';
$success = '';
$backupFiles = [];

$_SESSION['csrf_token'] ??= bin2hex(random_bytes(32));

function auditRestore(mysqli $conn, int $adminId, string $action, string $details): void
{
    try {
        $stmt = $conn->prepare(
            'INSERT INTO audit_logs (user_id, action, details)
             VALUES (?, ?, ?)'
        );
        $stmt->bind_param('iss', $adminId, $action, $details);
        $stmt->execute();
        $stmt->close();
    } catch (Throwable $e) {
        error_log('Restore audit log failed: ' . $e->getMessage());
    }
}

function runProcess(array $arguments, string $stdin = ''): array
{
    $spec = [
        0 => ['pipe', 'r'],
        1 => ['pipe', 'w'],
        2 => ['pipe', 'w']
    ];

    $process = proc_open($arguments, $spec, $pipes);

    if (!is_resource($process)) {
        throw new RuntimeException('Could not start the MySQL utility.');
    }

    fwrite($pipes[0], $stdin);
    fclose($pipes[0]);

    $stdout = stream_get_contents($pipes[1]);
    fclose($pipes[1]);

    $stderr = stream_get_contents($pipes[2]);
    fclose($pipes[2]);

    $exitCode = proc_close($process);

    return [$exitCode, (string)$stdout, (string)$stderr];
}

try {
    $adminId = (int)$_SESSION['user_id'];

    $stmt = $conn->prepare(
        'SELECT username, role, account_status
         FROM users WHERE id = ? LIMIT 1'
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
        redirectToLogin();
    }

    $_SESSION['username'] = $admin['username'];

    if (!is_dir($backupDirectory)) {
        throw new RuntimeException('The backup folder does not exist.');
    }

    foreach (glob($backupDirectory . DIRECTORY_SEPARATOR . '*.sql') ?: [] as $path) {
        if (is_file($path)) {
            $backupFiles[] = [
                'name' => basename($path),
                'size' => filesize($path) ?: 0,
                'modified' => filemtime($path) ?: 0
            ];
        }
    }

    usort($backupFiles, fn($a, $b) => $b['modified'] <=> $a['modified']);

    if ($_SERVER['REQUEST_METHOD'] === 'POST') {
        $token = $_POST['csrf_token'] ?? '';
        if (
            !is_string($token) ||
            !hash_equals((string)$_SESSION['csrf_token'], $token)
        ) {
            throw new RuntimeException('Security check failed. Refresh the page.');
        }

        if (($_POST['confirm_restore'] ?? '') !== 'YES') {
            throw new RuntimeException('Type YES in the confirmation field.');
        }

        $filename = $_POST['backup_file'] ?? '';
        if (
            !is_string($filename) ||
            $filename === '' ||
            basename($filename) !== $filename ||
            !preg_match('/\A[A-Za-z0-9_.-]+\.sql\z/', $filename)
        ) {
            throw new RuntimeException('Choose a valid backup file.');
        }

        $sourceFile = $backupDirectory . DIRECTORY_SEPARATOR . $filename;
        if (!is_file($sourceFile) || !in_array($filename, array_column($backupFiles, 'name'), true)) {
            throw new RuntimeException('The selected backup was not found.');
        }

        if (!is_executable($mysqlExe) || !is_executable($dumpExe)) {
            throw new RuntimeException(
                'The mysql and mysqldump utilities were not found. Set MYSQL_PATH and MYSQLDUMP_PATH.'
            );
        }

        $host = envValue('DB_HOST', '127.0.0.1');
        $port = (int)envValue('DB_PORT', '3306');
        $dbUser = envValue('DB_USERNAME', 'root');
        $dbPassword = envValue('DB_PASSWORD', '');

        if ($dbPassword === '') {
            // An empty password may be valid for a local development account.
            // Never print the password to the page or log.
        }

        // Credentials are passed through a temporary option file rather than
        // exposed in command-line arguments. Keep it outside the web root.
        $optionFile = tempnam(sys_get_temp_dir(), 'sa_mysql_');
        if ($optionFile === false) {
            throw new RuntimeException('Could not create a temporary MySQL option file.');
        }

        $escapedPassword = str_replace(
            ["\\", "\"", "\n", "\r"],
            ["\\\\", "\\\"", "\\n", "\\r"],
            $dbPassword
        );
        $escapedUser = str_replace(
            ["\\", "\"", "\n", "\r"],
            ["\\\\", "\\\"", "\\n", "\\r"],
            $dbUser
        );
        $escapedHost = str_replace(
            ["\\", "\"", "\n", "\r"],
            ["\\\\", "\\\"", "\\n", "\\r"],
            $host
        );

        $optionContent = "[client]\n"
            . (filter_var(envValue('DB_SSL', 'false'), FILTER_VALIDATE_BOOL)
                ? "ssl-mode=REQUIRED\n"
                : '')
            . 'user="' . $escapedUser . '"' . "\n"
            . 'password="' . $escapedPassword . '"' . "\n"
            . 'host="' . $escapedHost . '"' . "\n"
            . 'port=' . $port . "\n";

        if (file_put_contents($optionFile, $optionContent, LOCK_EX) === false) {
            @unlink($optionFile);
            throw new RuntimeException('Could not write the temporary MySQL option file.');
        }

        @chmod($optionFile, 0600);

        try {
            // First create a safety dump of the TEST database.
            $safetyFile = $backupDirectory . DIRECTORY_SEPARATOR
                . 'pre_restore_test_' . date('Ymd_His') . '.sql';

            [$dumpCode, $dumpOut, $dumpErr] = runProcess([
                $dumpExe,
                '--defaults-extra-file=' . $optionFile,
                '--single-transaction',
                '--routines',
                '--triggers',
                '--databases',
                $testDatabase
            ]);

            if ($dumpCode !== 0) {
                throw new RuntimeException(
                    'Could not create a safety backup of the test database. Restore cancelled. '
                    . substr($dumpErr, 0, 1000)
                );
            }

            // Use shell-free process arguments. Save the dump output to the
            // safety file; do not allow the input backup to select another DB.
            if (file_put_contents($safetyFile, $dumpOut, LOCK_EX) === false) {
                throw new RuntimeException('Could not save the safety backup. Restore cancelled.');
            }

            // Refuse dumps containing database-selection statements or
            // qualified live-database references.
            $sql = file_get_contents($sourceFile);
            if ($sql === false || trim($sql) === '') {
                throw new RuntimeException('The selected backup is empty or unreadable.');
            }

            if (
                preg_match('/^\s*USE\s+[`"]?(?!secured_auth_restore_test\b)[A-Za-z0-9_]+/im', $sql) ||
                preg_match('/\bCREATE\s+DATABASE\b/i', $sql) ||
                preg_match('/\bDROP\s+DATABASE\b/i', $sql) ||
                preg_match('/\bsecured_auth\s*\./i', $sql)
            ) {
                throw new RuntimeException(
                    'This SQL backup contains database-selection statements. It was not imported. A database-aware restore must be prepared separately.'
                );
            }

            // Import into the explicitly selected test database only.
            [$restoreCode, $restoreOut, $restoreErr] = runProcess([
                $mysqlExe,
                '--defaults-extra-file=' . $optionFile,
                $testDatabase
            ], $sql);

            if ($restoreCode !== 0) {
                auditRestore(
                    $conn,
                    $adminId,
                    'DATABASE_RESTORE_FAILED',
                    'Test database restore failed for ' . $filename
                );

                throw new RuntimeException(
                    'Test restore failed. The pre-restore safety dump was saved. '
                    . substr($restoreErr, 0, 1200)
                );
            }

            auditRestore(
                $conn,
                $adminId,
                'DATABASE_RESTORE_TEST',
                'Restored ' . $filename . ' into ' . $testDatabase
            );

            $success = 'Test restore completed successfully. Database: '
                . $testDatabase . '. Safety dump: ' . basename($safetyFile);

            $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
        } finally {
            @unlink($optionFile);
        }
    }
} catch (Throwable $ex) {
    error_log('SecuredAuth restore error: ' . $ex->getMessage());
    $error = $ex->getMessage();
}
?>
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Database Restore | SecuredAuth</title>
<style>
*{box-sizing:border-box}
body{margin:0;background:#f1f5f9;color:#172033;font-family:Arial,sans-serif}
.sidebar{position:fixed;inset:0 auto 0 0;width:235px;background:#172554;padding:25px 16px;color:#fff}
.brand{font-size:23px;font-weight:bold;margin-bottom:10px}
.label{font-size:11px;color:#bfdbfe;margin-bottom:25px}
.sidebar a{display:block;color:#fff;text-decoration:none;padding:12px;border-radius:7px;margin:6px 0}
.sidebar a:hover,.sidebar a.active{background:#1d4ed8}
main{margin-left:235px;padding:28px}
.subtitle{color:#64748b;line-height:1.5}
.panel{background:#fff;padding:22px;border-radius:12px;margin-bottom:20px;box-shadow:0 4px 15px #0000000a}
.notice{background:#fef3c7;color:#92400e;padding:14px;border-radius:8px;margin-bottom:18px;line-height:1.5}
.error,.success{padding:12px;border-radius:7px;margin-bottom:15px;overflow-wrap:anywhere}
.error{background:#fee2e2;color:#991b1b}.success{background:#dcfce7;color:#166534}
.table-wrap{overflow-x:auto}
table{width:100%;border-collapse:collapse;min-width:550px}
th,td{text-align:left;padding:12px;border-bottom:1px solid #e2e8f0;font-size:13px}
th{background:#f8fafc;color:#475569}
select,input,button{font:inherit;padding:10px;border:1px solid #cbd5e1;border-radius:7px;max-width:100%}
button{background:#1d4ed8;color:white;border:0;cursor:pointer;margin-top:12px}
button:hover{background:#1e40af}
form{display:grid;gap:12px;max-width:620px}
@media(max-width:700px){.sidebar{position:static;width:100%;height:auto}.sidebar a{display:inline-block}main{margin:0;padding:14px}.panel{padding:14px}}
</style>
</head>
<body>
<aside class="sidebar">
    <div class="brand">SecuredAuth</div>
    <div class="label">SYSTEM ADMINISTRATOR</div>
    <a href="admin.php">Dashboard</a>
    <a href="manage_users.php">User Management</a>
    <a href="audit_logs.php">Audit Logs</a>
    <a href="backup.php">Database Backup</a>
    <a href="restore.php" class="active">Database Restore</a>
    <a href="logout.php">Log out</a>
</aside>
<main>
    <h1>Database Restore</h1>
    <p class="subtitle">Restore a selected SQL backup into the isolated test database.</p>

    <div class="notice">
        <strong>Test-only restore:</strong> this page imports into
        <code>secured_auth_restore_test</code>, not the live <code>secured_auth</code>
        database. A safety dump is required before importing.
    </div>

    <?php if ($error !== ''): ?><div class="error"><?= e($error) ?></div><?php endif; ?>
    <?php if ($success !== ''): ?><div class="success"><?= e($success) ?></div><?php endif; ?>

    <section class="panel">
        <h2>Available Backups</h2>
        <p class="subtitle">Folder: <?= e($backupDirectory) ?></p>
        <div class="table-wrap">
        <table>
            <thead><tr><th>Backup File</th><th>Date Modified</th><th>Size</th></tr></thead>
            <tbody>
            <?php if (!$backupFiles): ?>
                <tr><td colspan="3">No SQL backup files found.</td></tr>
            <?php else: foreach ($backupFiles as $file): ?>
                <tr>
                    <td><?= e($file['name']) ?></td>
                    <td><?= e(date('d F Y, H:i:s', (int)$file['modified'])) ?></td>
                    <td><?= e(number_format((int)$file['size'] / 1024, 2)) ?> KB</td>
                </tr>
            <?php endforeach; endif; ?>
            </tbody>
        </table>
        </div>
    </section>

    <section class="panel">
        <h2>Test Restore</h2>
        <p class="subtitle">This will change data in the test database only.</p>
        <form method="post">
            <input type="hidden" name="csrf_token" value="<?= e($_SESSION['csrf_token']) ?>">
            <label for="backup_file">Choose backup</label>
            <select id="backup_file" name="backup_file" required>
                <option value="">Select a backup file</option>
                <?php foreach ($backupFiles as $file): ?>
                    <option value="<?= e($file['name']) ?>"><?= e($file['name']) ?></option>
                <?php endforeach; ?>
            </select>
            <label for="confirm_restore">Type YES to confirm the test restore</label>
            <input id="confirm_restore" name="confirm_restore" required pattern="YES" autocomplete="off">
            <button type="submit">Restore to Test Database</button>
        </form>
    </section>
</main>
</body>
</html>