<?php
declare(strict_types=1);

require_once __DIR__ . '/config.php';

/**
 * Open the application's MySQL connection.
 *
 * Set DB_SSL=true to enable TLS (needed by Aiven, whose services require it).
 * If DB_SSL_CA contains a PEM bundle, it is written to a temporary file and
 * used to verify the server certificate. Without a CA bundle TLS is still
 * negotiated, but the server certificate is not verified.
 */
function db_connect(): mysqli
{
    $host = envValue('DB_HOST', '127.0.0.1');
    $port = (int)envValue('DB_PORT', '3306');
    $database = envValue('DB_NAME', 'secured_auth');
    $username = envValue('DB_USERNAME', 'root');
    $password = envValue('DB_PASSWORD', '');

    mysqli_report(MYSQLI_REPORT_ERROR | MYSQLI_REPORT_STRICT);

    $useSsl = filter_var(envValue('DB_SSL', 'false'), FILTER_VALIDATE_BOOL);
    if (!$useSsl) {
        $conn = new mysqli($host, $username, $password, $database, $port);
        $conn->set_charset('utf8mb4');
        return $conn;
    }

    $mysqli = mysqli_init();
    if (!$mysqli) {
        throw new mysqli_sql_exception('mysqli_init() failed');
    }

    $caFile = null;
    $caPem = envValue('DB_SSL_CA', '');
    if ($caPem !== '') {
        $caFile = @tempnam(sys_get_temp_dir(), 'securedauth-ca-');
        if ($caFile === false) {
            throw new mysqli_sql_exception('Unable to create a temporary CA file');
        }
        if (file_put_contents($caFile, $caPem) === false) {
            @unlink($caFile);
            throw new mysqli_sql_exception('Unable to write the temporary CA file');
        }
    }

    $mysqli->ssl_set(null, null, $caFile, null, null);

    try {
        $mysqli->real_connect(
            $host,
            $username,
            $password,
            $database,
            $port,
            null,
            MYSQLI_CLIENT_SSL
        );
        $mysqli->set_charset('utf8mb4');
    } finally {
        if ($caFile !== null) {
            @unlink($caFile);
        }
    }

    return $mysqli;
}
