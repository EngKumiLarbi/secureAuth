<?php
$host = "127.0.0.1";
$username = "root";
$password = "nhyiBaby=123";
$database = "secured_auth";
$port = 3306;

mysqli_report(MYSQLI_REPORT_ERROR | MYSQLI_REPORT_STRICT);

try {
    $conn = new mysqli(
        $host,
        $username,
        $password,
        $database,
        $port
    
    );

    $conn->set_charset("utf8mb4");

} catch (mysqli_sql_exception $e) {
    error_log("Database connection error: " . $e->getMessage());
    die("Database connection failed. Please check your MySQL settings and database name.");
}
?>

