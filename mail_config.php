<?php
declare(strict_types=1);

require_once __DIR__ . '/config.php';

define('MAIL_HOST', envValue('MAIL_HOST', 'smtp.gmail.com'));
define('MAIL_PORT', (int)envValue('MAIL_PORT', '587'));
define('MAIL_ENCRYPTION', strtolower(envValue('MAIL_ENCRYPTION', 'tls')));
define('MAIL_USERNAME', envValue('MAIL_USERNAME', ''));
define('MAIL_PASSWORD', envValue('MAIL_PASSWORD', ''));

$mailFromAddress = envValue('MAIL_FROM_ADDRESS', '');
define(
    'MAIL_FROM_ADDRESS',
    $mailFromAddress !== '' ? $mailFromAddress : MAIL_USERNAME
);
define('MAIL_FROM_NAME', envValue('MAIL_FROM_NAME', 'SecuredAuth'));