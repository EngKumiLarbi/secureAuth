-- SecuredAuth database schema
-- Target: MySQL 8.0+ (also works with MariaDB 10.5+)
--
-- Import into an EMPTY database with the database already selected, e.g.:
--   mysql -h <DB_HOST> -P <DB_PORT> -u <DB_USERNAME> -p <DB_NAME> < schema.sql
--
-- This file intentionally contains no CREATE DATABASE or USE statements, so
-- the target database is controlled by the client connection / Render DB_NAME.
--
-- After importing: register an account, then visit /setup_admin.php with a
-- valid 32-character ADMIN_SETUP_TOKEN to promote the first administrator.

SET NAMES utf8mb4;

-- Application / website accounts.
CREATE TABLE users (
    id                INT UNSIGNED NOT NULL AUTO_INCREMENT,
    username          VARCHAR(150) NOT NULL,
    email             VARCHAR(254) NOT NULL,
    password_hash     VARCHAR(255) NOT NULL,
    salt              CHAR(32) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    full_name         VARCHAR(150) NOT NULL,
    role              VARCHAR(32) NOT NULL DEFAULT 'candidate',
    requested_role    VARCHAR(32) DEFAULT NULL,
    account_status    VARCHAR(20) NOT NULL DEFAULT 'active',
    two_factor_enabled TINYINT(1) NOT NULL DEFAULT 0,
    created_at        TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    UNIQUE KEY uq_users_username (username),
    UNIQUE KEY uq_users_email (email),
    KEY idx_users_role (role),
    KEY idx_users_account_status (account_status)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Administrative action history.
-- user_id is a legacy column still referenced by restore.php; new code should
-- use actor_user_id / actor_username.
CREATE TABLE audit_logs (
    id              INT UNSIGNED NOT NULL AUTO_INCREMENT,
    actor_user_id   INT UNSIGNED DEFAULT NULL,
    actor_username  VARCHAR(150) DEFAULT NULL,
    action          VARCHAR(100) NOT NULL,
    target_user_id  INT UNSIGNED DEFAULT NULL,
    target_username VARCHAR(150) DEFAULT NULL,
    details         TEXT,
    user_id         INT UNSIGNED DEFAULT NULL,
    created_at      TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    KEY idx_audit_actor (actor_user_id),
    KEY idx_audit_target (target_user_id),
    KEY idx_audit_user_legacy (user_id),
    KEY idx_audit_created_at (created_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- One-time codes for the mobile API login flow.
CREATE TABLE mobile_login_otps (
    id          INT UNSIGNED NOT NULL AUTO_INCREMENT,
    user_id     INT UNSIGNED NOT NULL,
    code_hash   CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    expires_at  DATETIME NOT NULL,
    attempts    INT UNSIGNED NOT NULL DEFAULT 0,
    PRIMARY KEY (id),
    KEY idx_otp_user (user_id),
    CONSTRAINT fk_otp_user FOREIGN KEY (user_id)
        REFERENCES users (id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Bearer tokens issued after mobile OTP verification.
CREATE TABLE mobile_api_tokens (
    id          INT UNSIGNED NOT NULL AUTO_INCREMENT,
    user_id     INT UNSIGNED NOT NULL,
    token_hash  CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    expires_at  DATETIME NOT NULL,
    PRIMARY KEY (id),
    UNIQUE KEY uq_api_token_hash (token_hash),
    KEY idx_api_token_user (user_id),
    CONSTRAINT fk_api_token_user FOREIGN KEY (user_id)
        REFERENCES users (id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
