# SecuredAuth

SecuredAuth is a PHP application using MySQLi and Composer dependencies.

## Deploy to Render

1. Provision an external MySQL-compatible database. Render web services do not
   provide a managed MySQL database. The database must be reachable from the
   Render service, and the application's schema must be imported before use.
   Import the included `schema.sql` before starting the service.
2. In Render, create a Blueprint from this repository and apply `render.yaml`.
   The web service is built from `Dockerfile` and listens on Render's default
   web-service port, `10000`.
3. Set the Blueprint's secret values when prompted:
   - `APP_PEPPER`: a long, unique random secret. Keep it stable; changing it
     invalidates existing password verification.
   - `ADMIN_SETUP_TOKEN`: exactly 32 random characters.
   - `DB_HOST`, `DB_NAME`, `DB_USERNAME`, and `DB_PASSWORD`: credentials for
     the external MySQL database. Set `DB_PORT` too if it is not `3306`.
   - Mail delivery: set `MAIL_PROVIDER=api` on Render free services, because
     outbound SMTP ports `25`, `465`, and `587` are blocked there. Use
     `MAIL_API_PROVIDER` (`brevo` by default, or `resend`), `MAIL_API_KEY`, and
     `MAIL_FROM_ADDRESS` with an address verified by that provider. For local
     development or hosts that allow SMTP, leave `MAIL_PROVIDER=smtp` and set
     `MAIL_USERNAME`, `MAIL_PASSWORD`, `MAIL_FROM_ADDRESS`, plus `MAIL_HOST`,
     `MAIL_PORT`, and `MAIL_ENCRYPTION` if your provider uses different values.
4. After the database schema is loaded and the service is live, visit
   `/setup_admin.php` to promote an existing active account. The setup page
   disables itself after an administrator exists.

Do not commit `.env` or use real credentials in `.env.example`. For local
development, copy `.env.example` to `.env` and fill in local values.

The application stores PHP sessions on the web container, so run one web
instance unless session storage is moved to a shared service.
