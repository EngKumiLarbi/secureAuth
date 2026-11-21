FROM php:8.3-apache

RUN apt-get update \
    && apt-get install -y --no-install-recommends unzip \
    && rm -rf /var/lib/apt/lists/* \
    && docker-php-ext-install mysqli \
    && sed -i 's/Listen 80/Listen 10000/' /etc/apache2/ports.conf \
    && sed -i 's/<VirtualHost \*:80>/<VirtualHost *:10000>/' /etc/apache2/sites-available/000-default.conf \
    && sed -i '/<Directory \/var\/www\/>/,/<\/Directory>/ s/AllowOverride None/AllowOverride All/' /etc/apache2/apache2.conf \
    && echo 'ServerName localhost' >> /etc/apache2/apache2.conf \
    && printf '\n# Pass Render-injected environment variables through to PHP\nPassEnv APP_ENV APP_DEBUG APP_PEPPER ADMIN_SETUP_TOKEN\nPassEnv DB_HOST DB_PORT DB_NAME DB_USERNAME DB_PASSWORD DB_SSL DB_SSL_CA\nPassEnv MAIL_HOST MAIL_PORT MAIL_ENCRYPTION MAIL_USERNAME MAIL_PASSWORD MAIL_FROM_ADDRESS MAIL_FROM_NAME\nPassEnv MAIL_PROVIDER MAIL_API_PROVIDER MAIL_API_KEY\n' >> /etc/apache2/sites-available/000-default.conf

COPY --from=composer:2 /usr/bin/composer /usr/bin/composer

WORKDIR /var/www/html

COPY composer.json composer.lock ./
RUN composer install --no-dev --no-interaction --no-progress --prefer-dist --optimize-autoloader

COPY . .

EXPOSE 10000

CMD ["apache2-foreground"]
