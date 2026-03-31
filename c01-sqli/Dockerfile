FROM php:8.1-apache

# Extension MySQLi
RUN docker-php-ext-install mysqli && docker-php-ext-enable mysqli

# Copier les sources
COPY src/ /var/www/html/

# Permissions
RUN chown -R www-data:www-data /var/www/html

EXPOSE 80
