FROM php:8.1-apache
COPY src/ /var/www/html/
RUN mkdir -p /var/www/html/uploads \
    && chown -R www-data:www-data /var/www/html \
    && chmod -R 755 /var/www/html \
    && chmod 777 /var/www/html/uploads
CMD ["sh", "-c", "mkdir -p /var/www/html/uploads && chown -R www-data:www-data /var/www/html/uploads && chmod 777 /var/www/html/uploads && exec apache2-foreground"]
EXPOSE 80
