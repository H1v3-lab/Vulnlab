FROM php:8.1-apache
# Copier les sources en premier
COPY src/ /var/www/html/
# Créer le dossier uploads avec les bonnes permissions
RUN mkdir -p /var/www/html/uploads \
    && chown -R www-data:www-data /var/www/html \
    && chmod -R 755 /var/www/html \
    && chmod 777 /var/www/html/uploads
EXPOSE 80
