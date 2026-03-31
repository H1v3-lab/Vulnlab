FROM php:8.1-apache
RUN echo "FLAG{lf1_p4th_tr4v3rs4l_r34d}" > /flag.txt && chmod 644 /flag.txt
COPY src/ /var/www/html/
RUN chown -R www-data:www-data /var/www/html
EXPOSE 80
