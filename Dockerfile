FROM php:8.1-apache

RUN apt-get update && apt-get install -y libzip-dev libicu-dev unzip \
    && docker-php-ext-install pdo pdo_mysql mysqli zip intl \
    && a2enmod rewrite headers \
    && rm -rf /var/lib/apt/lists/*

RUN sed -i 's/AllowOverride None/AllowOverride All/g' /etc/apache2/apache2.conf

RUN { echo "upload_max_filesize=256M"; echo "post_max_size=256M"; \
      echo "memory_limit=512M"; echo "max_execution_time=300"; \
      echo "date.timezone=Indian/Antananarivo"; } > /usr/local/etc/php/conf.d/csweb.ini

COPY . /var/www/html/
COPY start.sh /start.sh

# Corrige les fins de ligne Windows (CRLF) et crée les dossiers ignorés par Git
RUN sed -i 's/\r$//' /start.sh && chmod +x /start.sh \
    && mkdir -p /var/www/html/files /var/www/html/var/cache /var/www/html/var/logs \
    && chown -R www-data:www-data /var/www/html

CMD ["/start.sh"]