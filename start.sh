#!/bin/bash
sed -i "s/Listen 80/Listen ${PORT:-10000}/" /etc/apache2/ports.conf
sed -i "s/:80>/:${PORT:-10000}>/" /etc/apache2/sites-enabled/000-default.conf
mkdir -p /var/data/files /var/data/files_csweb /var/www/html/var/cache /var/www/html/var/logs
chown -R www-data:www-data /var/data /var/www/html/var
exec apache2-foreground
