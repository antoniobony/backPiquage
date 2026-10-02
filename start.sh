#!/bin/bash
sed -i "s/Listen 80/Listen ${PORT:-10000}/" /etc/apache2/ports.conf
sed -i "s/:80>/:${PORT:-10000}>/" /etc/apache2/sites-enabled/000-default.conf
mkdir -p /var/www/html/files /var/www/html/var/cache /var/www/html/var/logs
chown -R www-data:www-data /var/www/html/files /var/www/html/var
exec apache2-foreground
