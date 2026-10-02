FROM mariadb:10.11

CMD ["mariadbd", \
     "--datadir=/var/lib/mysql/data", \
     "--character-set-server=utf8mb4", \
     "--collation-server=utf8mb4_unicode_ci", \
     "--max_allowed_packet=256M"]
