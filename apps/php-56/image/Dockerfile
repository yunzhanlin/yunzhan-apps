FROM php:5.6.40-fpm-stretch@sha256:4f070f1b7b93cc5ab364839b79a5b26f38d5f89461f7bc0cd4bab4a3ad7d67d7

RUN set -eux; \
    test "$PHP_VERSION" = 5.6.40; \
    test "$PHP_SHA256" = 1369a51eee3995d7fbd1c5342e5cc917760e276d561595b6052b21ace2656d1c; \
    docker-php-ext-configure mysql --with-mysql=mysqlnd; \
    docker-php-ext-install -j2 bcmath exif mysqli opcache pdo_mysql pcntl sockets mysql; \
    php -r 'foreach (["bcmath", "exif", "mysqli", "Zend OPcache", "pdo_mysql", "pcntl", "sockets", "mysql"] as $extension) { if (!extension_loaded($extension)) { fwrite(STDERR, "$extension unavailable\n"); exit(1); } }'
