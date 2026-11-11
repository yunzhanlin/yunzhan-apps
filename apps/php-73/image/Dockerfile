FROM php:7.3.33-fpm-buster@sha256:bb3522a0ebacafdb712297d0cc068cfba044044e7e0211546f65803b5afe116f

RUN set -eux; \
    test "$PHP_VERSION" = 7.3.33; \
    test "$PHP_SHA256" = 166eaccde933381da9516a2b70ad0f447d7cec4b603d07b9a916032b215b90cc; \
    docker-php-ext-install -j2 bcmath exif mysqli opcache pdo_mysql pcntl sockets; \
    php -r 'foreach (["bcmath", "exif", "mysqli", "Zend OPcache", "pdo_mysql", "pcntl", "sockets"] as $extension) { if (!extension_loaded($extension)) { fwrite(STDERR, "$extension unavailable\n"); exit(1); } }'
