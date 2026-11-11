FROM php:8.0.30-fpm-bullseye@sha256:b07b8df17506cdb370945d942c5f12356af2d078005ded8b195f7e17129de9d1

RUN set -eux; \
    test "$PHP_VERSION" = 8.0.30; \
    test "$PHP_SHA256" = 216ab305737a5d392107112d618a755dc5df42058226f1670e9db90e77d777d9; \
    docker-php-ext-install -j2 bcmath exif mysqli opcache pdo_mysql pcntl sockets; \
    php -r 'foreach (["bcmath", "exif", "mysqli", "Zend OPcache", "pdo_mysql", "pcntl", "sockets"] as $extension) { if (!extension_loaded($extension)) { fwrite(STDERR, "$extension unavailable\n"); exit(1); } }'
