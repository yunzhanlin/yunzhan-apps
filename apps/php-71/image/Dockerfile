FROM php:7.1.33-fpm-stretch@sha256:aa24ec376855697d8b84960f4e0e616faae4afdf7ee43c957dc35e5992244d51

RUN set -eux; \
    test "$PHP_VERSION" = 7.1.33; \
    test "$PHP_SHA256" = bd7c0a9bd5433289ee01fd440af3715309faf583f75832b64fe169c100d52968; \
    docker-php-ext-install -j2 bcmath exif mysqli opcache pdo_mysql pcntl sockets; \
    php -r 'foreach (["bcmath", "exif", "mysqli", "Zend OPcache", "pdo_mysql", "pcntl", "sockets"] as $extension) { if (!extension_loaded($extension)) { fwrite(STDERR, "$extension unavailable\n"); exit(1); } }'
