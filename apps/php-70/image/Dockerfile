FROM php:7.0.33-fpm-stretch@sha256:8e8644c0fd61424939fff072ca617469550bbb659158301a2dcadf334746a1c2

RUN set -eux; \
    test "$PHP_VERSION" = 7.0.33; \
    test "$PHP_SHA256" = ab8c5be6e32b1f8d032909dedaaaa4bbb1a209e519abb01a52ce3914f9a13d96; \
    docker-php-ext-install -j2 bcmath exif mysqli opcache pdo_mysql pcntl sockets; \
    php -r 'foreach (["bcmath", "exif", "mysqli", "Zend OPcache", "pdo_mysql", "pcntl", "sockets"] as $extension) { if (!extension_loaded($extension)) { fwrite(STDERR, "$extension unavailable\n"); exit(1); } }'
