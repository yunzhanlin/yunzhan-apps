FROM php:7.2.34-fpm-buster@sha256:9c84ae47fddb97b94d1d2e289635b7306142a5336bc4ece0a393458c5e0d2cef

RUN set -eux; \
    test "$PHP_VERSION" = 7.2.34; \
    test "$PHP_SHA256" = 409e11bc6a2c18707dfc44bc61c820ddfd81e17481470f3405ee7822d8379903; \
    docker-php-ext-install -j2 bcmath exif mysqli opcache pdo_mysql pcntl sockets; \
    php -r 'foreach (["bcmath", "exif", "mysqli", "Zend OPcache", "pdo_mysql", "pcntl", "sockets"] as $extension) { if (!extension_loaded($extension)) { fwrite(STDERR, "$extension unavailable\n"); exit(1); } }'
