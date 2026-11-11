FROM php:7.4.33-fpm-bullseye@sha256:3ac7c8c74b2b047c7cb273469d74fc0d59b857aa44043e6ea6a0084372811d5b AS compile

COPY php-7.4.33-reviewed-security.patch /tmp/php-engine-security.patch
RUN set -eux; \
    test "$PHP_VERSION" = 7.4.33; \
    test "$PHP_SHA256" = 924846abf93bc613815c55dd3f5809377813ac62a9ec4eb3778675b82a27b927; \
    printf '%s  /usr/src/php.tar.xz\n' "$PHP_SHA256" | sha256sum --check; \
    printf '%s  %s\n' \
      fb49a1dcfe047dfa24325fc0b822a3f2bc1a95a4e6197f9eda55a832ff8cdfc3 /tmp/php-engine-security.patch \
      | sha256sum --check; \
    apt-get update; \
    apt-get install -y --no-install-recommends $PHPIZE_DEPS patch python3 \
      libargon2-dev libcurl4-openssl-dev libonig-dev libreadline-dev libsodium-dev \
      libsqlite3-dev libssl-dev libxml2-dev zlib1g-dev; \
    docker-php-source extract; \
    cd /usr/src/php; \
    patch -p1 --forward --fuzz=0 < /tmp/php-engine-security.patch; \
    export CFLAGS="$PHP_CFLAGS" CPPFLAGS="$PHP_CPPFLAGS" LDFLAGS="$PHP_LDFLAGS"; \
    python3 -c 'import os, shlex, subprocess; opts = shlex.split(subprocess.check_output(["php-config", "--configure-options"], text=True)); os.execv("./configure", ["./configure", *opts])'; \
    make -j2; \
    make install; \
    docker-php-ext-install -j2 bcmath exif mysqli opcache pdo_mysql pcntl sockets; \
    php -r 'foreach (["bcmath", "exif", "mysqli", "Zend OPcache", "pdo_mysql", "pcntl", "sockets"] as $extension) { if (!extension_loaded($extension)) { fwrite(STDERR, "$extension unavailable\n"); exit(1); } }'

FROM php:7.4.33-fpm-bullseye@sha256:3ac7c8c74b2b047c7cb273469d74fc0d59b857aa44043e6ea6a0084372811d5b
COPY --from=compile /usr/local/ /usr/local/
RUN php -r 'if (PHP_VERSION !== "7.4.33" || !extension_loaded("Zend OPcache")) exit(1);' \
    && php-fpm --test
