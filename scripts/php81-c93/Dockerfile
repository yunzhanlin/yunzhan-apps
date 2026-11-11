FROM php:8.1.34-fpm-bookworm@sha256:e3893eeb8f6fb719b6efa7e011e76a65cb1322054226250cedac1138b406aba4 AS compile

COPY php-8.1.34-reviewed-security.patch /tmp/php-engine-security.patch
RUN set -eux; \
    test "$PHP_VERSION" = 8.1.34; \
    test "$PHP_SHA256" = ffa9e0982e82eeaea848f57687b425ed173aa278fe563001310ae2638db5c251; \
    printf '%s  /usr/src/php.tar.xz\n' "$PHP_SHA256" | sha256sum --check; \
    printf '%s  %s\n' \
      4c13a0ee8af562e3e78eb06e30f7b6bc824d6eca70be9670c0c55f17c0d492ba /tmp/php-engine-security.patch \
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

FROM php:8.1.34-fpm-bookworm@sha256:e3893eeb8f6fb719b6efa7e011e76a65cb1322054226250cedac1138b406aba4
COPY --from=compile /usr/local/ /usr/local/
RUN php -r 'if (PHP_VERSION !== "8.1.34" || !extension_loaded("Zend OPcache")) exit(1);' \
    && php-fpm --test
