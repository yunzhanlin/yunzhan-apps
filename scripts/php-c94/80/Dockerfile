FROM php:8.0.30-fpm-bullseye@sha256:b07b8df17506cdb370945d942c5f12356af2d078005ded8b195f7e17129de9d1 AS compile

COPY php-8.0.30-reviewed-security.patch /tmp/php-engine-security.patch
RUN set -eux; \
    test "$PHP_VERSION" = 8.0.30; \
    test "$PHP_SHA256" = 216ab305737a5d392107112d618a755dc5df42058226f1670e9db90e77d777d9; \
    printf '%s  /usr/src/php.tar.xz\n' "$PHP_SHA256" | sha256sum --check; \
    printf '%s  %s\n' \
      8274d747533a62a27faa6be4d29f6e9a0a89ac56cebe008a8a547ea02094e6d8 /tmp/php-engine-security.patch \
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

FROM php:8.0.30-fpm-bullseye@sha256:b07b8df17506cdb370945d942c5f12356af2d078005ded8b195f7e17129de9d1
COPY --from=compile /usr/local/ /usr/local/
RUN php -r 'if (PHP_VERSION !== "8.0.30" || !extension_loaded("Zend OPcache")) exit(1);' \
    && php-fpm --test
