FROM php:7.3.33-fpm-buster@sha256:bb3522a0ebacafdb712297d0cc068cfba044044e7e0211546f65803b5afe116f AS compile

COPY php-engine-security.patch debian-bullseye-archive.gpg /tmp/
RUN set -eux; \
    test "$PHP_VERSION" = 7.3.33; \
    test "$PHP_SHA256" = 166eaccde933381da9516a2b70ad0f447d7cec4b603d07b9a916032b215b90cc; \
    printf '%s  /usr/src/php.tar.xz\n' "$PHP_SHA256" | sha256sum --check; \
    printf '%s  /tmp/php-engine-security.patch\n' 26ee7389db01726609e620e91309fcd49389776ea61a11c0d48c34a5c68c8dcc | sha256sum --check; \
    printf '%s  /tmp/debian-bullseye-archive.gpg\n' 9395df01c1c6226584206a77d237c60fdc7039a015ece4e6bd3b1947db6c3b1e | sha256sum --check; \
    printf '%s\n' 'deb [check-valid-until=no signed-by=/tmp/debian-bullseye-archive.gpg] http://archive.debian.org/debian buster main' > /tmp/php-build.list; \
    apt-get -o Dir::Etc::sourcelist=/tmp/php-build.list -o Dir::Etc::sourceparts=- update; \
    apt-get -o Dir::Etc::sourcelist=/tmp/php-build.list -o Dir::Etc::sourceparts=- \
      install -y --no-install-recommends libcurl4-openssl-dev libsqlite3-dev libssl-dev libxml2-dev zlib1g-dev libreadline-dev libargon2-dev libsodium-dev; \
    docker-php-source extract; \
    cd /usr/src/php; \
    patch -p1 --forward --fuzz=0 < /tmp/php-engine-security.patch; \
    export CFLAGS="$PHP_CFLAGS" CPPFLAGS="$PHP_CPPFLAGS" LDFLAGS="$PHP_LDFLAGS"; \
    perl -MText::ParseWords -e 'my @options = shellwords(`php-config --configure-options`); die "configure flags unavailable" unless $? == 0 && @options; exec "./configure", @options or die $!'; \
    make -j2; \
    make install; \
    docker-php-ext-install -j2 bcmath exif mysqli opcache pdo_mysql pcntl sockets; \
    php -r 'foreach (["bcmath","exif","mysqli","Zend OPcache","pdo_mysql","pcntl","sockets"] as $extension) { if (!extension_loaded($extension)) exit(1); }'

FROM php:7.3.33-fpm-buster@sha256:bb3522a0ebacafdb712297d0cc068cfba044044e7e0211546f65803b5afe116f
COPY --from=compile /usr/local/ /usr/local/
COPY PHP-LICENSE /usr/local/share/licenses/php/LICENSE
RUN php -r 'if (PHP_VERSION !== "7.3.33" || !extension_loaded("Zend OPcache")) exit(1);' \
    && php-fpm --test
