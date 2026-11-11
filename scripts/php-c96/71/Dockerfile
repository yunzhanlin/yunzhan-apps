FROM php:7.1.33-fpm-stretch@sha256:aa24ec376855697d8b84960f4e0e616faae4afdf7ee43c957dc35e5992244d51 AS compile

COPY php-engine-security.patch debian-bullseye-archive.gpg /tmp/
RUN set -eux; \
    test "$PHP_VERSION" = 7.1.33; \
    test "$PHP_SHA256" = bd7c0a9bd5433289ee01fd440af3715309faf583f75832b64fe169c100d52968; \
    printf '%s  /usr/src/php.tar.xz\n' "$PHP_SHA256" | sha256sum --check; \
    printf '%s  /tmp/php-engine-security.patch\n' fa0184d2c8d99179372c6b1c7c19ee4aa096aae46547e048b2ed5729729c38fc | sha256sum --check; \
    printf '%s  /tmp/debian-bullseye-archive.gpg\n' 9395df01c1c6226584206a77d237c60fdc7039a015ece4e6bd3b1947db6c3b1e | sha256sum --check; \
    printf '%s\n' 'deb [check-valid-until=no signed-by=/tmp/debian-bullseye-archive.gpg] http://archive.debian.org/debian stretch main' > /tmp/php-build.list; \
    apt-get -o Dir::Etc::sourcelist=/tmp/php-build.list -o Dir::Etc::sourceparts=- update; \
    apt-get -o Dir::Etc::sourcelist=/tmp/php-build.list -o Dir::Etc::sourceparts=- \
      install -y --no-install-recommends libcurl4-openssl-dev libsqlite3-dev libssl-dev libxml2-dev zlib1g-dev libedit-dev; \
    docker-php-source extract; \
    cd /usr/src/php; \
    patch -p1 --forward --fuzz=0 < /tmp/php-engine-security.patch; \
    export CFLAGS="$PHP_CFLAGS" CPPFLAGS="$PHP_CPPFLAGS" LDFLAGS="$PHP_LDFLAGS"; \
    perl -MText::ParseWords -e 'my @options = shellwords(`php-config --configure-options`); die "configure flags unavailable" unless $? == 0 && @options; exec "./configure", @options or die $!'; \
    make -j2; \
    make install; \
    docker-php-ext-install -j2 bcmath exif mysqli opcache pdo_mysql pcntl sockets; \
    php -r 'foreach (["bcmath","exif","mysqli","Zend OPcache","pdo_mysql","pcntl","sockets"] as $extension) { if (!extension_loaded($extension)) exit(1); }'

FROM php:7.1.33-fpm-stretch@sha256:aa24ec376855697d8b84960f4e0e616faae4afdf7ee43c957dc35e5992244d51
COPY --from=compile /usr/local/ /usr/local/
COPY PHP-LICENSE /usr/local/share/licenses/php/LICENSE
RUN php -r 'if (PHP_VERSION !== "7.1.33" || !extension_loaded("Zend OPcache")) exit(1);' \
    && php-fpm --test
