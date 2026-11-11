FROM php:7.0.33-fpm-stretch@sha256:8e8644c0fd61424939fff072ca617469550bbb659158301a2dcadf334746a1c2 AS compile

COPY php-engine-security.patch debian-bullseye-archive.gpg /tmp/
RUN set -eux; \
    test "$PHP_VERSION" = 7.0.33; \
    test "$PHP_SHA256" = ab8c5be6e32b1f8d032909dedaaaa4bbb1a209e519abb01a52ce3914f9a13d96; \
    printf '%s  /usr/src/php.tar.xz\n' "$PHP_SHA256" | sha256sum --check; \
    printf '%s  /tmp/php-engine-security.patch\n' 6ffa676548a1b1ff8f36bb70c2b2e6ed82e5ab7ccd0142248ef27c7eb418d485 | sha256sum --check; \
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

FROM php:7.0.33-fpm-stretch@sha256:8e8644c0fd61424939fff072ca617469550bbb659158301a2dcadf334746a1c2
COPY --from=compile /usr/local/ /usr/local/
COPY PHP-LICENSE /usr/local/share/licenses/php/LICENSE
RUN php -r 'if (PHP_VERSION !== "7.0.33" || !extension_loaded("Zend OPcache")) exit(1);' \
    && php-fpm --test
