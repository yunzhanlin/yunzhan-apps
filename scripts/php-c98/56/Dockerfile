FROM php:5.6.40-fpm-stretch@sha256:4f070f1b7b93cc5ab364839b79a5b26f38d5f89461f7bc0cd4bab4a3ad7d67d7 AS compile

COPY php-engine-security.patch debian-bullseye-archive.gpg /tmp/
RUN set -eux; \
    test "$PHP_VERSION" = 5.6.40; \
    test "$PHP_SHA256" = 1369a51eee3995d7fbd1c5342e5cc917760e276d561595b6052b21ace2656d1c; \
    printf '%s  /usr/src/php.tar.xz\n' "$PHP_SHA256" | sha256sum --check; \
    printf '%s  /tmp/php-engine-security.patch\n' 54f56f8e90153c436d5872ee18551cd8dd8ec7b25ea0397adae596bd0131fe5e | sha256sum --check; \
    printf '%s  /tmp/debian-bullseye-archive.gpg\n' 9395df01c1c6226584206a77d237c60fdc7039a015ece4e6bd3b1947db6c3b1e | sha256sum --check; \
    printf '%s\n' 'deb [check-valid-until=no signed-by=/tmp/debian-bullseye-archive.gpg] http://archive.debian.org/debian stretch main' > /tmp/php-build.list; \
    apt-get -o Dir::Etc::sourcelist=/tmp/php-build.list -o Dir::Etc::sourceparts=- update; \
    apt-get -o Dir::Etc::sourcelist=/tmp/php-build.list -o Dir::Etc::sourceparts=- \
      install -y --no-install-recommends libcurl4-openssl-dev libsqlite3-dev libssl-dev libxml2-dev zlib1g-dev libedit-dev; \
    mkdir /tmp/php-openssl10; \
    (cd /tmp/php-openssl10; \
      apt-get -o Dir::Etc::sourcelist=/tmp/php-build.list -o Dir::Etc::sourceparts=- download libssl1.0-dev; \
      dpkg-deb -x ./libssl1.0-dev_*.deb .); \
    multiarch="$(dpkg-architecture -qDEB_HOST_MULTIARCH)"; \
    for library in ssl crypto; do \
      lib="/usr/lib/$multiarch/lib$library.so.1.0.2"; \
      test -r "$lib"; \
      ln -s "$lib" "/tmp/php-openssl10/usr/lib/$multiarch/lib$library.so.1.0.2"; \
    done; \
    docker-php-source extract; \
    cd /usr/src/php; \
    patch -p1 --forward --fuzz=0 < /tmp/php-engine-security.patch; \
    export CFLAGS="$PHP_CFLAGS" CPPFLAGS="$PHP_CPPFLAGS" LDFLAGS="$PHP_LDFLAGS"; \
    perl -MText::ParseWords -e 'my $config = `php-config --configure-options`; die "configure flags unavailable" if $?; my $flags = " CFLAGS=$ENV{CFLAGS} LDFLAGS=$ENV{LDFLAGS} CPPFLAGS=$ENV{CPPFLAGS}"; chomp $config; die "unexpected compiler flags" unless $config =~ s/\Q$flags\E\z//; my @options = shellwords($config); die "OpenSSL option unavailable" unless grep { $_ eq "--with-openssl" } @options; @options = map { $_ eq "--with-openssl" ? "--with-openssl=/tmp/php-openssl10/usr" : $_ } @options; $ENV{CPPFLAGS} .= " -I/tmp/php-openssl10/usr/include/$ARGV[0]"; exec "./configure", @options or die $!' "$multiarch"; \
    make -j2; \
    make install; \
    docker-php-ext-configure mysql --with-mysql=mysqlnd; \
    docker-php-ext-install -j2 bcmath exif mysqli opcache pdo_mysql pcntl sockets mysql; \
    php -r 'foreach (["bcmath","exif","mysqli","Zend OPcache","pdo_mysql","pcntl","sockets","mysql"] as $extension) { if (!extension_loaded($extension)) exit(1); }'

FROM php:5.6.40-fpm-stretch@sha256:4f070f1b7b93cc5ab364839b79a5b26f38d5f89461f7bc0cd4bab4a3ad7d67d7
COPY --from=compile /usr/local/ /usr/local/
COPY PHP-LICENSE /usr/local/share/licenses/php/LICENSE
RUN php -r 'if (PHP_VERSION !== "5.6.40" || !extension_loaded("Zend OPcache")) exit(1);' \
    && php-fpm --test
