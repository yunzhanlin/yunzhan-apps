#!/bin/sh
set -eu

case "$PHP_VERSION" in
    5.2.17|5.3.29|5.4.45|5.5.38) ;;
    *) exit 1 ;;
esac

mkdir /tmp/legacy-php-source
cd /tmp/legacy-php-source
curl --fail --show-error --silent --proto '=https' --tlsv1.2 --retry 3 \
    "https://museum.php.net/php5/php-$PHP_VERSION.tar.gz" -o php.tar.gz
printf '%s  php.tar.gz\n' "$PHP_SOURCE_SHA256" | sha256sum --check -
tar -xzf php.tar.gz --strip-components=1
cp /usr/share/misc/config.guess /usr/share/misc/config.sub .

# Port PHP's later AArch64 register constraints to the final PHP 5.5 release.
if [ "$PHP_VERSION" = 5.5.38 ] && [ "$(uname -m)" = aarch64 ]; then
    patch --batch --fuzz=0 -p1 < /opt/php5538-arm64-multiply.patch
fi

set -- --prefix=/usr/local --with-config-file-path=/usr/local/etc/php \
    --with-config-file-scan-dir=/usr/local/etc/php/conf.d \
    --with-libdir="lib/$(gcc -dumpmachine)" --disable-all --enable-cli \
    --enable-bcmath --enable-ctype --enable-filter --enable-json --enable-session \
    --enable-tokenizer --enable-pdo --enable-libxml --enable-dom --enable-simplexml \
    --enable-xml --with-zlib

if [ "$PHP_VERSION" = 5.2.17 ]; then
    set -- "$@" --enable-cgi --enable-fastcgi --with-pcre-regex=/usr --with-mysql=/usr \
        --with-mysqli=/usr/bin/mysql_config --with-pdo-mysql=/usr
else
    set -- "$@" --disable-cgi --enable-fpm --with-fpm-user=www-data --with-fpm-group=www-data \
        --with-mysql=mysqlnd --with-mysqli=mysqlnd --with-pdo-mysql=mysqlnd
fi

CFLAGS='-O2 -fcommon -std=gnu89' ./configure "$@"
make -j2
make install INSTALL_ROOT=/opt/php-root
prefix=/opt/php-root/usr/local
mkdir -p "$prefix/etc/php/conf.d"
printf '%s\n' 'cgi.fix_pathinfo=0' > "$prefix/etc/php/conf.d/20-fastcgi.ini"
"$prefix/bin/php" -r 'if (PHP_VERSION !== $argv[1] || !extension_loaded("mysql") || !extension_loaded("mysqli") || !extension_loaded("pdo_mysql") || !extension_loaded("json")) exit(1);' "$PHP_VERSION"
if [ "$PHP_VERSION" = 5.2.17 ]; then
    "$prefix/bin/php-cgi" -v
else
    "$prefix/sbin/php-fpm" -v
fi
