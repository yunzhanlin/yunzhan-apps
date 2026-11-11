FROM debian:bookworm-slim@sha256:734a72b3d6142a71993b4bc580ca01d8ca687f77a2c422d96a961d3376b179bc AS build
RUN apt-get update && apt-get install --no-install-recommends -y \
        autotools-dev build-essential ca-certificates curl libcrypt-dev libmariadb-dev-compat \
        libpcre3-dev libxml2-dev patch pkg-config zlib1g-dev \
    && rm -rf /var/lib/apt/lists/*
ARG PHP_VERSION
ARG PHP_SOURCE_SHA256
COPY build.sh /opt/build-php.sh
COPY php5538-arm64-multiply.patch /opt/php5538-arm64-multiply.patch
COPY php5217-libxml-output.patch /opt/php5217-libxml-output.patch
COPY php5217-mariadb-reconnect.patch /opt/php5217-mariadb-reconnect.patch
COPY php5217-mariadb-local-infile.patch /opt/php5217-mariadb-local-infile.patch
RUN /bin/sh /opt/build-php.sh

FROM debian:bookworm-slim@sha256:734a72b3d6142a71993b4bc580ca01d8ca687f77a2c422d96a961d3376b179bc
RUN apt-get update && apt-get install --no-install-recommends -y \
        ca-certificates libcrypt1 libmariadb3 libpcre3 libxml2 zlib1g \
    && rm -rf /var/lib/apt/lists/*
COPY --from=build /opt/php-root/usr/local/bin/ /usr/local/bin/
COPY --from=build /opt/php-root/usr/local/sbin/ /usr/local/sbin/
COPY --from=build /opt/php-root/usr/local/etc/ /usr/local/etc/
COPY php-fpm.conf /usr/local/etc/php-fpm.conf
COPY start-php-cgi /usr/local/bin/yunzhan-start-php-cgi
RUN chmod 0755 /usr/local/bin/yunzhan-start-php-cgi \
    && mkdir -p /var/www/html \
    && php --version
WORKDIR /var/www/html
