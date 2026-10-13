#!/usr/bin/env bash
set -euo pipefail
[[ $(id -u) == 0 && -f /etc/panel-development-vm ]] || { echo 'Dedicated development VM only' >&2; exit 1; }
export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get install -y --no-install-recommends build-essential autoconf pkg-config libxml2-dev libsqlite3-dev libssl-dev libcurl4-openssl-dev libonig-dev libzip-dev zlib1g-dev libpng-dev libjpeg62-turbo-dev libfreetype6-dev libicu-dev libpcre2-dev ca-certificates bison re2c gpg gpg-agent libaio1t64 libnuma1 libncurses6 libtinfo6 xz-utils
install -d -m 0755 /var/lib/panel-build-deps
dpkg-query -W -f='${binary:Package}\t${Version}\n' > /var/lib/panel-build-deps/debian-packages.tsv
