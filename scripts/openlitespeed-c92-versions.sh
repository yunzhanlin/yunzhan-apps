#!/bin/bash
set -euo pipefail
test "$GITHUB_ACTIONS" = true
test "$GITHUB_REPOSITORY" = yunzhanlin/yunzhan-apps
case "$(uname -m)" in
    x86_64) arch=amd64 ;;
    aarch64) arch=arm64 ;;
    *) exit 1 ;;
esac
out="$RUNNER_TEMP/c92-ols-php-version"
mkdir -m 0700 "$out"
original=litespeedtech/openlitespeed:1.8.4-lsphp83@sha256:6f50ba204e66f1c746dd183f3022340ca912124c414669755db7f4701167f268
candidate=litespeedtech/openlitespeed:1.9.4-lsphp83@sha256:e240c9af427fe36e373382384a8eaabd7224412fbb3257a4288525adbd67d19c
for name in original candidate; do
    image="${!name}"
    docker pull --platform "linux/$arch" "$image"
    test "$(docker image inspect --format '{{.Os}}/{{.Architecture}}' "$image")" = "linux/$arch"
    docker run --rm --network none --entrypoint /bin/sh "$image" -c '
        set -eu
        printf "site_path=%s\n" "$(readlink -f /usr/local/lsws/fcgi-bin/lsphp)"
        printf "admin_path=%s\n" "$(readlink -f /usr/local/lsws/admin/fcgi-bin/admin_php)"
        printf "site="
        /usr/local/lsws/fcgi-bin/lsphp -v
        printf "admin="
        /usr/local/lsws/admin/fcgi-bin/admin_php -v
    ' > "$out/$name.txt"
    test "$(wc -c < "$out/$name.txt")" -lt 32768
    cat "$out/$name.txt"
done
grep -q '^site=PHP 8\.3\.36 ' "$out/candidate.txt"
printf '%s\n' "$arch" > "$out/architecture.txt"
