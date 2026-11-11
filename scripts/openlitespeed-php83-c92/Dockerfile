FROM litespeedtech/openlitespeed:1.9.4-lsphp83@sha256:e240c9af427fe36e373382384a8eaabd7224412fbb3257a4288525adbd67d19c

ARG TARGETARCH

# The registry's WebAdmin binary differs from the security-release asset.
# Retain the site's packaged PHP and install only the release's verified WebAdmin binary.
RUN set -eu; \
    case "$TARGETARCH" in \
      amd64) machine=x86_64; file=admin_php5; archive_sha=feab597ea0f5824d8873b1aa0f85bb0728c968e87d1e5b2eda3ea41321b0ad79; binary_sha=e9716e3c929865087009bea3c922768ed9be0034eef71cc0e0925779bfb66c60 ;; \
      arm64) machine=aarch64; file=admin_php; archive_sha=9481f1e48d11777917a394205055f840fa97e1fa6fc8f47ace39e0b5bc95b4bc; binary_sha=b6b0c67bada79e6c38e1c7d5e91977283595d6c2e1ab7b6482bb793c9d4303c6 ;; \
      *) exit 1 ;; \
    esac; \
    work="$(mktemp -d)"; \
    trap 'rm -rf "$work"' EXIT; \
    curl --fail --silent --show-error --location --proto '=https' --max-time 240 \
      "https://github.com/litespeedtech/openlitespeed/releases/download/v1.9.4/openlitespeed-1.9.4-${machine}-linux.tgz" \
      --output "$work/official.tgz"; \
    printf '%s  %s\n' "$archive_sha" "$work/official.tgz" | sha256sum --check; \
    tar -xzOf "$work/official.tgz" "openlitespeed/admin/fcgi-bin/$file" > "$work/admin_php"; \
    printf '%s  %s\n' "$binary_sha" "$work/admin_php" | sha256sum --check; \
    install -m 0755 "$work/admin_php" /usr/local/lsws/admin/fcgi-bin/admin_php
