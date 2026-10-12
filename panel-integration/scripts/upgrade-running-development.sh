#!/usr/bin/env bash
# Use a verified normal release, never source metadata or provision host state.
set -euo pipefail
RELEASE_PATH="${1:?usage: upgrade-running-development.sh VERIFIED_RELEASE_DIRECTORY}"
[[ $(id -u) == 0 ]] || { echo 'run this migration as root' >&2; exit 1; }
"$RELEASE_PATH/verify-release.sh" "$RELEASE_PATH" >/dev/null
exec /usr/bin/python3 "$RELEASE_PATH/development-upgrade.py" run "$RELEASE_PATH"
