#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
VERSION="${1:-}"
ARCH="${2:-}"
if [[ ! "$VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+([.-][a-z0-9]+)*$ ]]; then echo 'usage: build-release.sh VERSION amd64|arm64' >&2; exit 2; fi
if [[ "$ARCH" != amd64 && "$ARCH" != arm64 ]]; then echo 'architecture must be amd64 or arm64' >&2; exit 2; fi
source "$ROOT/scripts/env.sh"
OUT="$ROOT/.local/releases"
NAME="panel-${VERSION}-linux-${ARCH}"
mkdir -p "$OUT"
for suffix in '' .sha256 .manifest .sig; do
  [[ ! -e "$OUT/$NAME.tar.gz$suffix" ]] || { echo 'release already exists; choose a new version' >&2; exit 1; }
done
[[ ! -e "$OUT/$NAME.executor-tests" && ! -e "$OUT/$NAME.executor-tests.sha256" ]] || { echo 'release test artifact already exists; choose a new version' >&2; exit 1; }
LOCK="$OUT/.build-$NAME.lock"
mkdir "$LOCK" 2>/dev/null || { echo 'this release is already building; do not replace its stage' >&2; exit 1; }
STAGE=''
cleanup() {
  local result=$?
  # Finder may create .DS_Store while the private snapshot is being removed.
  # Retry only our own stage; never mask a compile/check failure with cleanup.
  if [[ -n "$STAGE" ]]; then
    python3 - "$STAGE" <<'PY_CLEANUP'
import pathlib, shutil, sys, time
stage = pathlib.Path(sys.argv[1])
for attempt in range(3):
    try:
        shutil.rmtree(stage)
        break
    except FileNotFoundError:
        break
    except OSError:
        if attempt == 2:
            print(f"warning: private build stage retained for cleanup: {stage}", file=sys.stderr)
        else:
            time.sleep(0.1)
PY_CLEANUP
  fi
  rmdir "$LOCK" 2>/dev/null || true
  return "$result"
}
trap cleanup EXIT
STAGE="$(mktemp -d "$OUT/.stage-$NAME.XXXXXX")"
BUILD_ROOT="$STAGE/.source"
python3 "$ROOT/packaging/freeze-source.py" "$ROOT" "$BUILD_ROOT"
mkdir -p "$STAGE/$NAME/bin" "$STAGE/$NAME/web" "$STAGE/$NAME/systemd" "$STAGE/$NAME/config"
(cd "$BUILD_ROOT" && go version && /opt/homebrew/bin/node --version && go test ./... && go vet ./...) 2>&1 | tee "$STAGE/$NAME/BUILD_CHECKS.txt"
(cd "$BUILD_ROOT" && python3 -m unittest discover -s packaging -p 'test_*.py' -v) 2>&1 | tee -a "$STAGE/$NAME/BUILD_CHECKS.txt"
(cd "$BUILD_ROOT" && /opt/homebrew/bin/node scripts/test-software-routing.mjs) 2>&1 | tee -a "$STAGE/$NAME/BUILD_CHECKS.txt"
(cd "$BUILD_ROOT" && /opt/homebrew/bin/node scripts/test-store-search.mjs) 2>&1 | tee -a "$STAGE/$NAME/BUILD_CHECKS.txt"
(cd "$BUILD_ROOT" && /opt/homebrew/bin/node scripts/test-analytics-tracker.mjs) 2>&1 | tee -a "$STAGE/$NAME/BUILD_CHECKS.txt"
(cd "$BUILD_ROOT" && /opt/homebrew/bin/node --test scripts/test-analytics-latency.mjs) 2>&1 | tee -a "$STAGE/$NAME/BUILD_CHECKS.txt"
(cd "$BUILD_ROOT" && /opt/homebrew/bin/node --test scripts/test-panel-health-context.mjs) 2>&1 | tee -a "$STAGE/$NAME/BUILD_CHECKS.txt"
(cd "$BUILD_ROOT" && /opt/homebrew/bin/node scripts/test-analytics-html-filter.mjs) 2>&1 | tee -a "$STAGE/$NAME/BUILD_CHECKS.txt"
(cd "$BUILD_ROOT" && /opt/homebrew/bin/node --test scripts/test-analytics-html-state.mjs) 2>&1 | tee -a "$STAGE/$NAME/BUILD_CHECKS.txt"
(cd "$BUILD_ROOT" && /opt/homebrew/bin/node scripts/test-menu-permissions.mjs) 2>&1 | tee -a "$STAGE/$NAME/BUILD_CHECKS.txt"
(cd "$BUILD_ROOT" && /opt/homebrew/bin/node --test scripts/test-network-ids-operations.mjs) 2>&1 | tee -a "$STAGE/$NAME/BUILD_CHECKS.txt"
(cd "$BUILD_ROOT" && /opt/homebrew/bin/node --test scripts/test-registry-request-identity.mjs) 2>&1 | tee -a "$STAGE/$NAME/BUILD_CHECKS.txt"
(cd "$BUILD_ROOT" && /opt/homebrew/bin/node --test scripts/test-registry-freshness.mjs) 2>&1 | tee -a "$STAGE/$NAME/BUILD_CHECKS.txt"
(cd "$BUILD_ROOT" && /opt/homebrew/bin/node --test scripts/test-remote-sync.mjs) 2>&1 | tee -a "$STAGE/$NAME/BUILD_CHECKS.txt"
(cd "$BUILD_ROOT" && /opt/homebrew/bin/node --test scripts/test-remote-sync-plans.mjs) 2>&1 | tee -a "$STAGE/$NAME/BUILD_CHECKS.txt"
(cd "$BUILD_ROOT" && /opt/homebrew/bin/node --test scripts/test-remote-sync-backups.mjs) 2>&1 | tee -a "$STAGE/$NAME/BUILD_CHECKS.txt"
(cd "$BUILD_ROOT" && /opt/homebrew/bin/node --test scripts/test-remote-backup-archive.mjs) 2>&1 | tee -a "$STAGE/$NAME/BUILD_CHECKS.txt"
(cd "$BUILD_ROOT" && /opt/homebrew/bin/node --test scripts/test-waf-rotation-refresh.mjs) 2>&1 | tee -a "$STAGE/$NAME/BUILD_CHECKS.txt"
(cd "$BUILD_ROOT" && /opt/homebrew/bin/node --test scripts/test-waf-body-inventory.mjs) 2>&1 | tee -a "$STAGE/$NAME/BUILD_CHECKS.txt"
(cd "$BUILD_ROOT" && /opt/homebrew/bin/node --test scripts/test-load-balance-routing.mjs) 2>&1 | tee -a "$STAGE/$NAME/BUILD_CHECKS.txt"
(cd "$BUILD_ROOT" && /opt/homebrew/bin/node --test scripts/test-load-balance-transactions.mjs) 2>&1 | tee -a "$STAGE/$NAME/BUILD_CHECKS.txt"
(cd "$BUILD_ROOT" && /opt/homebrew/bin/node --test scripts/test-load-balance-report-export.mjs) 2>&1 | tee -a "$STAGE/$NAME/BUILD_CHECKS.txt"
(cd "$BUILD_ROOT" && /opt/homebrew/bin/node --test scripts/test-apache-waf-transactions.mjs) 2>&1 | tee -a "$STAGE/$NAME/BUILD_CHECKS.txt"
(cd "$BUILD_ROOT" && /opt/homebrew/bin/node --test scripts/test-deferred-workspace.mjs) 2>&1 | tee -a "$STAGE/$NAME/BUILD_CHECKS.txt"
(cd "$BUILD_ROOT" && /opt/homebrew/bin/node --test scripts/test-web-entry-budget.mjs) 2>&1 | tee -a "$STAGE/$NAME/BUILD_CHECKS.txt"
(cd "$BUILD_ROOT" && CGO_ENABLED=0 GOOS=linux GOARCH="$ARCH" go test -c -ldflags="-s -w" -o "$STAGE/executor-tests" ./internal/executor)
printf 'Linux executor tests compiled from frozen inputs; execute separately on the target OS.\n' >> "$STAGE/$NAME/BUILD_CHECKS.txt"
(cd "$BUILD_ROOT/web" && VITE_PANEL_VERSION="$VERSION" /opt/homebrew/bin/npm run build >/dev/null)
(cd "$BUILD_ROOT" && /opt/homebrew/bin/node scripts/web-entry-budget.mjs "$BUILD_ROOT/web/dist") 2>&1 | tee -a "$STAGE/$NAME/BUILD_CHECKS.txt"
(cd "$BUILD_ROOT" && CGO_ENABLED=0 GOOS=linux GOARCH="$ARCH" go build -trimpath -ldflags="-s -w" -o "$STAGE/$NAME/bin/panel" ./cmd/panel)
(cd "$BUILD_ROOT" && CGO_ENABLED=0 GOOS=linux GOARCH="$ARCH" go build -trimpath -ldflags="-s -w" -o "$STAGE/$NAME/bin/panel-executor" ./cmd/executor)
cp -R "$BUILD_ROOT/web/dist/." "$STAGE/$NAME/web/"
cp "$BUILD_ROOT/SOURCE_INPUTS.json" "$STAGE/$NAME/"
find "$STAGE/$NAME/web/assets" -type f \( -name '*.js' -o -name '*.css' \) -print0 | while IFS= read -r -d '' asset; do
  gzip -9 -n -c "$asset" > "$asset.gz"
done
cp "$BUILD_ROOT/dev/"*.service "$BUILD_ROOT/dev/"*.timer "$STAGE/$NAME/systemd/"
rm -f "$STAGE/$NAME/systemd/panel-pebble"*
cp "$BUILD_ROOT/dev/nginx.conf" "$BUILD_ROOT/dev/nginx-panel.conf" "$STAGE/$NAME/config/"
cp "$BUILD_ROOT/packaging/install.sh" "$BUILD_ROOT/packaging/verify-release.sh" "$BUILD_ROOT/packaging/prune-releases.sh" "$BUILD_ROOT/packaging/first-install.py" "$BUILD_ROOT/packaging/waf-state-directory.py" "$BUILD_ROOT/packaging/native-build-directories.py" "$BUILD_ROOT/packaging/release-file-modes.py" "$STAGE/$NAME/"
chmod 0755 "$STAGE/$NAME/install.sh" "$STAGE/$NAME/verify-release.sh" "$STAGE/$NAME/prune-releases.sh" "$STAGE/$NAME/bin/"*
cat > "$STAGE/$NAME/RELEASE" <<EOF
PANEL_FORMAT=1
PANEL_VERSION=$VERSION
PANEL_OS=linux
PANEL_ARCH=$ARCH
EOF
(command -v xattr >/dev/null && xattr -cr "$STAGE/$NAME") || true
(
  cd "$STAGE/$NAME"
  { find bin web systemd config -type f; printf '%s\n' RELEASE SOURCE_INPUTS.json BUILD_CHECKS.txt install.sh verify-release.sh prune-releases.sh first-install.py waf-state-directory.py native-build-directories.py release-file-modes.py; } | LC_ALL=C sort | xargs shasum -a 256 > SHA256SUMS
)
python3 "$BUILD_ROOT/packaging/release-file-modes.py" normalize "$STAGE/$NAME"
"$STAGE/$NAME/verify-release.sh" "$STAGE/$NAME"
COPYFILE_DISABLE=1 tar --no-xattrs -C "$STAGE" -czf "$STAGE/$NAME.tar.gz" "$NAME"
# Exclusive hard links publish on this filesystem without ever overwriting a release.
printf '%s  %s\n' "$(shasum -a 256 "$STAGE/$NAME.tar.gz" | cut -d ' ' -f 1)" "$NAME.tar.gz" > "$STAGE/archive.sha256"
ln "$STAGE/$NAME.tar.gz" "$OUT/$NAME.tar.gz"
ln "$STAGE/archive.sha256" "$OUT/$NAME.tar.gz.sha256"
ln "$STAGE/executor-tests" "$OUT/$NAME.executor-tests"
printf '%s  %s\n' "$(shasum -a 256 "$STAGE/executor-tests" | cut -d ' ' -f 1)" "$OUT/$NAME.executor-tests" > "$STAGE/executor-tests.sha256"
ln "$STAGE/executor-tests.sha256" "$OUT/$NAME.executor-tests.sha256"
echo "$OUT/$NAME.tar.gz"
