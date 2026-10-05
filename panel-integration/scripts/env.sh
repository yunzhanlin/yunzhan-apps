#!/usr/bin/env bash
set -euo pipefail
PANEL_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
export PANEL_DEV_HOME="${PANEL_DEV_HOME:-/Volumes/MacSSD/MacData/PanelDev}"
export PATH="$PANEL_DEV_HOME/tools/go/bin:$PANEL_DEV_HOME/tools/lima/bin:$PATH"
export LIMA_HOME="$PANEL_DEV_HOME/lima"
export GOCACHE="$PANEL_DEV_HOME/cache/go-build"
export GOMODCACHE="$PANEL_DEV_HOME/cache/go-mod"
export GOPATH="$PANEL_DEV_HOME/cache/gopath"
export npm_config_cache="$PANEL_DEV_HOME/cache/npm"
export GOTOOLCHAIN=local
# The project can be built from an external volume even when macOS developer
# tools (and therefore Git's VCS probe) are unavailable on the host.
export GOFLAGS="${GOFLAGS:--buildvcs=false}"
