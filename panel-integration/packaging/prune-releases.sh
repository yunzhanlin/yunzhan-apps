#!/usr/bin/env bash
set -euo pipefail

ROOT=/
KEEP=10
APPLY=0
usage() {
  echo 'usage: prune-releases.sh [--root DIR] [--keep COUNT] [--apply]'
  echo 'Defaults to a read-only preview. Keeps the current release and the COUNT newest release directories.'
}
while (($#)); do
  case "$1" in
    --root) ROOT="${2:?}"; shift 2 ;;
    --keep) KEEP="${2:?}"; shift 2 ;;
    --apply) APPLY=1; shift ;;
    --help) usage; exit 0 ;;
    *) usage >&2; exit 2 ;;
  esac
done
[[ "$KEEP" =~ ^[1-9][0-9]*$ ]] && ((KEEP <= 1000)) || { echo 'keep must be an integer from 1 to 1000' >&2; exit 2; }
[[ "$ROOT" == /* && -d "$ROOT" && ! -L "$ROOT" ]] || { echo 'root must be an existing absolute ordinary directory' >&2; exit 2; }
ROOT="$(realpath -e -- "$ROOT")"
if ((APPLY)) && [[ "$ROOT" == / ]] && ((EUID != 0)); then echo 'apply to the host requires root' >&2; exit 1; fi
RELEASES="${ROOT%/}/opt/panel/releases"
CURRENT="${ROOT%/}/opt/panel/current"
[[ -d "$RELEASES" && ! -L "$RELEASES" && -L "$CURRENT" ]] || { echo 'release directory and current symlink are required' >&2; exit 1; }
RELEASES="$(realpath -e -- "$RELEASES")"
CURRENT_TARGET="$(readlink -f -- "$CURRENT")"
CURRENT_VERSION="${CURRENT_TARGET##*/}"
[[ "$CURRENT_TARGET" == "$RELEASES/$CURRENT_VERSION" && -d "$CURRENT_TARGET" && ! -L "$CURRENT_TARGET" ]] || { echo 'current release must resolve to a direct release directory' >&2; exit 1; }
[[ "$CURRENT_VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+([.-][a-z0-9]+)*$ ]] || { echo 'current release has an invalid version name' >&2; exit 1; }
command -v flock >/dev/null || { echo 'flock is required' >&2; exit 1; }
LOCK="$RELEASES/.release.lock"
[[ ! -L "$LOCK" ]] || { echo 'release lock must not be a symlink' >&2; exit 1; }
if ((APPLY)); then
  if [[ -e "$LOCK" ]]; then exec 9<>"$LOCK"; else exec 9>"$LOCK"; fi
  flock -x 9
elif [[ -f "$LOCK" ]]; then
  exec 9<"$LOCK"
  flock -s 9
fi
[[ "$(readlink -f -- "$CURRENT")" == "$CURRENT_TARGET" ]] || { echo 'current release changed while acquiring lock' >&2; exit 1; }

mapfile -t ORDERED < <(find "$RELEASES" -mindepth 1 -maxdepth 1 -type d -printf '%T@ %f\n' | LC_ALL=C sort -k1,1nr -k2,2Vr | cut -d' ' -f2-)
declare -A PROTECTED=()
PROTECTED["$CURRENT_VERSION"]=1
rank=0
for version in "${ORDERED[@]}"; do
  [[ "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+([.-][a-z0-9]+)*$ ]] || continue
  if ((rank < KEEP)); then PROTECTED["$version"]=1; fi
  rank=$((rank + 1))
done

count=0
bytes=0
for version in "${ORDERED[@]}"; do
  [[ "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+([.-][a-z0-9]+)*$ ]] || continue
  [[ -n "${PROTECTED[$version]+x}" ]] && continue
  path="$RELEASES/$version"
  [[ -d "$path" && ! -L "$path" ]] || continue
  [[ "$(readlink -f -- "$CURRENT")" != "$path" ]] || { echo 'current release changed; refusing cleanup' >&2; exit 1; }
  if mountpoint -q -- "$path"; then echo "release is a mount point: $path" >&2; exit 1; fi
  size="$(du -sb -- "$path" | cut -f1)"
  if ((APPLY)); then rm -rf --one-file-system -- "$path"; printf 'removed %s (%s bytes)\n' "$version" "$size";
  else printf 'would remove %s (%s bytes)\n' "$version" "$size"; fi
  count=$((count + 1))
  bytes=$((bytes + size))
done
printf 'current=%s keep_newest=%s candidates=%s bytes=%s mode=%s\n' "$CURRENT_VERSION" "$KEEP" "$count" "$bytes" "$([[ "$APPLY" == 1 ]] && echo apply || echo preview)"
