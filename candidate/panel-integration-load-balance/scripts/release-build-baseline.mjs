// Reverse only the reviewed L4 additions. The caller still compares the entire
// remaining build script with its pre-L4 frozen digest; unknown edits survive.
import assert from 'node:assert/strict';

export function beforeLoadBalanceStreamBuild(text) {
  const once = (current, previous) => {
    assert.equal(text.split(current).length, 2, 'missing or duplicate L4 build contract');
    text = text.replace(current, () => previous);
  };
  once(`APP_CHANNEL="\${3:-stable}"
if (( $# > 3 )) || [[ "$APP_CHANNEL" != stable && "$APP_CHANNEL" != candidate ]]; then echo 'application channel must be stable or candidate; no URL/key override is accepted' >&2; exit 2; fi
if [[ "$APP_CHANNEL" == candidate && "$VERSION" != *candidate* ]]; then echo 'candidate application channel requires a clearly labelled candidate programme version' >&2; exit 2; fi
`, '');
  once(`PROGRAMME_INPUTS_SHA="$(python3 -I -B - "$BUILD_ROOT/SOURCE_INPUTS.json" <<'PY_PROGRAMME_INPUTS'
import json, pathlib, re, sys
value = json.loads(pathlib.Path(sys.argv[1]).read_bytes())
digest = value['inputs_sha256']
if value['format'] != 1 or not isinstance(digest, str) or not re.fullmatch('[a-f0-9]{64}', digest) or digest == '0' * 64:
    raise ValueError('invalid independently frozen programme cohort')
print(digest)
PY_PROGRAMME_INPUTS
)"
PANEL_LDFLAGS="-s -w -X=local/panel/internal/appcatalog.officialCatalogChannel=$APP_CHANNEL"
EXECUTOR_LDFLAGS="$PANEL_LDFLAGS -X=local/panel/internal/executor.loadBalanceStreamCompiledProgrammeInputsSHA256=$PROGRAMME_INPUTS_SHA"
`, '');
  once(`printf 'Official app catalogue channel: %s (same compiled publisher key; no runtime override)\\n' "$APP_CHANNEL" | tee -a "$STAGE/$NAME/BUILD_CHECKS.txt"
`, '');
  once('go build -trimpath -ldflags="$PANEL_LDFLAGS" -o "$STAGE/$NAME/bin/panel" ./cmd/panel', 'go build -trimpath -ldflags="-s -w" -o "$STAGE/$NAME/bin/panel" ./cmd/panel');
  for (const name of ['test-load-balance-stream.mjs', 'test-load-balance-stream-account-entry.mjs']) {
    once('(cd "$BUILD_ROOT" && /opt/homebrew/bin/node --test scripts/' + name + ') 2>&1 | tee -a "$STAGE/$NAME/BUILD_CHECKS.txt"\n', '');
  }
  for (const command of [
    'go test -c -ldflags="$EXECUTOR_LDFLAGS" -o "$STAGE/executor-tests" ./internal/executor',
    'go build -trimpath -ldflags="$EXECUTOR_LDFLAGS" -o "$STAGE/$NAME/bin/panel-executor" ./cmd/executor',
  ]) once(command, command.replace('"$EXECUTOR_LDFLAGS"', '"-s -w"'));
  // Preserve the previous whole-script digest while requiring these exact
  // additional frozen read-only component artifacts once each. Unknown build
  // edits and every earlier runtime/authority gate remain in the digest.
  for (const addition of [
  "[[ ! -e \"$OUT/$NAME.upgraderead-tests\" && ! -e \"$OUT/$NAME.upgraderead-tests.sha256\" ]] || { echo 'release maintenance reader test artifact already exists; choose a new version' >&2; exit 1; }\n",
  "(cd \"$BUILD_ROOT\" && CGO_ENABLED=0 GOOS=linux GOARCH=\"$ARCH\" go test -c -ldflags=\"-s -w\" -o \"$STAGE/upgraderead-tests\" ./internal/upgraderead)\n",
  "ln \"$STAGE/upgraderead-tests\" \"$OUT/$NAME.upgraderead-tests\"\n",
  "printf '%s  %s\\n' \"$(shasum -a 256 \"$STAGE/upgraderead-tests\" | cut -d ' ' -f 1)\" \"$OUT/$NAME.upgraderead-tests\" > \"$STAGE/upgraderead-tests.sha256\"\n",
  "ln \"$STAGE/upgraderead-tests.sha256\" \"$OUT/$NAME.upgraderead-tests.sha256\"\n"
]) once(addition, '');
  // The independent country gate is mandatory; no other build bytes move.
  once('(cd "$BUILD_ROOT" && /opt/homebrew/bin/node --test scripts/test-waf-country-identity.mjs scripts/test-waf-country-policy.mjs) 2>&1 | tee -a "$STAGE/$NAME/BUILD_CHECKS.txt"\n', '');
  return text;
}
