// Reverse only the reviewed L4 additions. The caller still compares the entire
// remaining build script with its pre-L4 frozen digest; unknown edits survive.
import assert from 'node:assert/strict';

export function beforeReleaseCompilerPolicy(text) {
  const note=`# A caller may set GOFLAGS for parallelism or include VCS stamping. The fixed
# v4 guard must remain byte identical across unrelated repository commits.
# Make the release policy explicit on the real compiler command so inherited
# GOFLAGS cannot silently replace scripts/env.sh's default buildvcs setting.
`;
  assert.equal(text.split(note).length,2,'missing or duplicate immutable guard compiler policy');
  text=text.replace(note,()=> '');
  for(const [name,flags,entry] of [
    ['panel','$PANEL_LDFLAGS','panel'],
    ['panel-executor','$EXECUTOR_LDFLAGS','executor'],
    ['panel-start-guard','-s -w','startguard'],
  ]) {
    const current='(cd "$BUILD_ROOT" && CGO_ENABLED=0 GOOS=linux GOARCH="$ARCH" go build -trimpath -buildvcs=false -ldflags="'+flags+'" -o "$STAGE/$NAME/bin/'+name+'" ./cmd/'+entry+')\n';
    assert.equal(text.split(current).length,2,'missing, duplicated or changed explicit release compiler policy: '+name);
    text=text.replace(current,()=>current.replace(' -buildvcs=false',''));
  }
  return text;
}

export function beforeUnpublishedCopyBuild(text) {
  text=beforePM2ProjectsBuild(text);
  text=beforeReleaseCompilerPolicy(text);
  const independent='(cd "$BUILD_ROOT" && /opt/homebrew/bin/node --test scripts/test-remote-independent-backup.mjs) 2>&1 | tee -a "$STAGE/$NAME/BUILD_CHECKS.txt"\n';
  const unpublished='(cd "$BUILD_ROOT" && /opt/homebrew/bin/node --test scripts/test-remote-unpublished-copy.mjs) 2>&1 | tee -a "$STAGE/$NAME/BUILD_CHECKS.txt"\n';
  assert.equal(text.split(unpublished).length,2,'missing or duplicate unpublished-retention build gate');
  assert.equal(text.split(independent+unpublished).length,2,'unpublished-retention gate must follow the original independent-copy gate exactly');
  return text.replace(independent+unpublished,independent);
}

// C69 adds only this exact PM2 readonly/stop regression. Preserve every
// previously frozen command and digest; missing, moved, changed or repeated
// gates must still fail instead of being erased by a generic filter.
export function beforePM2ProjectsBuild(text) {
  const previous='(cd "$BUILD_ROOT" && /opt/homebrew/bin/node --test scripts/test-registry-request-identity.mjs) 2>&1 | tee -a "$STAGE/$NAME/BUILD_CHECKS.txt"\n';
  const addition='(cd "$BUILD_ROOT" && /opt/homebrew/bin/node --test scripts/test-pm2-projects.mjs) 2>&1 | tee -a "$STAGE/$NAME/BUILD_CHECKS.txt"\n';
  assert.equal(text.split(previous).length,2,'missing or duplicate original registry request gate');
  assert.equal(text.split(addition).length,2,'missing or duplicate PM2 project gate');
  assert.equal(text.split(previous+addition).length,2,'PM2 project gate must follow the original registry request gate exactly');
  return text.replace(previous+addition,()=>previous);
}

export function beforeLoadBalanceStreamBuild(text) {
  text=beforeUnpublishedCopyBuild(text);
  const once = (current, previous) => {
    assert.equal(text.split(current).length, 2, 'missing or duplicate L4 build contract');
    text = text.replace(current, () => previous);
  };
  // C62 adds exactly one mandatory independent-backup protocol gate after
  // the original remote-archive gate. Require its exact command and position,
  // then reverse only that addition for every unchanged historical build hash.
  const remoteArchiveGate='(cd "$BUILD_ROOT" && /opt/homebrew/bin/node --test scripts/test-remote-backup-archive.mjs) 2>&1 | tee -a "$STAGE/$NAME/BUILD_CHECKS.txt"\n';
  const independentCopyGate='(cd "$BUILD_ROOT" && /opt/homebrew/bin/node --test scripts/test-remote-independent-backup.mjs) 2>&1 | tee -a "$STAGE/$NAME/BUILD_CHECKS.txt"\n';
  assert.equal(text.split(independentCopyGate).length,2,'missing or duplicate independent backup build gate');
  once(remoteArchiveGate+independentCopyGate,remoteArchiveGate);
  // C61's enterprise gate must follow the original website gate exactly.
  // Remove only that new command before the unchanged historical comparison.
  const websiteKernelGate='(cd "$BUILD_ROOT" && /opt/homebrew/bin/node --test scripts/test-integrity-kernel-workspace.mjs) 2>&1 | tee -a "$STAGE/$NAME/BUILD_CHECKS.txt"\n';
  const enterpriseKernelGate='(cd "$BUILD_ROOT" && /opt/homebrew/bin/node --test scripts/test-enterprise-kernel-workspace.mjs) 2>&1 | tee -a "$STAGE/$NAME/BUILD_CHECKS.txt"\n';
  assert.equal(text.split(enterpriseKernelGate).length,2,'missing or duplicate enterprise kernel build gate');
  once(websiteKernelGate+enterpriseKernelGate,websiteKernelGate);
  // C60's fixed inode protection UI/unknown-admission gate is mandatory.
  // Normalize only this exact addition for historical whole-script pins.
  once('(cd "$BUILD_ROOT" && /opt/homebrew/bin/node --test scripts/test-integrity-kernel-workspace.mjs) 2>&1 | tee -a "$STAGE/$NAME/BUILD_CHECKS.txt"\n','');
  // C59 adds one mandatory performance behavior gate immediately after the
  // existing session gate. Reverse only that additive command for historical
  // whole-script pins; omission, duplication, movement or edits still fail.
  const sessionGate='(cd "$BUILD_ROOT" && /opt/homebrew/bin/node --test scripts/test-analytics-session.mjs) 2>&1 | tee -a "$STAGE/$NAME/BUILD_CHECKS.txt"\n';
  const routeGate='(cd "$BUILD_ROOT" && /opt/homebrew/bin/node --test scripts/test-analytics-performance.mjs) 2>&1 | tee -a "$STAGE/$NAME/BUILD_CHECKS.txt"\n';
  assert.equal(text.split(routeGate).length,2,'missing or duplicate route performance gate');
  once(sessionGate+routeGate,sessionGate);
  // Require C57's complete CC archive/recovery UI behavior gate exactly once.
  // Reverse only that reviewed addition for the historical whole-script pins.
  once('(cd "$BUILD_ROOT" && /opt/homebrew/bin/node --test scripts/test-apache-cc-archives.mjs) 2>&1 | tee -a "$STAGE/$NAME/BUILD_CHECKS.txt"\n', '');
  // C56 adds exactly this mandatory CC selection/admission UI regression.
  // Keep every prior command and frozen whole-script digest unchanged;
  // omission, duplication or any altered command must fail normalization.
  once('(cd "$BUILD_ROOT" && /opt/homebrew/bin/node --test scripts/test-apache-cc.mjs) 2>&1 | tee -a "$STAGE/$NAME/BUILD_CHECKS.txt"\n', '');
  // Recognize only C55's exact new helper delivery in the copy and checksum
  // lists. Removing, duplicating or renaming either addition must still fail;
  // all historical commands and whole-script digests remain unchanged.
  once('"$BUILD_ROOT/packaging/native-build-directories.py" "$BUILD_ROOT/packaging/backup-directories.py" "$BUILD_ROOT/packaging/release-file-modes.py"', '"$BUILD_ROOT/packaging/native-build-directories.py" "$BUILD_ROOT/packaging/release-file-modes.py"');
  once('fresh-ssh-policy.py backup-directories.py waf-state-directory.py', 'fresh-ssh-policy.py waf-state-directory.py');
  // Recognize exactly the reviewed Apache numeric-log gate and the larger
  // whole-suite time budget. Keep the old commands and frozen digests intact;
  // removing, duplicating or altering either addition must fail closed.
  once('(cd "$BUILD_ROOT" && /opt/homebrew/bin/node --test scripts/test-apache-numeric-logs.mjs) 2>&1 | tee -a "$STAGE/$NAME/BUILD_CHECKS.txt"\n', '');
  once('go test ./... -timeout=30m', 'go test ./...');
  // Only this additional PM2 acknowledgement/cancellation regression is
  // removed for historical comparison. All old commands and hashes stay.
  once('(cd "$BUILD_ROOT" && /opt/homebrew/bin/node --experimental-strip-types --test scripts/test-pm2-configuration-receipt.mjs) 2>&1 | tee -a "$STAGE/$NAME/BUILD_CHECKS.txt"\n', '');
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
  // Require the exact NFS navigation regression once. Only this reviewed
  // additive command is reversed; the historical whole-script digests stay.
  once('(cd "$BUILD_ROOT" && /opt/homebrew/bin/node --test scripts/test-nfs-report-scope.mjs) 2>&1 | tee -a "$STAGE/$NAME/BUILD_CHECKS.txt"\n', '');
  // Undo only the exact reviewed first-install helper delivery additions.
  // Every earlier command and baseline digest remains protected; changing or
  // omitting this copy/checksum/dependency gate cannot be normalized away.
  once("\"$BUILD_ROOT/packaging/first-install.py\" \"$BUILD_ROOT/packaging/fresh-ssh-policy.py\" \"$BUILD_ROOT/packaging/waf-state-directory.py\"", "\"$BUILD_ROOT/packaging/first-install.py\" \"$BUILD_ROOT/packaging/waf-state-directory.py\"");
  once('first-install.py fresh-ssh-policy.py waf-state-directory.py', 'first-install.py waf-state-directory.py');
  once("# Every literal Python helper used by the packaged installer must be present.\n# Validate the actual assembled tree before checksumming/signing, so a new\n# source helper cannot silently be omitted from the delivery.\npython3 -I -B - \"$STAGE/$NAME\" <<'PY_CHECK_INSTALLER_HELPERS' | tee -a \"$STAGE/$NAME/BUILD_CHECKS.txt\"\nimport pathlib, re, stat, sys\nroot = pathlib.Path(sys.argv[1])\nsource = (root / 'install.sh').read_text()\nhelpers = set(re.findall(r'\\$HERE/([a-z0-9][a-z0-9._-]*\\.py)', source))\nif not 1 <= len(helpers) <= 64:\n    raise ValueError('invalid installer helper dependency set')\ncopy = next(line for line in source.splitlines() if line.startswith('cp -a \"$HERE/bin\"'))\nstaged_helpers = set(re.findall(r'\\$HERE/([a-z0-9][a-z0-9._-]*\\.py)', copy))\nif not helpers <= staged_helpers:\n    raise ValueError('installer does not stage required helper: ' + ','.join(sorted(helpers - staged_helpers)))\nfor name in sorted(helpers):\n    value = (root / name).lstat()\n    if not stat.S_ISREG(value.st_mode) or value.st_nlink != 1:\n        raise ValueError('missing or linked packaged installer helper: ' + name)\nprint('packaged installer helpers verified: ' + str(len(helpers)))\nPY_CHECK_INSTALLER_HELPERS\n", '');
  return text;
}

// Recognize only the new pre-response PHP source retry. All historical
// queue/producer checks still compare their original complete pinned inputs.
function beforePHPSourceResponseRetry(text) {
 for(const addition of [
  "\t\"net\"\n",
  "// sourceResponseTimeout is only constructed before a response or source\n// file exists. A stalled or interrupted body cannot use this retry path.\ntype sourceResponseTimeout struct{ cause error }\n\nfunc (e sourceResponseTimeout) Error() string { return e.cause.Error() }\nfunc (e sourceResponseTimeout) Unwrap() error { return e.cause }\n\n",
  "\tvar responseTimeout sourceResponseTimeout\n\tif r.Family == \"php\" && strings.HasPrefix(r.URL, \"https://www.php.net/distributions/\") && errors.As(err, &responseTimeout) {\n\t\t// A new GET to the same official URL is safe before any response or\n\t\t// staged bytes. Never retry the install or use another source here.\n\t\terr = download(ctx, r.URL, r.SHA256, dst, limits)\n\t\tif cancelled := ctx.Err(); cancelled != nil {\n\t\t\treturn cancelled\n\t\t}\n\t}\n",
  "\t\tvar network net.Error\n\t\tif resp == nil && ctx.Err() == nil && errors.As(e, &network) && network.Timeout() {\n\t\t\treturn sourceResponseTimeout{cause: e}\n\t\t}\n",
 ]) {
  assert.equal(text.split(addition).length,2,"missing, duplicate or altered PHP source response retry");
  text=text.replace(addition,()=>'');
 }
 return text;
}

// Reverse only the exact Apache archive budget for the older PHP source pins.
function beforeApacheSourceArchiveBudget(text) {
 for (const [current, previous] of [
  ["const apacheSourceArchiveBudget = 25 * time.Minute\n\nfunc runtimeSourceTotalCeiling(url, digest string) time.Duration {\n\t// This historical release remains pinned in installed manifests. Allow\n\t// its official archive to finish on a slow link without extending the\n\t// budget for primary URLs, different source bytes, or any other runtime.\n\tapache, ok := runtimecatalog.Find(\"apache-2.4.68\")\n\tif ok && url == runtimecatalog.SourceArchiveURL(apache) && digest == apache.SHA256 {\n\t\treturn apacheSourceArchiveBudget\n\t}\n\treturn 20 * time.Minute\n}\n\n", ""],
  ["\t\t\t// Follow only the exact catalogued Apache archive after relocation.\n\t\t\t// Do not resume partial content or relax its digest or idle budget.\n\t\t\tlimits.Total = runtimeSourceTotalCeiling(archive, r.SHA256)", "\t\t\t// Only this exact catalogued official Apache archive gets 20 minutes.\n\t\t\t// No arbitrary mirrors, URLs, digests, retries or resumed partial bytes.\n\t\t\tlimits.Total = 20 * time.Minute"],
  ["limits.Total > runtimeSourceTotalCeiling(url, digest)", "limits.Total > 20*time.Minute"],
 ]) {
  assert.equal(text.split(current).length,2,'missing, duplicate or altered Apache source archive budget');
  text=text.replace(current,()=>previous);
 }
 return text;
}

// Reverse only C57's exact Apache dependency admission for historical PHP pins.
export function beforeApacheBuildDependencyAdmission(text) {
 text=beforePHPSourceResponseRetry(beforeApacheSourceArchiveBudget(text));
 for(const addition of ["\tif r.Family == \"apache\" && !nativeWAFService().wafBuildPackagesReady([]string{\"libapr1-dev\", \"libaprutil1-dev\", \"libnghttp2-dev\"}) {\n\t\treturn errors.New(\"Apache 编译依赖缺失：请先安装 libapr1-dev、libaprutil1-dev、libnghttp2-dev；本次未下载或编译源码\")\n\t}\n", "\tif e = add(\"正在从官方站点下载精确版本源码并校验完整性\"); e != nil {\n\t\treturn e\n\t}\n"]) {
  assert.equal(text.split(addition).length,2,"missing, duplicate or altered Apache dependency/progress addition");
  text=text.replace(addition,()=>'');
 }
 return text;
}

// Reverse only C65's exact, private offline-reader parameterization. The
// ordinary entry still supplies nil; all previous full-file hashes stay intact.
export function beforeFilesyncOfflineReaderHook(text) {
  {
    const current="func CheckProgramUpgradeQueues() error {\n\treturn checkCompleteProgramUpgradeQueues(nil)\n}\n\n// A nonnil reader is package-private and used only by the explicit signed\n// offline recovery protocol. Ordinary upgrades and all existing controllers\n// always pass nil and retain their complete pending-copy refusal.\nfunc checkCompleteProgramUpgradeQueues(remoteReader func(*Service) error) error {\n\tif err := checkLegacyProgramUpgradeQueuesWithRemoteReader(remoteReader); err != nil {\n\t\treturn err\n\t}\n\tctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)\n\tdefer cancel()\n\tif err := checkApacheNumericLogUpgrade(ctx, \"/\"); err != nil {\n\t\treturn err\n\t}\n\treturn checkLoadBalanceStreamUpgrade(ctx, nil)\n}\n\n// Preserves all existing application, recovery and filesystem checks. The\n// private L4 controllers call this PLUS their independently self-bound fence;\n// they never pass a general native-unit prefix or selected-ID exemption here.\nfunc checkLegacyProgramUpgradeQueues() error {\n\treturn checkLegacyProgramUpgradeQueuesWithRemoteReader(nil)\n}\n\nfunc checkLegacyProgramUpgradeQueuesWithRemoteReader(remoteReader func(*Service) error) error {\n";
    const previous="func CheckProgramUpgradeQueues() error {\n\tif err := checkLegacyProgramUpgradeQueues(); err != nil {\n\t\treturn err\n\t}\n\tctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)\n\tdefer cancel()\n\tif err := checkApacheNumericLogUpgrade(ctx, \"/\"); err != nil {\n\t\treturn err\n\t}\n\treturn checkLoadBalanceStreamUpgrade(ctx, nil)\n}\n\n// Preserves all existing application, recovery and filesystem checks. The\n// private L4 controllers call this PLUS their independently self-bound fence;\n// they never pass a general native-unit prefix or selected-ID exemption here.\nfunc checkLegacyProgramUpgradeQueues() error {\n";
    assert.equal(text.split(current).length,2,'missing, duplicate or altered offline-reader hook');
    text=text.split(current).join(previous);
  }
  {
    const current="checkProgramUpgradeQueuesWithRemoteReader(ctx, \"/\", remoteReader)";
    const previous="checkProgramUpgradeQueues(ctx, \"/\")";
    assert.equal(text.split(current).length,3,'missing, duplicate or altered offline-reader hook');
    text=text.split(current).join(previous);
  }
  {
    const current="func checkProgramUpgradeQueues(ctx context.Context, root string) error {\n\treturn checkProgramUpgradeQueuesWithRemoteReader(ctx, root, nil)\n}\n\nfunc checkProgramUpgradeQueuesWithRemoteReader(ctx context.Context, root string, remoteReader func(*Service) error) error {\n";
    const previous="func checkProgramUpgradeQueues(ctx context.Context, root string) error {\n";
    assert.equal(text.split(current).length,2,'missing, duplicate or altered offline-reader hook');
    text=text.split(current).join(previous);
  }
  {
    const current="\tif remoteReader == nil {\n\t\tif pending, err := protected.remoteCopyPending(\"\", \"\"); err != nil {\n\t\t\treturn err\n\t\t} else if pending {\n\t\t\treturn errors.New(\"独立备份原操作待核对，保留副本和片段并拒绝升级\")\n\t\t}\n\t} else if err := remoteReader(protected); err != nil {\n\t\treturn err\n\t}\n";
    const previous="\tif pending, err := protected.remoteCopyPending(\"\", \"\"); err != nil {\n\t\treturn err\n\t} else if pending {\n\t\treturn errors.New(\"独立备份原操作待核对，保留副本和片段并拒绝升级\")\n\t}\n";
    assert.equal(text.split(current).length,2,'missing, duplicate or altered offline-reader hook');
    text=text.split(current).join(previous);
  }
  return text;
}
