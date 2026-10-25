import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { createHash } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { originalReviewedFiveAppHistoricalWorkflow, original34WorkflowSHA } from './reviewed-five-app-workflow.mjs';
const root = fileURLToPath(new URL('..', import.meta.url));
const scope = 'panel-integration-mobile-delivery-links/';
const parent = 'panel-integration-memcached-retirement-handler/';
const read = name => fs.readFileSync(root + name), json = name => JSON.parse(read(name));
const sha = bytes => createHash('sha256').update(bytes).digest('hex');
const changed = ['internal/executor/app_load_balance_https_linux_test.go', 'packaging/build-release.sh', 'web/package-lock.json', 'web/package.json', 'web/src/AppModuleReport.vue'];
const added = ['scripts/test-mobile-delivery-links.mjs', 'web/src/mobileDelivery.ts'];
test('new mobile link source is exactly1922 archive-bound files with no overlay or private L4 work', () => {
  const report = json('registry/mobile-delivery-links-core.json');
  const raw = read(scope + 'source-sha256.json'), value = JSON.parse(raw);
  assert.equal(sha(raw), report.export.index_sha256);
  assert.equal(sha(read(scope + 'release-source-inputs.json')), report.export.release_index_sha256);
  assert.equal(value.release.frozen_inputs_sha256, '3858db5be263ebb85537a695cd9fdf16c14b32df696aa289bf1cc5e383801255');
  assert.equal(value.release.archive, 'panel-0.1.0-dev.proapps24mobilelinkblgt-linux-amd64.tar.gz');
  assert.equal(value.release.archive_sha256, report.normal_programme_builds.amd64.archive_sha256);
  assert.deepEqual(value.test_overrides, {});
  assert.equal(Object.keys(value.files).length, 1922);
  assert.equal(Object.keys(value.files).filter(name => name.endsWith('.go')).length, 1459);
  assert(!Object.keys(value.files).some(name => name.startsWith('internal/loadbalancestream/')));
  assert.deepEqual(json(scope + 'release-source-inputs.json'), { ...value.release, files: value.files });
  for (const [name, digest] of Object.entries(value.files)) {
    const file = root + scope + name, st = fs.lstatSync(file);
    assert(path.posix.normalize(name) === name && !path.isAbsolute(name) && !name.split('/').some(s => ['..', '.git', '.local', 'node_modules'].includes(s)));
    assert(st.isFile() && !st.isSymbolicLink() && st.nlink === 1 && st.size <= (2 << 20));
    assert.equal(sha(fs.readFileSync(file)), digest, name);
  }
});
test('every production Go input remains byte-exact F48 and only the declared seven source members differ', () => {
  const oldRaw = read(parent + 'source-sha256.json'), old = JSON.parse(oldRaw), current = json(scope + 'source-sha256.json');
  assert.equal(sha(oldRaw), 'a1c1909d3a33c6abaf613e9feaf50af2c846d1db7055f4d1b4cb87e918bc1467');
  assert.equal(old.release.frozen_inputs_sha256, 'f7d38cf4498342a12e59ec57c1a7ce404ac1a2b3daaab3c093f51e54b95e409b');
  assert.deepEqual(Object.keys(old.files).filter(name => old.files[name] !== current.files[name]), changed);
  assert.deepEqual(Object.keys(current.files).filter(name => !Object.hasOwn(old.files, name)), added);
  assert(!Object.keys(old.files).some(name => !current.files[name]));
  for (const name of Object.keys(old.files).filter(name => name.endsWith('.go') && !name.endsWith('_test.go'))) assert.equal(current.files[name], old.files[name], name);
  for (const name of ['web/src/FileManager.vue', 'web/src/MemcachedUnixManager.vue', 'internal/executor/memcached_unix_retirement_linux.go', 'internal/core/app_mobile.go']) assert.equal(current.files[name], old.files[name]);
});
test('the ordinary release build adds its real-delivery gate without deleting any previous test or changing any bound', () => {
  const old = read(parent + 'packaging/build-release.sh').toString(), current = read(scope + 'packaging/build-release.sh').toString();
  const line = '(cd "$BUILD_ROOT" && /opt/homebrew/bin/node --test scripts/test-mobile-delivery-links.mjs) 2>&1 | tee -a "$STAGE/$NAME/BUILD_CHECKS.txt"\n';
  assert.equal(current.split(line).length, 2);
  assert.equal(current.replace(line, ''), old);
});
test('the canonical HTTPS fixture retains its original complete test while separating only colliding fixture ports', () => {
  const text = read(scope + 'internal/executor/app_load_balance_https_linux_test.go').toString();
  assert.equal(sha(text), '026dce1a592366561eecba2ba4e7eb1c16828285f226c3fd9140e79be8e98ff3');
  const old = read(parent + 'internal/executor/app_load_balance_https_linux_test.go').toString();
  const addedAt = text.indexOf('\nfunc lbHTTPSFixtureAvoidPortCollision(');
  assert(addedAt > 0);
  assert.equal(text.slice(0, addedAt).replace('\n\tlbHTTPSFixtureAvoidPortCollision(t, &in)', ''), old.trimEnd() + '\n');
  for (const value of ['otherRequests.Load() != 0', 'rows[0]["reason"] != "status_mismatch"', 'TLS observer changed routing configuration', 'for _, checkPort := range []int{42791, 41001, 41002, 41003}']) assert(text.includes(value), value);
});
test('the previous complete34-job workflow stays byte-exact and the35th gate is an independent workflow', () => {
  const report = json('registry/mobile-delivery-links-core.json'), original = read('.github/workflows/verify.yml');
  assert.equal(sha(original), report.original34_workflow_sha256);
  assert.equal(sha(originalReviewedFiveAppHistoricalWorkflow(original)), original34WorkflowSHA);
  assert.equal(original.toString().slice(original.indexOf('\njobs:\n')).match(/^  [a-z0-9-]+:$/gm).length, 34);
  const addedWorkflow = read('.github/workflows/mobile-delivery-links.yml').toString();
  assert.deepEqual(addedWorkflow.match(/^  [a-z0-9_-]+:$/gm), ['  push:', '  pull_request:', '  mobile-delivery-links-native-amd64:']);
  for (const value of ['timeout-minutes: 25', 'npm ci --prefix panel-integration-mobile-delivery-links/web --ignore-scripts', 'node scripts/web-entry-budget.mjs web/dist', 'FixturePortCollisionsKeepOriginalAdmission', 'node --test tests/mobile-delivery-links-source.test.mjs']) assert(addedWorkflow.includes(value), value);
  assert(!/continue-on-error|--overlay|reset-failed|TestNone/.test(addedWorkflow));
});
test('download links are closed metadata records for genuine1.3.0 and actual1.3.2 deliveries, not arbitrary URLs', () => {
  const helper = read(scope + 'web/src/mobileDelivery.ts').toString(), component = read(scope + 'web/src/AppModuleReport.vue').toString();
  for (const version of ['"1.3.0":', '"1.3.2":']) assert(helper.includes(version));
  assert(!helper.includes('"1.3.1":') && !helper.includes('fetch(') && !helper.includes('localStorage'));
  for (const value of ['Object.getOwnPropertyDescriptor(item, key)', 'cohort.files[filename] !== sha256', 'url !== cohort.prefix + filename']) assert(helper.includes(value));
  assert(component.includes('mobileArtifactURL(props.report.version, item)'));
  assert(component.includes('v-if="mobileDownloadURL(item)" :href="mobileDownloadURL(item)"'));
  assert(component.includes('target="_blank" rel="noopener noreferrer"'));
  assert(component.includes('交付物与报告版本或内置发布清单不一致'));
  const artifact = json('registry/mobile-delivery-links-core.json').actual_downloaded_mobile132_artifacts;
  assert.equal(artifact.length, 3);
  for (const item of artifact) assert(helper.includes(item.filename) && helper.includes(item.sha256) && item.bytes > 0);
});
test('both normal builds keep exact original Go ELF bytes but portable builds are not signatures installation or device acceptance', () => {
  const report = json('registry/mobile-delivery-links-core.json');
  for (const arch of ['amd64', 'arm64']) {
    const build = report.normal_programme_builds[arch];
    assert(build.portable_build_artifacts_complete_and_verified && build.all_three_original_F48_Go_ELFs_byte_identical);
    assert.equal(build.source_inputs_sha256, '3858db5be263ebb85537a695cd9fdf16c14b32df696aa289bf1cc5e383801255');
    assert.equal(build.source_overrides, 0);
    assert(!build.signed && !build.installed && !build.all50_commercial);
    assert.deepEqual(Object.keys(build.programmes).sort(), ['panel', 'panel-executor', 'panel-start-guard']);
  }
  for (const key of ['signed', 'normal_upgrade_accepted', 'Main19100_download_buttons_fixed', 'physical_Android_device_accepted', 'signed_iOS_device_accepted', 'all50_commercial']) assert.equal(report[key], false, key);
  assert.equal(report.application_manifests_changed, 0);
  assert.equal(report.production_Go_implementation_changes, 0);
});
test('the same minor-line official Vite security backport is exact and does not update any unrelated dependency', () => {
  const before = json(parent + 'web/package.json'), now = json(scope + 'web/package.json');
  assert.equal(now.devDependencies.vite, '8.2.4');
  assert.deepEqual({ ...now, devDependencies: { ...now.devDependencies, vite: '8.2.2' } }, before);
  const oldLock = json(parent + 'web/package-lock.json'), lock = json(scope + 'web/package-lock.json');
  assert.deepEqual(Object.keys(lock.packages).sort(), Object.keys(oldLock.packages).sort());
  assert.deepEqual(Object.keys(oldLock.packages).filter(name => JSON.stringify(oldLock.packages[name]) !== JSON.stringify(lock.packages[name])), ['', 'node_modules/vite']);
  const vite = lock.packages['node_modules/vite'];
  assert.equal(vite.version, '8.2.4');
  assert.equal(vite.resolved, 'https://registry.npmjs.org/vite/-/vite-8.2.4.tgz');
  assert.equal(vite.integrity, 'sha512-lfauXnrf2x0p+UoA+wXh0dgFWnUjCyG6Js95KBkgaCwUU9k0DAHI4W6Q0WCx+h+5g+Alce1y4Zi2QjjK0UvGBw==');
  assert.equal(json('registry/mobile-delivery-links-core.json').known_dependency_audit_count, 0);
  assert(read('.github/workflows/mobile-delivery-links.yml').includes('npm audit --prefix panel-integration-mobile-delivery-links/web --audit-level=low'));
});
