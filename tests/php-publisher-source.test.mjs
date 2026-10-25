import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import { createHash } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';
import { phpPublisherCIScope, verifyPHPPublisherCISource, phpPublisherCIArguments } from '../tools/run-php-publisher-ci.mjs';
import { phpPublisherNativeTests, phpPublisherNativeCIArguments, verifyPHPPublisherNativeEvents } from '../tools/run-php-publisher-native-ci.mjs';

const root = fileURLToPath(new URL('../', import.meta.url)), scope = 'panel-integration-php-publisher/', parent = 'panel-integration-compiler-memory/';
const read = n => fs.readFileSync(root + n), json = n => JSON.parse(read(n)), sha = b => createHash('sha256').update(b).digest('hex'), report = json('registry/php-publisher-core.json');
test('exact1940 archive-bound members and1475 Go files have no private trees, overlays or unfinished L4', () => {
  const index = verifyPHPPublisherCISource(root + scope.slice(0, -1));
  assert.equal(phpPublisherCIScope.files, 1940); assert.equal(phpPublisherCIScope.Go, 1475);
  assert.equal(sha(read(scope + 'source-sha256.json')), report.export.source_index_sha256);
  assert.equal(sha(read(scope + 'release-source-inputs.json')), report.export.release_index_sha256);
  assert.deepEqual(json(scope + 'release-source-inputs.json'), { ...index.release, files: index.files });
  assert.equal(index.release.frozen_inputs_sha256, report.frozen_inputs_sha256);
  assert(!Object.keys(index.files).some(n => n.startsWith('internal/loadbalancestream/')));
  assert.throws(() => verifyPHPPublisherCISource(root + parent.slice(0, -1))); assert.throws(() => verifyPHPPublisherCISource(root + scope));
});
test('three changed members and six additions are the entire parent delta and preserve all prior runtime policies', () => {
  const a = json(parent + 'source-sha256.json'), z = json(scope + 'source-sha256.json');
  assert.equal(sha(read(parent + 'source-sha256.json')), '911b5d13f3e1e62ba4d040e5916baeb68624435b4cc71bef7dbff33f7b802ac4');
  assert.deepEqual(Object.keys(a.files).filter(n => a.files[n] !== z.files[n]), report.changed_source_members);
  assert.deepEqual(Object.keys(z.files).filter(n => !a.files[n]), report.added_source_members); assert(!Object.keys(a.files).some(n => !z.files[n]));
  for (const [n, h] of Object.entries(a.files)) if (!report.changed_source_members.includes(n)) assert.equal(z.files[n], h, n);
  assert.equal(z.files['dev/panel-install@.service'], 'bf2432e1084dce9629be620dfab2ed47995c9bbfa86a70285990f4d6fb1cd947');
  assert.equal(z.files['internal/executor/program_upgrade_runtime_compile_oom_linux.go'], '174c81f08b3215402b4ff0ee9d14dd7aa0fa0e24c08a2e25dad91d0f77758ef1');
  assert.equal(z.files['internal/core/runtime_compile_oom_upgrade.go'], '06c7de138a4a3625b24cba22d45b3ac6105c6ed99123ab5f00f53e1963f163e1');
  for (const [n, h] of Object.entries(report.native_component.exact_Go_files)) assert.equal(z.files[n], h, n);
  assert.equal(report.production_Go_existing_changes, 2); assert.equal(report.production_Go_added, 3); assert.equal(report.added_Go_tests, 3);
});
test('the optional new-build seal and read-only successor proof cannot adopt legacy prefixes or relabel old failures', () => {
  const p = report.policy;
  for (const key of ['legacy_manifests_remain_inventory_compatible', 'existing_prefixes_never_adopted_as_new_publishers', 'actual_InstallJob_identity_only', 'official_source_and_exact_native_architecture', 'source_bound_CLI_and_FPM_bytes_and_sha256', 'new_FPM_version_check_before_publication', 'final_streaming_held_descriptor_rehash_required', 'existing_readonly_start_and_build_leases_required', 'original_stopped_OOM_generation_required', 'original_failed_Core_and_raw_native_ledgers_never_relabelled', 'distinct_successful_publisher_and_audits_required', 'canonical_manifest_and_native_ledger_bytes_required', 'unknown_pending_jobs_and_unconsumed_retry_grants_refuse', 'upgrade_Core_validator_SELECT_only', 'original_unpublished_OOM_protocols_byte_identical', 'installer_unit_unchanged_from_parent']) assert.equal(p[key], true, key);
  assert.equal(p.native_budget_seconds, 5); assert.equal(p.memory_max_bytes, 1073741824); assert.equal(p.swap_limit_bytes, 0); assert.equal(p.task_limit, 512); assert.equal(p.timeout_minutes, 300);
  const env = { ...process.env }; delete env.NODE_TEST_CONTEXT;
  const run = spawnSync(process.execPath, ['--test', '--test-reporter=tap', 'scripts/test-runtime-build-pressure.mjs', 'scripts/test-native-queue-unit-snapshot.mjs'], { cwd: root + scope, env, encoding: 'utf8', timeout: 30000, maxBuffer: 2 << 20 });
  assert.equal(run.status, 0, run.stdout + run.stderr); for (const value of ['# tests 10', '# pass 10', '# fail 0', '# skipped 0']) assert(run.stdout.includes(value), value);
});
test('all original38 workflows stay byte-exact and the39th complete-source Root gate has no skip or deadline bypass', () => {
  assert.equal(Object.keys(report.original38_workflow_files).length, 7);
  for (const [n, h] of Object.entries(report.original38_workflow_files)) assert.equal(sha(read('.github/workflows/' + n)), h, n);
  const text = read('.github/workflows/php-publisher.yml').toString();
  assert.deepEqual(text.match(/^  [a-z0-9_-]+:$/gm), ['  push:', '  pull_request:', '  php-publisher-contracts-linux-amd64:']);
  for (const value of ['timeout-minutes: 25', 'tests/php-publisher-source.test.mjs', 'run-php-publisher-native-ci.mjs', 'run-php-publisher-ci.mjs', 'test -p 1 ./... -count=1', 'go test -race ./internal/core', 'go vet ./...', '--ignore-scripts', '--preserve-env=GITHUB_ACTIONS,GITHUB_REPOSITORY']) assert(text.includes(value), value);
  assert(!/continue-on-error|--overlay|reset-failed|TestNone|GOFLAGS|GOENV/.test(text));
  assert.deepEqual(phpPublisherCIArguments(['test', '-p', '1', './...', '-count=1']), ['test', '-p', '1', './...', '-count=1']);
  for (const args of [['test', './internal/executor'], ['test', '-p', '1', './...'], ['test', '-p', '1', './...', '-count=1', '-run=TestNone'], ['test', '-overlay=foreign.json', '-p', '1', './...', '-count=1']]) assert.throws(() => phpPublisherCIArguments(args));
});
test('native race gate requires all six actual Root groups and120 passes without any skip, failure or reduced argument', () => {
  const args = phpPublisherNativeCIArguments(); assert.equal(phpPublisherNativeTests.length, 6);
  assert.deepEqual(args.slice(0, 4), ['test', '-race', '-json', './internal/executor']); assert.equal(args.at(-1), '-count=1'); assert.equal(args.length, 6);
  const rows = phpPublisherNativeTests.map(Test => ({ Action: 'pass', Test }));
  for (let i = 0; i < 114; i++) rows.push({ Action: 'pass', Test: phpPublisherNativeTests[0] + '/parser-model-' + i });
  rows.push({ Action: 'pass', Package: 'local/panel/internal/executor' });
  assert.deepEqual(verifyPHPPublisherNativeEvents(rows), { top_level: 6, including_subtests: 120, failed: 0, skipped: 0 });
  for (const changed of [[], rows.slice(1), [...rows, { Action: 'skip' }], [...rows, { Action: 'fail' }], rows.map((v, i) => i === 0 ? { ...v, Test: 'ForeignRootTest' } : v), rows.map((v, i) => i === rows.length - 1 ? { ...v, Package: 'foreign/package' } : v)]) assert.throws(() => verifyPHPPublisherNativeEvents(changed));
});
test('component, normal build and old-refusal provenance never becomes installed or all50 acceptance', () => {
  const n = report.native_component; assert.equal(n.architecture, 'arm64'); assert.equal(n.top_level, 6); assert.equal(n.including_subtests, 120); assert.equal(n.failures, 0); assert.equal(n.skips, 0);
  assert(n.synthetic_private_Root_model_not_new_installation && n.original_same_size_write_refusal_retained && n.full_original109_schema103_business_runtime_NSS_programmes_preserved); assert.equal(n.original_statistics_window_seconds, 600);
  for (const v of Object.values(report.normal_programme_builds)) { assert.equal(v.original_build_exit, 0); assert(v.start_guard_byte_identical_to_parent && v.installer_unit_byte_identical_to_parent); assert(!v.signed && !v.installed && !v.all50_commercial); }
  assert(report.original_failed_native_and_unpublished_candidates_preserved);
  for (const key of ['programme_signed', 'normal_upgrade_accepted', 'new_Main_PHP_install_accepted', 'all50_commercial']) assert.equal(report[key], false);
});
test('all50 signed app manifests, catalogue and application verification key remain unchanged', () => {
  for (const [n, h] of Object.entries({ 'dist/catalog-v1.json': '247c8db6cc762413c0779f8cb8a251b16d01b641b109981f084076c20f104813', 'signatures/catalog-v1.sig': '4828f4a705f62ca1c8e2380528e0b1d65719e0be37c561790343862c60936727', 'signatures/catalog-v1.bundle.json': 'deb1a606c402933f40b772c920de3396f2b6c8d6c910b581c4acef6b7f6b7f25', 'signatures/catalog-v1.pub.pem': '659ea4edcecaf23a586e2ff371616fde5f6ee7c219fb70fa978816e2b10acf75' })) assert.equal(sha(read(n)), h, n);
  const catalogue = json('dist/catalog-v1.json'); assert.equal(catalogue.apps.length, 50);
  for (const app of catalogue.apps) assert.equal(sha(read('dist/apps/' + app.id + '/' + app.version + '/manifest.json')), app.sha256);
});
