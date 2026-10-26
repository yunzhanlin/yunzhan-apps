import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import { createHash } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';
import { runtimeMemoryWaitCIScope, verifyRuntimeMemoryWaitCISource, runtimeMemoryWaitCIArguments } from '../tools/run-runtime-memory-wait-ci.mjs';
const root = fileURLToPath(new URL('../', import.meta.url)), scope = 'panel-integration-runtime-memory-wait/';
const read = n => fs.readFileSync(root + n), json = n => JSON.parse(read(n)), sha = b => createHash('sha256').update(b).digest('hex');
const report = json('registry/runtime-memory-wait-core.json');
test('exact1948 archive-bound source members and1478 Go files, no private data or unfinished load-balance implementation', () => {
 const index = verifyRuntimeMemoryWaitCISource(root + scope.slice(0, -1));
 assert.equal(runtimeMemoryWaitCIScope.files, 1948); assert.equal(runtimeMemoryWaitCIScope.Go, 1478);
 assert.equal(sha(read(scope + 'source-sha256.json')), report.export.source_index_sha256);
 assert.equal(sha(read(scope + 'release-source-inputs.json')), report.export.release_index_sha256);
 assert.deepEqual(json(scope + 'release-source-inputs.json'), { ...index.release, files: index.files });
 assert(!Object.keys(index.files).some(n => n.startsWith('internal/loadbalancestream/')));
 assert.throws(() => verifyRuntimeMemoryWaitCISource(root + 'panel-integration-php-publisher'));
});
test('all six existing member changes and eight additions are source bound; old Core protocols stay exact', () => {
 const a = json('panel-integration-php-publisher/source-sha256.json'), z = json(scope + 'source-sha256.json');
 assert.equal(sha(read('panel-integration-php-publisher/source-sha256.json')), '286b57d0a6c181ab4010fe97966d46ad52db532cd0f99e265914a7873080c49e');
 assert.deepEqual(Object.keys(a.files).filter(n => a.files[n] !== z.files[n]), report.changed_source_members);
 assert.deepEqual(Object.keys(z.files).filter(n => !a.files[n]), report.added_source_members);
 assert.equal(report.changed_source_members.length, 6); assert.equal(report.added_source_members.length, 8);
 assert(!Object.keys(a.files).some(n => !z.files[n]));
 for (const [n, h] of Object.entries(a.files)) if (!report.changed_source_members.includes(n)) assert.equal(z.files[n], h, n);
});
test('finite wait cannot lower the budget, trust unknown failures, replay a job or extend its original deadline', () => {
 const p = report.policy;
 for (const key of ['fixed_1GiB_kernel_limit','zero_swap','existing512MiB_service_reserve_unchanged','initial_admission_immediate_and_unchanged','original_parent_context_inherited','exact_internal_shortage_only','identity_inventory_kernel_and_unknown_failures_immediate','no_jobs_replayed_or_prefixes_adopted','no_controller_cache_or_NSS_writes','no_file_cache_or_slab_host_credit','original240minute_build_and300minute_unit_unchanged','original_publication_and_failed_OOM_protocols_unchanged']) assert.equal(p[key], true, key);
 assert.equal(p.maximum_memory_wait_seconds, 90); assert.equal(p.memory_poll_seconds, 2); assert.equal(p.maximum_retries, 45);
 const env = { ...process.env }; delete env.NODE_TEST_CONTEXT;
 const run = spawnSync(process.execPath, ['--experimental-strip-types','--test','--test-reporter=tap','scripts/test-runtime-memory-wait.mjs','scripts/test-runtime-selection.mjs','scripts/test-native-queue-unit-snapshot.mjs'], {cwd:root+scope,env,encoding:'utf8',timeout:30000,maxBuffer:2<<20});
 assert.equal(run.status,0,run.stdout+run.stderr);
 for (const value of ['# tests 37','# pass 37','# fail 0','# skipped 0']) assert(run.stdout.includes(value),value);
});
test('all original39 workflows remain byte exact; 40th complete Root gate has no skip, overlay or time bypass', () => {
 assert.equal(Object.keys(report.original39_workflow_files).length,8);
 for (const [n,h] of Object.entries(report.original39_workflow_files)) assert.equal(sha(read('.github/workflows/'+n)),h,n);
 const text=read('.github/workflows/runtime-memory-wait.yml').toString();
 assert.deepEqual(text.match(/^  [a-z0-9_-]+:$/gm),['  push:','  pull_request:','  runtime-memory-wait-contracts-linux-amd64:']);
 for (const s of ['timeout-minutes: 25','run-runtime-memory-wait-ci.mjs','test -p 1 ./... -count=1','go vet ./...','--ignore-scripts','test -race ./internal/executor','test-runtime-memory-wait.mjs','test-runtime-selection.mjs']) assert(text.includes(s),s);
 assert(!/continue-on-error|--overlay|reset-failed|TestNone|GOFLAGS|GOENV/.test(text));
 assert.deepEqual(runtimeMemoryWaitCIArguments(['test','-p','1','./...','-count=1']),['test','-p','1','./...','-count=1']);
 for (const args of [['test','./...'],['test','-p','1','./...','-count=1','-run=TestNone'],['test','-overlay=foreign.json','-p','1','./...','-count=1']]) assert.throws(()=>runtimeMemoryWaitCIArguments(args));
});
test('actual kernel and synthetic UI components never claim a new programme, PHP installation or all50 acceptance', () => {
 const n=report.native_component;
 assert.equal(n.arch,'arm64'); assert.equal(n.top_level_cases,2); assert.equal(n.failures,0); assert.equal(n.skips,0);
 assert(n.actual_host_pressure_not_injected&&n.typed_transient_fixture_not_claimed_as_real_pressure&&n.obsolete768MiB_actual_kernel_refused&&n.all109_schema103_full_business_NSS_runtime_programmes_preserved);
 assert(n.original600_second_window_seconds>=0&&n.original600_second_window_seconds<=600&&!n.normal_runtime_or_programme_installation);
 assert.equal(report.source_release_archive.ordinary_full_build_exit,0);
 assert(report.source_release_archive.core_panel_and_start_guard_unchanged&&report.source_release_archive.only_executor_programme_changed&&report.source_release_archive.installer_unit_unchanged);
 assert(report.original_failed_native_and_unpublished_candidates_preserved);
 assert.equal(report.UI.source_contracts,23); assert.equal(report.UI.original_synthetic_browser_checks,8); assert(!report.UI.installed_UI_acceptance);
 for (const key of ['programme_signed','normal_upgrade_accepted','new_Main_PHP_install_accepted','all50_commercial']) assert.equal(report[key],false);
});
test('signed fifty application manifests and catalogue trust remain unchanged', () => {
 for (const [n,h] of Object.entries({'dist/catalog-v1.json':'247c8db6cc762413c0779f8cb8a251b16d01b641b109981f084076c20f104813','signatures/catalog-v1.sig':'4828f4a705f62ca1c8e2380528e0b1d65719e0be37c561790343862c60936727','signatures/catalog-v1.bundle.json':'deb1a606c402933f40b772c920de3396f2b6c8d6c910b581c4acef6b7f6b7f25','signatures/catalog-v1.pub.pem':'659ea4edcecaf23a586e2ff371616fde5f6ee7c219fb70fa978816e2b10acf75'})) assert.equal(sha(read(n)),h,n);
 const catalogue=json('dist/catalog-v1.json');assert.equal(catalogue.apps.length,50);
 for (const app of catalogue.apps) assert.equal(sha(read('dist/apps/'+app.id+'/'+app.version+'/manifest.json')),app.sha256);
});
