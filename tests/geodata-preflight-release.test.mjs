import {preAnalyticsRead} from './previous-analytics-catalog.mjs';
import {preAnalyticsWorkflowRead} from './pre-analytics-workflow.mjs';
import test from 'node:test';import assert from 'node:assert/strict';import fs from 'node:fs';import path from 'node:path';import {fileURLToPath} from 'node:url';import {createHash} from 'node:crypto';
const root=fileURLToPath(new URL('..',import.meta.url)),read=p=>preAnalyticsWorkflowRead(p,preAnalyticsRead(p,fs.readFileSync(path.join(root,p)))),sha=b=>createHash('sha256').update(b).digest('hex'),json=p=>JSON.parse(read(p));
const release=json('registry/geodata-preflight-release.json'),scope='panel-integration-geodata-preflight';
test('four immutable original-key verified cohorts retain every source byte without fixture overrides',()=>{
 const expected={firstuse:'0f92ce9a55b78e128b8f5fb13916239b96a6dd1691f99c885b7c69f2e665ce46',ranges:'bb72ec40d4e1c4b32cad5f963fe24eb1f6aba6546a9334db73c32954b8aab26c',terminal:'23b54d643b3c720c524d1892fa2feda2972e3d0b66a149550e33d88c3f6c6fc4',preflight:'d733416fab89e4ce6151c9b7052b3ffdfb4a7aa12845a644b0c9241d22d77f72'};
 assert.deepEqual(Object.keys(release.immutable_scopes),Object.keys(expected));
 for(const [name,digest] of Object.entries(expected)){
  const prefix='panel-integration-geodata-'+name,index=json(prefix+'/source-sha256.json'),meta=release.immutable_scopes[name];
  assert.equal(sha(read(prefix+'/source-sha256.json')),digest);assert.equal(meta.index_sha256,digest);assert.equal(Object.keys(index.files).length,meta.files);assert.deepEqual(index.test_overrides,{});
  const {index_sha256,files,...archive}=meta;assert.deepEqual(index.release,archive);assert.deepEqual(json(prefix+'/release-source-inputs.json'),{...archive,files:index.files});
  for(const [p,h] of Object.entries(index.files)){assert.equal(path.posix.normalize(p),p);assert(!path.isAbsolute(p));assert(!p.split('/').some(x=>['..','.git','.local','node_modules'].includes(x)));assert(fs.lstatSync(path.join(root,prefix,p)).isFile());assert.equal(sha(read(prefix+'/'+p)),h,p);}
 }
 assert.equal(release.source_files,17113);assert.equal(release.exported_source_files,1470);assert.equal(release.source_overrides,0);assert(release.normal_original_key_signatures_verified);
 assert.equal(release.source_inputs_sha256,release.immutable_scopes.preflight.frozen_inputs_sha256);assert.equal(release.normal_archives.amd64,release.immutable_scopes.preflight.archive_sha256);
});
test('newest cohort changes only native verifier inventory and its actual-command regression',()=>{
 const old=json('panel-integration-geodata-terminal/source-sha256.json'),current=json(scope+'/source-sha256.json');
 assert.deepEqual([...new Set([...Object.keys(old.files),...Object.keys(current.files)])].filter(p=>old.files[p]!==current.files[p]).sort(),['internal/executor/program_upgrade_queues_linux.go','internal/executor/program_upgrade_queues_linux_test.go']);
 const code=read(scope+'/internal/executor/program_upgrade_queues_linux.go').toString(),fixture=read(scope+'/internal/executor/program_upgrade_queues_linux_test.go').toString();
 assert(code.includes('args = append(args, statisticsGeoVerifyPrefix+"*.service")'));assert(fixture.includes('TestProgramUpgradeQueuesActualInventoryIncludesGeoVerifierWorkers'));
 assert.equal(sha(read('dist/catalog-v1.json')),release.current_original_key_app_catalog_sha256);
});
test('failed install admission retains original dual authority and never resets or repairs state',()=>{
 const native=read(scope+'/internal/executor/program_upgrade_geodata_failed_linux.go').toString(),core=read(scope+'/internal/core/statistics_geodata_upgrade.go').toString();
 for(const p of ['"MainPID": "0"','"ControlPID": "0"','"Result": "exit-code"','"ExecMainStatus": "1"','"KillMode": "control-group"','unix.LOCK_SH|unix.LOCK_NB','p.trust.VerifyGeoDataEnvelope','request.Selection.Action != "install"','!statisticsGeoJobSameFiles(files, finalFiles)','p.jobs.openJob(id)'])assert(native.includes(p),p);
 assert.equal((native.match(/p.validate\(ctx, result\)/g)||[]).length,2);
 for(const p of ['ReadOnly: true',"kind='statistics_geodata'","action='statistics.geodata.queue'","action='statistics.geodata.dispatch'",'digest != Hash(payload)','state != result.State','detail != result.Error'])assert(core.includes(p),p);
 for(const p of ['os.WriteFile(', 'os.Remove(', 'os.Mkdir(', '"reset-failed"','"restart"','"stop"'])assert(!native.includes(p),p);
});
test('evidence read shares only existing instance lease and still holds original exclusive job lease',()=>{
 const code=read(scope+'/internal/executor/app_statistics_geodata_export_linux.go').toString();assert(code.includes('statisticsGeoInstanceLeaseOpen(path, false, false)'));assert(code.includes('unix.LOCK_EX|unix.LOCK_NB'));assert(code.includes('!geoStoreStableInfo(li, visible)'));
 const fixture=read(scope+'/internal/executor/app_statistics_geodata_export_lease_linux_test.go').toString();assert(fixture.includes('func Test'));assert(!code.includes('os.WriteFile('));assert(!code.includes('os.Remove('));
});
test('new complete Root race ABI and locked frontend gates append without altering historical checks',()=>{
 const workflow=read('.github/workflows/verify.yml').toString(),marker='      - name: Original failed geodata terminal and verifier inventory complete Root Linux contracts',boundary=workflow.indexOf(marker);assert(boundary>0);assert.equal(sha(Buffer.from(workflow.slice(0,boundary))),release.previous_workflow_sha256);
 for(const phrase of [scope,'sudo "$(command -v go)" test -p 1 ./... -count=1','go vet ./...','TestPublishedRepositoryCurrentSignedManifestABI','-published-app-registry-root "$GITHUB_WORKSPACE"','test -race ./internal/core ./internal/executor','npm ci --prefix '+scope+'/web --ignore-scripts','scripts/test-job-presentation.mjs','scripts/web-entry-budget.mjs web/dist','scripts/qa-statistics-geodata-workspace.mjs'])assert(workflow.slice(boundary).includes(phrase),phrase);
});
test('actual normal program upgrades preserve 99 projections but are not application install acceptance',()=>{
 for(const [arch,proof] of Object.entries(release.normal_program_upgrades)){assert(['arm64','amd64'].includes(arch));assert(proof.accepted);assert.equal(proof.original_business_projections_preserved,99);assert(proof.protected_entries_preserved>3000);assert(proof.original_statistics_history_preserved&&proof.original_geodata_files_preserved);assert.equal(proof.application_operations,0);assert.match(proof.proof_sha256,/^[a-f0-9]{64}$/);assert.match(proof.transaction_sha256,/^[a-f0-9]{64}$/);}
 assert.deepEqual(release.source_tests,{passed:2552,failed:0,explicit_environment_skips_NOT_acceptance:11});assert.deepEqual(release.native_source_tests_each,{Core:494,terminal_export_and_upgrade:36,failed:0,skipped:0});assert.deepEqual(release.Core_race,{passed:494,failed:0,skipped:0});
 assert.deepEqual(release.actual_original_key_signed50_compiled_ABI_each,{arm64:51,amd64:51,failed:0,skipped:0,application_installs:0});assert.equal(release.normal_release_eager_JS_bytes,1160848);assert.equal(release.unchanged_eager_JS_limit,1200000);
});
test('real city install export bytes failures and unproven commercial requirements remain distinct',()=>{
 assert(release.separate_original_AMD_city_install.accepted);assert(release.separate_original_AMD_city_install.full_data_and_tree_verified);assert.equal(release.separate_original_AMD_city_install.offline_IP_probes,5);
 const exported=release.separate_original_ARM_failed_job_export;assert(exported.accepted_readonly_bytes_and_UI&&exported.all99_preserved&&exported.original_failure_retained&&exported.no_native_job_dispatch);assert.equal(exported.bytes,102195);assert.equal(exported.browser_saved_file_proven,false);
 for(const failed of Object.values(release.preserved_failures))assert.equal(failed.accepted,false);assert.equal(release.preserved_failures.ARM_original_city_install.partial_bytes,55451630);assert(release.preserved_failures.AMD_prior_terminal_program_install.temporal_cause_NOT_established);
 for(const name of ['commercial_all50','Main_program_delivered','actual_Memcached_rollback_proven','browser_saved_evidence_file_proven','physical_device_or_power_loss_proven'])assert.equal(release[name],false,name);
});
