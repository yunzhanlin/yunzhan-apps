import{originalReviewedHTTPSFixtureWorkflow}from'./reviewed-https-fixture-workflow.mjs';
import {preAnalyticsRead} from './previous-analytics-catalog.mjs';
import {preAnalyticsWorkflowRead} from './pre-analytics-workflow.mjs';
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
import {createHash} from 'node:crypto';
const root=fileURLToPath(new URL('..',import.meta.url)),scope='panel-integration-geodata-identity';
const read=p=>preAnalyticsWorkflowRead(p,preAnalyticsRead(p,fs.readFileSync(path.join(root,p)))),sha=b=>createHash('sha256').update(b).digest('hex');
const release=JSON.parse(read('registry/geodata-identity-release.json')),index=JSON.parse(read(scope+'/source-sha256.json'));
test('new identity source exactly binds every normal original-key signed release input without overrides',()=>{
 assert.equal(sha(read(scope+'/source-sha256.json')),'07aa0d8283038ed3de4a38292a2560a5017b1d0be1ed1b626e691069eb3151b2');
 assert.equal(index.release.frozen_inputs_sha256,release.source_inputs_sha256);assert.equal(index.release.archive_sha256,release.normal_archives.amd64);
 assert.equal(index.release.archive,'panel-'+release.program+'-linux-amd64.tar.gz');assert.deepEqual(index.test_overrides,{});
 assert.equal(Object.keys(index.files).length,1462);
 for(const [name,digest]of Object.entries(index.files)){assert.equal(path.posix.normalize(name),name);assert(!path.isAbsolute(name));assert(!name.split('/').some(p=>['..','.git','.local','node_modules'].includes(p)));assert.equal(sha(read(scope+'/'+name)),digest,name)}
 assert.deepEqual(JSON.parse(read(scope+'/release-source-inputs.json')),{...index.release,files:index.files});
});
test('all historical revision bytes stay exact; new history identity and Docker guard are separate source',()=>{
 const raw=read('panel-integration-memcached-revision/source-sha256.json');assert.equal(sha(raw),'72e22bdbdedb6ab525d86497aebca06d982fd51e9508473337209594f2689a65');
 const prior=JSON.parse(raw);for(const [p,digest]of Object.entries(prior.files))assert.equal(sha(read('panel-integration-memcached-revision/'+p)),digest,p);
 assert.deepEqual([...new Set([...Object.keys(prior.files),...Object.keys(index.files)])].filter(p=>prior.files[p]!==index.files[p]).sort(),[
  'internal/core/app_registry_compose_plan_test.go','internal/core/memcached_update_current_test.go','internal/core/memcached_update_producer.go','internal/core/statistics_geodata.go','internal/core/statistics_geodata_request.go','internal/core/statistics_geodata_request_test.go','internal/executor/docker_linux.go','internal/executor/docker_retention_guard_linux.go','internal/executor/docker_retention_guard_linux_test.go','scripts/qa-statistics-geodata-workspace.mjs','scripts/test-memcached-update-identity.mjs','scripts/test-statistics-history.mjs','web/src/App.vue','web/src/AppModuleManager.vue','web/src/DockerManager.vue','web/src/MemcachedAppUpdate.vue','web/src/MemcachedHistory.vue','web/src/StatisticsGeoWorkspace.vue','web/src/statisticsGeoIdentity.ts'
 ]);assert.equal(sha(read('dist/catalog-v1.json')),release.current_original_key_app_catalog_sha256);
});
test('exclusive source publisher verifies original public key before writing and cannot sign or replace history',()=>{
 const tool=read('tools/export-geodata-identity-source.mjs').toString();
 assert(tool.includes("'verify',archive,'--public-key',key"));assert(!tool.includes('--private-key'));assert(tool.indexOf("'verify',archive")<tool.indexOf('fs.mkdirSync(output'));
 for(const value of [release.original_program_public_key_sha256,'fe128e82b4e11345b320cd782134768bfe1a4df14947c425d7494873a7a7b7b5','if(fs.existsSync(output))throw Error','selected.length!==1462','original signed source/input identity differs'])assert(tool.includes(value),value);
 assert.equal(release.source_overrides,0);assert.equal(release.normal_original_key_signatures_verified,true);
});
test('all old workflow bytes remain before new complete Root, races, ABI, locked UI and original-key gates',()=>{
 const workflow=originalReviewedHTTPSFixtureWorkflow(read('.github/workflows/verify.yml')).toString(),marker='      - name: Durable geodata identity and protected Docker complete Root Linux contracts';
 const boundary=workflow.indexOf(marker);assert(boundary>0);assert.equal(sha(Buffer.from(workflow.slice(0,boundary))),release.previous_workflow_sha256);
 for(const phrase of ['panel-integration-geodata-identity','sudo "$(command -v go)" test -p 1 ./... -count=1','go vet ./...','TestPublishedRepositoryCurrentSignedManifestABI','-published-app-registry-root "$GITHUB_WORKSPACE"','test -race ./internal/core ./internal/executor','npm ci --prefix panel-integration-geodata-identity/web --ignore-scripts','test-memcached-update-identity.mjs','test-statistics-history.mjs','qa-statistics-geodata-workspace.mjs','scripts/web-entry-budget.mjs web/dist'])assert(workflow.slice(boundary).includes(phrase),phrase);
});
test('source, synthetic browser, native ABI, dataset, rollback and all50 remain distinct evidence levels',()=>{
 assert.deepEqual(release.source_tests,{passed:2494,failed:0,explicit_environment_skips_NOT_acceptance:11});
 assert.deepEqual(release.native_source_tests_each,{Core:465,Docker_retention:30,failed:0,skipped:0});
 assert.deepEqual(release.actual_original_key_signed50_compiled_ABI_each,{arm64:51,amd64:51,failed:0,skipped:0,application_installs:0});
 assert.equal(release.browser_source_fixture.actual_two_independent_IndexedDB_connections,true);assert.equal(release.browser_source_fixture.lost_reply_reload_second_tab_synthetic_POSTs,1);assert.equal(release.browser_source_fixture.real_panel_or_provider_calls,0);assert.equal(release.browser_source_fixture.NOT_power_loss_acceptance,true);
 for(const name of ['actual_city_dataset_install_proven_in_this_release_record','actual_Memcached_rollback_proven','Main_program_delivered','commercial_all50'])assert.equal(release[name],false,name);
 assert.equal(release.normal_release_eager_JS_bytes,1159781);assert.equal(release.unchanged_eager_JS_limit,1200000);
});
