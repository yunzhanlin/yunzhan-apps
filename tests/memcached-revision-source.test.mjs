import {preAnalyticsRead} from './previous-analytics-catalog.mjs';
import {preAnalyticsWorkflowRead} from './pre-analytics-workflow.mjs';
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
import {createHash} from 'node:crypto';
const root=fileURLToPath(new URL('..',import.meta.url));
const sha=b=>createHash('sha256').update(b).digest('hex');
const read=p=>preAnalyticsWorkflowRead(p,preAnalyticsRead(p,fs.readFileSync(path.join(root,p))));
const release=JSON.parse(read('registry/memcached-revision-release.json'));
const scope='panel-integration-memcached-revision';
const index=JSON.parse(read(scope+'/source-sha256.json'));
test('new revision scope binds every byte to the normal original-key verified release, without source overrides',()=>{
 assert.equal(sha(read(scope+'/source-sha256.json')),'72e22bdbdedb6ab525d86497aebca06d982fd51e9508473337209594f2689a65');
 assert.equal(index.release.frozen_inputs_sha256,release.source_inputs_sha256);
 assert.equal(index.release.archive_sha256,release.normal_archives.amd64);
 assert.equal(index.release.archive,'panel-'+release.program+'-linux-amd64.tar.gz');
 assert.deepEqual(index.test_overrides,{});assert.equal(Object.keys(index.files).length,1455);
 for(const [name,digest] of Object.entries(index.files)){
  assert.equal(path.posix.normalize(name),name);assert(!path.isAbsolute(name));assert(!name.split('/').some(x=>['..','.git','.local','node_modules'].includes(x)));
  assert.equal(sha(read(scope+'/'+name)),digest,name);
 }
 assert.deepEqual(JSON.parse(read(scope+'/release-source-inputs.json')),{...index.release,files:index.files});
});
test('historical source stays exact; only the eleven reviewed close and revision members differ',()=>{
 const raw=read('panel-integration-memcached-update/source-sha256.json');assert.equal(sha(raw),'467f5766f15dce0fb54fe5597acd3d411aecff4840ca1f8a7ee3c9d041aad494');
 const previous=JSON.parse(raw);for(const [name,digest] of Object.entries(previous.files))assert.equal(sha(read('panel-integration-memcached-update/'+name)),digest,name);
 assert.deepEqual([...new Set([...Object.keys(previous.files),...Object.keys(index.files)])].filter(p=>previous.files[p]!==index.files[p]).sort(),[
  'internal/core/app_registry.go','internal/core/app_registry_memcached_revision_test.go','internal/core/memcached_update_close.go','internal/core/memcached_update_close_test.go','internal/core/memcached_update_producer.go','internal/core/memcached_update_status.go','internal/core/memcached_update_store.go','scripts/test-memcached-update-identity.mjs','web/src/App.vue','web/src/MemcachedAppUpdate.vue','web/src/memcachedUpdateIdentity.ts'
 ]);
 assert.equal(sha(read('dist/catalog-v1.json')),release.current_original_key_app_catalog_sha256);
});
test('publisher verifies the original public program key before any exclusive new source write',()=>{
 const source=read('tools/export-memcached-revision-source.mjs').toString();
 assert(source.includes("'verify',archive,'--public-key',key"));assert(!source.includes('--private-key'));
 assert(source.indexOf("'verify',archive")<source.indexOf('fs.mkdirSync(output'));
 for(const phrase of ['4ccfcc861d56a41e3ba7f7ace7e2432c815f366c58448d783df92c6632f01339','fe128e82b4e11345b320cd782134768bfe1a4df14947c425d7494873a7a7b7b5','if(fs.existsSync(output))throw Error','selected.length!==1455','original signed source/input identity differs'])assert(source.includes(phrase),phrase);
 assert.equal(release.source_overrides,0);assert.equal(release.normal_original_key_signatures_verified,true);
});
test('all prior mandatory workflow bytes survive before the new complete Root and management gates',()=>{
 const source=read('.github/workflows/verify.yml').toString(),marker='      - name: Exact legacy Memcached package revision complete Root Linux contracts';
 const boundary=source.indexOf(marker);assert(boundary>0);assert.equal(sha(Buffer.from(source.slice(0,boundary))),release.previous_workflow_sha256);
 const appended=source.slice(boundary);
 for(const phrase of ['panel-integration-memcached-revision','sudo "$(command -v go)" test -p 1 ./... -count=1','go vet ./...','TestPublishedRepositoryCurrentSignedManifestABI','-published-app-registry-root "$GITHUB_WORKSPACE"','test -race ./internal/core ./internal/executor','npm ci --prefix panel-integration-memcached-revision/web --ignore-scripts','test-memcached-update-identity.mjs','scripts/web-entry-budget.mjs web/dist'])assert(appended.includes(phrase),phrase);
});
test('source, installed API, store preview and real native update remain distinct evidence boundaries',()=>{
 assert.equal(release.source_tests.passed,2470);assert.equal(release.source_tests.explicit_environment_skips_NOT_acceptance,11);
 assert.deepEqual(release.native_source_tests_each,{arm64:347,amd64:347,failed:0,skipped:0});
 assert.deepEqual(release.actual_original_key_signed50_compiled_ABI_each,{arm64:51,amd64:51,failed:0,skipped:0,application_installs:0});
 assert.equal(release.normal_QA_program_upgrade.original_business_projections_preserved_each,99);
 assert.equal(release.normal_QA_program_upgrade.application_updates_installs_uninstalls,0);
 assert.equal(release.installed_close_protocol.new_Core_or_native_update_jobs_or_receipts,0);
 assert.equal(release.actual_store_revision_indicator.update_button_and_new_version_visible,true);
 assert.equal(release.actual_store_revision_indicator.maintenance_update_submitted_in_this_evidence,false);
 assert.equal(release.actual_signed_Memcached_update_apply_or_rollback_proven,false);
 assert.equal(release.Main_program_delivered,false);assert.equal(release.commercial_all50,false);
 assert.equal(release.normal_release_eager_JS_bytes,1159198);assert.equal(release.unchanged_eager_JS_limit,1200000);
});
