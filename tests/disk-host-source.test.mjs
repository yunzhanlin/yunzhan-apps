import{originalReviewedHTTPSFixtureWorkflow}from'./reviewed-https-fixture-workflow.mjs';
import test from 'node:test';
import assert from 'node:assert/strict';
import {catalogBeforeDisk140Bytes} from './previous-disk-host-catalog.mjs';
import {readFile,lstat} from 'node:fs/promises';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
import {sha256} from '../tools/lib.mjs';
const root=fileURLToPath(new URL('../',import.meta.url));
// Escaped systemd unit names contain literal backslashes. A URL constructor
// would normalize them into separators and inspect a different file.
const read=p=>readFile(path.join(root,p));
test('independent host candidate source is exactly bound to the new normal signed program, not historical geography inputs',async()=>{
 const r=JSON.parse(await read('registry/disk-host-candidate-release.json'));
 const i=JSON.parse(await read(r.source_export+'/source-sha256.json')),f=JSON.parse(await read(r.source_export+'/release-source-inputs.json'));
 assert.equal(r.program,'0.1.0-dev.proapps24diskhostbfns');assert.equal(r.source_inputs_sha256,'f887a29c68b85bbf31150fa204503ecad2d291bb0e2203e752307e5a36eaac32');assert.equal(r.frozen_files,17030);
 assert.equal(r.source_export,'panel-integration-disk');assert.deepEqual(i.test_overrides??{},{});assert.equal(r.source_overrides,0);
 assert.equal(Object.keys(i.files).length,1374);assert.equal(Object.keys(f.files).length,1333);
 assert.equal(i.release.frozen_inputs_sha256,r.source_inputs_sha256);assert.equal(f.frozen_inputs_sha256,r.source_inputs_sha256);
 assert.equal(i.release.archive,'panel-'+r.program+'-linux-amd64.tar.gz');assert.equal(i.release.archive_sha256,r.normal_original_key_archives.amd64);assert.equal(f.archive_sha256,r.normal_original_key_archives.amd64);
 for(const [p,digest]of Object.entries(i.files)){
  assert(!path.isAbsolute(p)&&path.posix.normalize(p)===p&&!p.split('/').some(v=>['..','.local','.git','node_modules'].includes(v)),p);
  const info=await lstat(path.join(root,r.source_export,p));assert(info.isFile()&&!info.isSymbolicLink()&&info.size<=2*1024*1024,p);
  assert.equal(sha256(await read(r.source_export+'/'+p)),digest,p);
  if(p in f.files)assert.equal(digest,f.files[p],p);
 }
 for(const p of ['internal/appcatalog/disk_host_features_test.go','internal/core/disk_host_http.go','internal/core/disk_host_request_http_test.go','internal/core/disk_host_recovery_http.go','internal/diskjob/closure_linux.go','internal/executor/app_disk_host_producer_linux.go','web/src/HostDiskWorkspace.vue','web/src/hostDisk.ts','scripts/test-host-disk.mjs','scripts/host-disk-fixture.mjs'])assert.equal(i.files[p],f.files[p],p);
 assert.equal(r.normal_build_both_arches_passed,true);assert.equal(r.original_key_signature_both_arches_verified,true);
});
test('candidate delivery never rewrites stable signatures, installed receipts or all50 claims',async()=>{
 const r=JSON.parse(await read('registry/disk-host-candidate-release.json'));
 assert.equal(sha256(await catalogBeforeDisk140Bytes()),r.published_catalog_sha256_unchanged);
 assert.equal(sha256(await read('dist/apps/disk-analysis/1.3.0/manifest.json')),r.published_disk_manifest_sha256_unchanged);
 for(const k of ['new_program_deployed','new_app_manifest_published','new_signed_app_installed','new_full_host_job_accepted','main_delivered','main_absent_disk_app_installed','commercial_all50'])assert.equal(r[k],false,k);
 assert.equal(r.candidate_stage,'integration');assert(r.scope.includes('No signed installed1.4'));
 assert(r.remaining.some(s=>s.includes('Genuine signed1.4')));assert(r.remaining.some(s=>s.includes('all other50')));
 const workflow=(originalReviewedHTTPSFixtureWorkflow(await read('.github/workflows/verify.yml'))).toString();assert(workflow.includes('working-directory: panel-integration-disk'));assert(workflow.includes('panel-integration-disk/scripts/qa-host-disk-workspace.mjs'));
 const historical=JSON.parse(await read('panel-integration-geography/source-sha256.json'));assert.equal(historical.release.frozen_inputs_sha256,'87c6326b2a711ab4d1d9b83db6342c341ce9cfe75369d6d8f536fb680406fa2e');
});
