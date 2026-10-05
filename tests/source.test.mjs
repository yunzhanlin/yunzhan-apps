import test from 'node:test';import assert from 'node:assert/strict';
import {readFile,lstat} from 'node:fs/promises';import {createHash} from 'node:crypto';
test('published implementation source matches its review index',async()=>{
 const index=JSON.parse(await readFile(new URL('../panel-integration/source-sha256.json',import.meta.url),'utf8'));
 assert.equal(index.schema_version,1);assert(Object.keys(index.files).length>400);
 for(const [name,digest] of Object.entries(index.files)){
  assert(!name.split('/').includes('..')&&!name.startsWith('/'));
  const file=new URL('../panel-integration/'+name,import.meta.url);assert((await lstat(file)).isFile());
  assert.equal(createHash('sha256').update(await readFile(file)).digest('hex'),digest,name);
 }
});
test('published production source is pinned to the verified release snapshot',async()=>{
 const index=JSON.parse(await readFile(new URL('../panel-integration/source-sha256.json',import.meta.url),'utf8'));
 const release=JSON.parse(await readFile(new URL('../panel-integration/release-source-inputs.json',import.meta.url),'utf8'));
 assert.deepEqual(index.release,{archive:release.archive,archive_sha256:release.archive_sha256,frozen_inputs_sha256:release.frozen_inputs_sha256});
 assert(Object.keys(release.files).length>390);
 for(const [name,digest] of Object.entries(release.files))assert.equal(index.files[name],digest,name);
});
test('all 50 published apps have explicit functional acceptance evidence',async()=>{
 const report=JSON.parse(await readFile(new URL('../docs/acceptance-50.json',import.meta.url),'utf8'));
 assert.equal(report.passed,50);assert.equal(report.total,50);assert.equal(report.apps.length,50);
 for(const app of report.apps){assert.equal(app.passed,true,app.id);assert(app.evidence.length>10,app.id)}
});
test('final delivery evidence matches the signed release snapshot',async()=>{
 const report=JSON.parse(await readFile(new URL('../docs/acceptance-50.json',import.meta.url),'utf8'));
 const index=JSON.parse(await readFile(new URL('../panel-integration/source-sha256.json',import.meta.url),'utf8'));
 const delivery=report.delivery;assert(delivery);
 assert.equal(delivery.real_github_package_hashes,50);assert.equal(delivery.signed_native_installs,9);
 assert.equal(delivery.signed_module_installs,23);assert.equal(delivery.signed_isolated_installs,18);
 assert.equal(delivery.browser_checks,25);assert.equal(delivery.mobile_overflow,0);
 assert.equal(delivery.whole_vm_reboot,true);assert.equal(delivery.managed_sigterm,true);
 assert.equal(delivery.release_sha256,index.release.archive_sha256);
 assert.equal(delivery.frozen_inputs_sha256,index.release.frozen_inputs_sha256);
 assert.equal(delivery.elasticsearch_qa_cpu_affinity,'0');assert.equal(delivery.elasticsearch_final_restart_count,0);
 assert(report.limitations.some(value=>value.includes('multicore')));
});
