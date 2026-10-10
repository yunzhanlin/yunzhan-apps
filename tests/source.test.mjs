import test from 'node:test';import assert from 'node:assert/strict';
import {readFile,lstat} from 'node:fs/promises';import {createHash} from 'node:crypto';

function assertReleaseSource(index,release){
 assert.deepEqual(index.release,{archive:release.archive,archive_sha256:release.archive_sha256,frozen_inputs_sha256:release.frozen_inputs_sha256});
 const overrides=index.test_overrides??{};
 for(const [name,override] of Object.entries(overrides)){
  assert.match(name,/^(?:cmd|internal)\/.+_test\.go$/,'only Go test fixtures may differ from the frozen release');
  assert.equal(override.release_sha256,release.files[name],name);
  assert.match(override.release_sha256,/^[0-9a-f]{64}$/);
  assert.match(index.files[name],/^[0-9a-f]{64}$/);
  assert.notEqual(index.files[name],override.release_sha256,name);
  assert.equal(typeof override.reason,'string');assert(override.reason.trim().length>0);
 }
 for(const [name,digest] of Object.entries(release.files)){
  if(!Object.hasOwn(overrides,name))assert.equal(index.files[name],digest,name);
 }
}

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
 assert(Object.keys(release.files).length>390);
 assertReleaseSource(index,release);
});
test('fixture overrides cannot unpin production source or lose the original test digest',()=>{
 const runtime='internal/executor/app_sync_remote_linux.go',fixture='internal/executor/app_sync_remote_linux_test.go';
 const original='a'.repeat(64),updated='b'.repeat(64);
 const release={archive:'frozen.tar.gz',archive_sha256:original,frozen_inputs_sha256:original,files:{[runtime]:original,[fixture]:original}};
 const index={release:{archive:release.archive,archive_sha256:original,frozen_inputs_sha256:original},files:{[runtime]:original,[fixture]:updated},test_overrides:{[fixture]:{release_sha256:original,reason:'correct CI fixture'}}};
 assertReleaseSource(index,release);
 assert.throws(()=>assertReleaseSource({...index,files:{...index.files,[runtime]:updated}},release));
 assert.throws(()=>assertReleaseSource({...index,files:{...index.files,[runtime]:updated},test_overrides:{...index.test_overrides,[runtime]:{release_sha256:original,reason:'runtime drift'}}},release));
 assert.throws(()=>assertReleaseSource({...index,test_overrides:{[fixture]:{release_sha256:updated,reason:'wrong original'}}},release));
 assert.throws(()=>assertReleaseSource({...index,test_overrides:{}},release));
 assert.throws(()=>assertReleaseSource({...index,test_overrides:{[fixture]:{release_sha256:original,reason:''}}},release));
});
