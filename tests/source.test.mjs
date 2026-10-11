import test from 'node:test';import assert from 'node:assert/strict';
import {readFile,lstat} from 'node:fs/promises';import {createHash} from 'node:crypto';
import path from 'node:path';import {fileURLToPath} from 'node:url';
test('published implementation source matches its review index',async()=>{
 const index=JSON.parse(await readFile(new URL('../panel-integration/source-sha256.json',import.meta.url),'utf8'));
 assert.equal(index.schema_version,1);assert(Object.keys(index.files).length>400);
 for(const [name,digest] of Object.entries(index.files)){
  assert(!name.split('/').includes('..')&&!name.startsWith('/'));
  // systemd escaped mount-unit filenames contain literal backslashes on Linux;
  // URL resolution would interpret them as path separators, unlike the filesystem.
  const file=path.join(fileURLToPath(new URL('../panel-integration/',import.meta.url)),name);assert((await lstat(file)).isFile());
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
