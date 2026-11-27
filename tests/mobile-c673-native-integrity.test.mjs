import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import {createHash} from 'node:crypto';
import {execFileSync} from 'node:child_process';
import test from 'node:test';
const root=path.resolve(import.meta.dirname,'..'),scope=path.join(root,'native-client-1.3.3');
const sha=b=>createHash('sha256').update(b).digest('hex');
const index=JSON.parse(fs.readFileSync(path.join(scope,'SOURCE_INPUTS.json')));
test('native133 has its complete immutable independent source with zero overlays',()=>{
 assert.equal(index.format,1);assert.equal(index.version,'1.3.3');assert.equal(index.inputs_sha256,'895c674a1c3475f934df1b2289fa3b01e613b16c5cad46f60f8bdc36739e680e');assert.equal(sha(JSON.stringify(index.files)),index.inputs_sha256);assert.equal(Object.keys(index.files).length,40);assert.deepEqual(index.source_overlays,{});
 for(const[name,record]of Object.entries(index.files)){
  assert(name.startsWith('mobile/')&&path.posix.normalize(name)===name&&!name.split('/').some(v=>['..','.local','.build','.gradle','build','local.properties'].includes(v)));
  const file=path.join(scope,name),s=fs.lstatSync(file),bytes=fs.readFileSync(file);assert(s.isFile()&&!s.isSymbolicLink()&&s.nlink===1&&fs.realpathSync(file)===file);assert.equal(s.mode&0o777,record.mode);assert.equal(bytes.length,record.bytes);assert.equal(sha(bytes),record.sha256,name);
 }
 const published=JSON.parse(fs.readFileSync(path.join(scope,'source-sha256.json')));assert.equal(published.source_inputs_sha256,index.inputs_sha256);assert.deepEqual(published.files,index.files);assert.deepEqual(published.test_overrides,{});
});
