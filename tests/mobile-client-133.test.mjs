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
test('historical native-only build qualification retains its original accepted server witness',()=>{
 const proof=JSON.parse(fs.readFileSync(path.join(root,'registry/mobile-native-133-local-build-qualification.json')));
 assert.equal(proof.source_inputs_sha256,index.inputs_sha256);assert.equal(proof.source_files,40);assert.equal(proof.source_overrides,0);assert.equal(proof.all50_commercial,false);assert.equal(proof.actual_native_UI_acceptance,false);
 assert.equal(proof.Swift_actual_host_tests,37);assert.equal(proof.android_actual_host_tests_each,43);assert.equal(proof.android_lint_issues_each,0);
 assert.equal(execFileSync('git',['rev-parse','5f8457971e3ca4868d85c70d3f854d5773f25c8f:candidate/panel-integration-load-balance'],{cwd:root,encoding:'utf8'}).trim(),'c07c9c047359fa6696fa3eb73eef721ec0429ab0');
 for(const name of ['candidate/dist/catalog-v1.json','candidate/signatures/catalog-v1.sig','candidate/signatures/catalog-v1.bundle.json','native-client-1.3.2/SOURCE_INPUTS.json']){const retained=name.startsWith('candidate/')?'registry/reviewed-catalogs/before-mobile-native133-c68r3/'+name.slice('candidate/'.length):name;assert(fs.readFileSync(path.join(root,retained)).equals(execFileSync('git',['show','5f8457971e3ca4868d85c70d3f854d5773f25c8f:'+name],{cwd:root,maxBuffer:16<<20})),name);}
});
test('current server delivery sources bind C68r3 while original132 client and signed catalogue witnesses remain immutable',()=>{
 const proof=JSON.parse(fs.readFileSync(path.join(root,'registry/mobile-native-133-server-source-c68r3-qualification.json')));
 const sdk=path.join(root,'candidate/panel-integration-load-balance'),published=JSON.parse(fs.readFileSync(path.join(sdk,'source-sha256.json'))),inputs=JSON.parse(fs.readFileSync(path.join(sdk,'release-source-inputs.json')));
 assert.equal(proof.source_inputs_sha256,'7ae19475cac7a31941533befe97d6288eabcc6f5b8a0ea9b83e3feadc3e8fdda');assert.equal(proof.source_sdk_files,2467);assert.equal(proof.native133_inputs_sha256,index.inputs_sha256);assert.equal(proof.zero_source_overlays,true);assert.equal(proof.all50_commercial,false);
 assert.equal(sha(fs.readFileSync(path.join(sdk,'source-sha256.json'))),proof.source_index_sha256);assert.equal(published.release.frozen_inputs_sha256,proof.source_inputs_sha256);assert.equal(published.release.archive_sha256,'71fa47af8607e1ea1f123a0d8fae1727bf76238313ec70038c477075f59537da');assert.equal(Object.keys(published.files).length,2467);assert.deepEqual(published.files,inputs.files);assert.equal(inputs.frozen_inputs_sha256,proof.source_inputs_sha256);assert.deepEqual(published.test_overrides??{},{});
 for(const[name,digest]of Object.entries(published.files)){
  assert(path.posix.normalize(name)===name&&!name.startsWith('/')&&!name.split('/').includes('..'));
  const file=path.join(sdk,name),s=fs.lstatSync(file);assert(s.isFile()&&!s.isSymbolicLink()&&s.nlink===1&&fs.realpathSync(file)===file);assert.equal(sha(fs.readFileSync(file)),digest,name);
 }
 for(const[name,record]of Object.entries(index.files))assert.equal(published.files[name],record.sha256,name);
});
