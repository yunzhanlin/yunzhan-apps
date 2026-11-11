import fs from'node:fs';
import path from'node:path';
import test from'node:test';
import assert from'node:assert/strict';
import {execFileSync}from'node:child_process';
import {sha256}from'../tools/lib.mjs';
const root=path.resolve(import.meta.dirname,'..');
test('independent PM2 SDK is the exact original signed C69r4 source and retains the C68r3 delivery SDK',()=>{
 const sdk=path.join(root,'candidate/panel-integration-pm2-maintenance'),proof=JSON.parse(fs.readFileSync(path.join(root,'registry/pm2-maintenance-c69r4-core.json'))),index=JSON.parse(fs.readFileSync(path.join(sdk,'source-sha256.json'))),inputs=JSON.parse(fs.readFileSync(path.join(sdk,'release-source-inputs.json')));
 assert.equal(proof.source_inputs_sha256,'9983bbf3986af49b75aba6e06f94a6f43f2e66eb18b2b013895453017cff681e');assert.equal(proof.source_sdk_files,2478);assert.equal(proof.source_overlays,0);assert.equal(proof.all50_commercial,false);
 assert.equal(index.release.frozen_inputs_sha256,proof.source_inputs_sha256);assert.equal(sha256(fs.readFileSync(path.join(sdk,'source-sha256.json'))),proof.source_index_sha256);assert.equal(index.release.archive_sha256,proof.signed_original_archives.amd64.archive_sha256);
 assert.deepEqual(inputs.files,index.files);assert.equal(inputs.frozen_inputs_sha256,proof.source_inputs_sha256);assert.equal(Object.keys(index.files).length,2478);assert.deepEqual(index.test_overrides??{},{});
 for(const [n,h]of Object.entries(index.files)){
  assert(path.posix.normalize(n)===n&&!n.startsWith('/')&&!n.split('/').includes('..'));const file=path.join(sdk,n),st=fs.lstatSync(file);assert(st.isFile()&&!st.isSymbolicLink()&&st.nlink===1&&fs.realpathSync(file)===file);assert.equal(sha256(fs.readFileSync(file)),h,n);
 }
 const native=JSON.parse(fs.readFileSync(path.join(root,'native-client-1.3.3/SOURCE_INPUTS.json')));assert.equal(native.inputs_sha256,proof.native133_inputs_sha256);
 for(const [n,v]of Object.entries(native.files))assert.equal(index.files[n],v.sha256,n);
 assert.equal(execFileSync('git',['rev-parse','HEAD:candidate/panel-integration-load-balance'],{cwd:root,encoding:'utf8'}).trim(),'0754086b782f551323285bd885f1901c93b5391d');
 // Source tree frozen by the published native WebView compatibility repair.
 assert.equal(execFileSync('git',['rev-parse','HEAD:native-client-1.3.3'],{cwd:root,encoding:'utf8'}).trim(),'8f06c25869bb223a41ae8c349f9212a808d0b04a');
});

