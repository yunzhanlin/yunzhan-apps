import fs from 'node:fs';
import path from 'node:path';
import test from 'node:test';
import assert from 'node:assert/strict';
import {execFileSync} from 'node:child_process';
import {sha256} from '../tools/lib.mjs';
const root=path.resolve(import.meta.dirname,'..');

test('C70 PM2 SDK binds the exact original signed programme inputs and keeps earlier SDK and native mobile bytes',()=>{
 const sdk=path.join(root,'candidate/panel-integration-pm2-root-vendor');
 const proof=JSON.parse(fs.readFileSync(path.join(root,'registry/pm2-root-vendor-c70-core.json')));
 const indexRaw=fs.readFileSync(path.join(sdk,'source-sha256.json')),index=JSON.parse(indexRaw);
 const release=JSON.parse(fs.readFileSync(path.join(sdk,'release-source-inputs.json')));
 assert.equal(proof.source_inputs_sha256,'44683a15e9b23357ebe34aea11970f6fa90069ef99621d5780aa3749f7d05907');
 assert.equal(proof.source_sdk_files,2489);assert.equal(proof.frozen_inputs,18192);assert.equal(proof.source_overlays,0);
 assert.equal(index.release.frozen_inputs_sha256,proof.source_inputs_sha256);
 assert.equal(sha256(indexRaw),proof.source_index_sha256);
 assert.equal(index.release.archive_sha256,proof.signed_original_archives.amd64.archive_sha256);
 assert.deepEqual(release.files,index.files);assert.equal(release.frozen_inputs_sha256,proof.source_inputs_sha256);
 assert.equal(Object.keys(index.files).length,2489);assert.deepEqual(index.test_overrides??{},{});
 for(const [n,h]of Object.entries(index.files)){
  assert(path.posix.normalize(n)===n&&!n.startsWith('/')&&!n.split('/').includes('..'));
  const f=path.join(sdk,n),st=fs.lstatSync(f);assert(st.isFile()&&!st.isSymbolicLink()&&st.nlink===1&&fs.realpathSync(f)===f);
  assert.equal(sha256(fs.readFileSync(f)),h,n);
 }
 const native=JSON.parse(fs.readFileSync(path.join(root,'native-client-1.3.3/SOURCE_INPUTS.json')));
 assert.equal(native.inputs_sha256,proof.native133_inputs_sha256);assert.equal(Object.keys(native.files).length,40);
 for(const[n,v]of Object.entries(native.files))assert.equal(index.files[n],v.sha256,n);
 const git=(ref)=>execFileSync('git',['rev-parse',ref],{cwd:root,encoding:'utf8'}).trim();
 assert.equal(git('HEAD:candidate/panel-integration-pm2-maintenance'),'8af2e959b6a7a63c3102bb6519161dc949e016aa');
 assert.equal(git('HEAD:candidate/panel-integration-load-balance'),'0754086b782f551323285bd885f1901c93b5391d');
 assert.equal(proof.all50_commercial,false);
});
