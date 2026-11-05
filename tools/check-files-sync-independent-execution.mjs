import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import {fileURLToPath}from 'node:url';
const root=fileURLToPath(new URL('../',import.meta.url));
export const filesSyncIndependentExecution=JSON.parse(fs.readFileSync(root+'tools/files-sync-independent-execution.json'));
function exact(rows,packages){
 assert(rows.length>0&&!rows.some(row=>['skip','fail'].includes(row.Action)),'Missing, skipped or failed execution is not acceptance');
 assert(rows.every(row=>Object.hasOwn(packages,row.Package)),'Foreign package cannot replace selected source');
 for(const[pkg,names]of Object.entries(packages)){
  assert(names.length>0&&new Set(names).size===names.length);
  const selected=rows.filter(row=>row.Package===pkg);assert(selected.every(row=>!row.Test||names.includes(row.Test)));
  for(const action of ['run','pass']){const actual=selected.filter(row=>row.Action===action&&row.Test).map(row=>row.Test);assert.equal(actual.length,names.length);assert.equal(new Set(actual).size,actual.length);assert.deepEqual(actual.sort(),[...names].sort())}
  assert.equal(selected.filter(row=>row.Action==='pass'&&!row.Test).length,1,'Original package completion required');
 }
}
export function verifyFilesSyncIndependentExecution(coreRows,rootRows,sftpRows,identity,architecture){
 assert(['x86_64','aarch64'].includes(architecture));const spec=filesSyncIndependentExecution;
 assert.equal(spec.format,1);assert(/^[a-f0-9]{64}$/.test(spec.source_inputs_sha256));assert.equal(spec.source_sdk_files,2434);
 assert.equal(Object.values(spec.core_packages).reduce((n,cases)=>n+cases.length,0),31);assert.equal(spec.Root_executor_cases.length,8);assert.equal(spec.unprivileged_SFTP_cases.length,72);assert.equal(spec.unprivileged_SFTP_cases.filter(name=>!name.includes('/')).length,61);assert.equal(spec.unprivileged_SFTP_root_cases,61);
 exact(coreRows,spec.core_packages);exact(rootRows,{'local/panel/internal/executor':spec.Root_executor_cases});exact(sftpRows,{'local/panel/internal/executor':spec.unprivileged_SFTP_cases});
 assert(identity&&identity.system==='Linux'&&identity.architecture===architecture&&Number.isSafeInteger(identity.uid)&&identity.uid>0&&identity.euid===identity.uid&&Array.isArray(identity.groups)&&identity.groups.length===0&&typeof identity.status==='string'&&/^[a-f0-9]{64}$/.test(identity.native_sftp_sha256));
 const status=Object.fromEntries(identity.status.split('\n').filter(line=>line.includes(':')).map(line=>[line.split(':')[0],line.slice(line.indexOf(':')+1).trim()]));
 assert(status.NoNewPrivs==='1');for(const key of ['CapInh','CapPrm','CapEff','CapBnd','CapAmb'])assert.equal(status[key],'0000000000000000',key);
 assert(rootRows.some(row=>row.Test==='TestRemoteIndependentRootPrivateCopyNamespace'&&row.Output?.includes('actual_Root_private_uid=0 actual_private_mode=0600 actual_UID33_private_read=EACCES')),'Actual Root/UID33 filesystem control must execute');
 assert(sftpRows.some(row=>row.Test==='TestRemoteIndependentCopyTrueMidReadKillPreservesPartialAndRecovers'&&row.Output?.includes('actual_native_read_partial_bytes=32768 actual_signal=SIGKILL preserved_original_inode=true new_complete_attempt=true')),'Genuine partial-copy child interruption must execute');
 return {ok:true,architecture,source_inputs_sha256:spec.source_inputs_sha256,core_PASS:31,Root_PASS:8,unprivileged_SFTP_PASS:72,unprivileged_SFTP_roots:61,actual_nonroot_UID:identity.uid,all_capability_sets_zero:true,skips:0,normal_installed_or_store_acceptance:false};
}
if(process.argv[1]&&path.resolve(process.argv[1])===fileURLToPath(import.meta.url)){
 assert.equal(process.platform,'linux');assert.equal(process.argv.length,7);const architecture=process.argv[6];assert.equal(architecture,process.arch==='x64'?'x86_64':process.arch==='arm64'?'aarch64':'unsupported');
 const read=(file,maximum)=>{const st=fs.lstatSync(file);assert(st.isFile()&&!st.isSymbolicLink()&&st.size>0&&st.size<=maximum);return fs.readFileSync(file,'utf8')};
 const rows=file=>read(file,16*1024*1024).trim().split('\n').map(line=>JSON.parse(line));const index=JSON.parse(fs.readFileSync(root+'candidate/panel-integration-load-balance/source-sha256.json'));
 assert.equal(index.release.frozen_inputs_sha256,filesSyncIndependentExecution.source_inputs_sha256);assert.equal(Object.keys(index.files).length,filesSyncIndependentExecution.source_sdk_files);assert.deepEqual(index.test_overrides??{},{});
 console.log(JSON.stringify(verifyFilesSyncIndependentExecution(rows(process.argv[2]),rows(process.argv[3]),rows(process.argv[4]),JSON.parse(read(process.argv[5],64*1024)),architecture)));
}
