import assert from'node:assert/strict';
import fs from'node:fs';
import path from'node:path';
import {fileURLToPath}from'node:url';
const root=fileURLToPath(new URL('../',import.meta.url));
export const integrityKernelExecution=JSON.parse(fs.readFileSync(root+'tools/integrity-kernel-execution.json'));
export function verifyIntegrityKernelExecution(coreRows,executorRows,architecture){
 assert(['x86_64','aarch64'].includes(architecture));
 const expected=integrityKernelExecution.packages,all=[...coreRows,...executorRows];
 assert(all.length>0&&!all.some(row=>['skip','fail'].includes(row.Action)),'Kernel source gate cannot skip or fail');
 assert(coreRows.every(row=>['local/panel/internal/core','local/panel/internal/appcatalog'].includes(row.Package)));
 assert(executorRows.every(row=>row.Package==='local/panel/internal/executor'));
 for(const[pkg,names]of Object.entries(expected)){
  const rows=all.filter(row=>row.Package===pkg);
  assert(names.length>0&&new Set(names).size===names.length);
  assert(rows.every(row=>!row.Test||names.includes(row.Test)),'Foreign test cannot replace an original case');
  for(const action of ['run','pass']){
   const observed=rows.filter(row=>row.Action===action&&row.Test).map(row=>row.Test);
   assert.equal(observed.length,names.length,'Missing or duplicate kernel execution');
   assert.equal(new Set(observed).size,names.length);assert.deepEqual([...observed].sort(),[...names].sort());
  }
  assert.equal(rows.filter(row=>row.Action==='pass'&&!row.Test).length,1,'Actual package completion required');
 }
 const evidence=executorRows.filter(row=>row.Output?.includes('actual_uid33_protection='));assert.equal(evidence.length,1);
 const actual=JSON.parse(evidence[0].Output.split('actual_uid33_protection=')[1].trim());
 assert.deepEqual(Object.keys(actual.blocked).sort(),['held-write','truncate','new-open','new-entry','rename','unlink','outside-hardlink'].sort());
 assert(Object.values(actual.blocked).every(errno=>errno===1)&&actual.excluded_write===true,'Actual UID33 write denial and writable exclusion required');
 assert(executorRows.some(row=>row.Output?.includes('actual Root programme queue: active kernel request refused')),'Actual Root upgrade fence must execute');
 return {ok:true,architecture,PASS:Object.fromEntries(Object.entries(expected).map(([pkg,names])=>[pkg,names.length])),skips:0,source_inputs_sha256:integrityKernelExecution.source_inputs_sha256,installed_or_store_acceptance:false};
}
if(process.argv[1]&&path.resolve(process.argv[1])===fileURLToPath(import.meta.url)){
 assert.equal(process.platform,'linux');assert.equal(process.argv.length,5);
 const read=file=>{const s=fs.lstatSync(file);assert(s.isFile()&&!s.isSymbolicLink()&&s.size>0&&s.size<=16*1024*1024);return fs.readFileSync(file,'utf8').trim().split('\n').map(line=>JSON.parse(line))};
 const arch=process.argv[4];assert.equal(arch,process.arch==='x64'?'x86_64':process.arch==='arm64'?'aarch64':'unsupported');
 const index=JSON.parse(fs.readFileSync(root+'candidate/panel-integration-load-balance/source-sha256.json'));
 assert.equal(index.release.frozen_inputs_sha256,integrityKernelExecution.source_inputs_sha256);assert.equal(Object.keys(index.files).length,integrityKernelExecution.source_sdk_files);
 console.log(JSON.stringify(verifyIntegrityKernelExecution(read(process.argv[2]),read(process.argv[3]),arch)));
}
