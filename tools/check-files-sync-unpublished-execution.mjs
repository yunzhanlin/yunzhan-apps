import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import {fileURLToPath}from 'node:url';
const root=fileURLToPath(new URL('../',import.meta.url));
export const unpublishedExecution=JSON.parse(fs.readFileSync(root+'tools/files-sync-unpublished-execution.json'));
function exactEvents(rows,packages){
 assert(Array.isArray(rows)&&rows.length>0&&rows.length<=20000);
 const expected=Object.entries(packages).flatMap(([Package,names])=>names.map(Test=>Package+'\0'+Test));
 assert.equal(expected.length,new Set(expected).size);
 assert(rows.every(r=>r&&Object.hasOwn(packages,r.Package)&&!['skip','fail'].includes(r.Action)&&(!r.Test||expected.includes(r.Package+'\0'+r.Test))));
 for(const action of ['run','pass']){const actual=rows.filter(r=>r.Action===action&&r.Test).map(r=>r.Package+'\0'+r.Test);assert.equal(actual.length,new Set(actual).size);assert.deepEqual(actual.sort(),[...expected].sort())}
 for(const Package of Object.keys(packages))assert.equal(rows.filter(r=>r.Package===Package&&r.Action==='pass'&&!r.Test).length,1);
 return expected.length;
}
export function verifyUnpublishedExecution(core,executor,tap,architecture){
 assert(['x86_64','aarch64'].includes(architecture));const s=unpublishedExecution;
 const coreCount=exactEvents(core,s.core_packages),rootCount=exactEvents(executor,{'local/panel/internal/executor':s.Root_executor_cases});
 assert.equal(coreCount,26);assert.equal(rootCount,25);assert.equal(s.Root_executor_cases.filter(n=>!n.includes('/')).length,9);
 assert(executor.some(r=>r.Test==='TestRemoteUnpublishedCopyAtFullContentBudgetRetainsMetadataAndCountsTombstone'&&r.Output?.includes('original_regular_records=127 logical_content_bytes=1073741824 retained_unpublished_namespaces=1 total_namespaces=128')&&r.Output.includes('full_content_claim=false')),'The actual sparse metadata capacity witness must remain explicitly distinct from a full1GiB transfer');
 const names=[...tap.matchAll(/^ok \d+ - (.+)$/gm)].map(m=>m[1]);assert.equal(names.length,29);assert.deepEqual(names,s.Node_test_names);
 for(const pattern of [/^# tests 29$/m,/^# pass 29$/m,/^# fail 0$/m,/^# cancelled 0$/m,/^# skipped 0$/m,/^# todo 0$/m])assert(pattern.test(tap));
 assert(!/^not ok|# SKIP|# TODO/m.test(tap));assert.equal(names.filter(n=>n.startsWith('actual Vue')).length,7);
 return {ok:true,architecture,actual_Core_and_ABI_PASS:coreCount,actual_Root_PASS:rootCount,actual_Node_PASS:29,actual_Vue_cases:7,skips:0,not_installed_or_powercut_acceptance:true};
}
if(process.argv[1]&&path.resolve(process.argv[1])===fileURLToPath(import.meta.url)){
 assert.equal(process.platform,'linux');assert.equal(process.argv.length,6);
 const read=n=>{const st=fs.lstatSync(n);assert(st.isFile()&&!st.isSymbolicLink()&&st.size>0&&st.size<=4*1024*1024);return fs.readFileSync(n,'utf8')};
 const index=JSON.parse(fs.readFileSync(root+'candidate/panel-integration-load-balance/source-sha256.json'));assert.equal(index.release.frozen_inputs_sha256,unpublishedExecution.source_inputs_sha256);assert.equal(Object.keys(index.files).length,2443);assert.deepEqual(index.test_overrides??{},{});
 const rows=n=>read(n).trim().split('\n').map(line=>JSON.parse(line));
 console.log(JSON.stringify({...verifyUnpublishedExecution(rows(process.argv[2]),rows(process.argv[3]),read(process.argv[4]),process.argv[5]),source_inputs_sha256:unpublishedExecution.source_inputs_sha256}));
}
