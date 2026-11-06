import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import {fileURLToPath}from 'node:url';
const root=fileURLToPath(new URL('../',import.meta.url));
export const queryRoot='TestAnalyticsQueryRequiresExactFiveHandlersAndRetainsOriginalABI';
export const queryScenarios=['missing','duplicate','foreign-feature','previous-version','future-version','alias','build','leading-zero','foreign-app','provider','target','route'];
export function verifyAnalyticsQueryExecution(rows,tap,architecture){
 assert(['x86_64','aarch64'].includes(architecture));
 const expected=[queryRoot,...queryScenarios.map(n=>queryRoot+'/'+n)];
 assert(rows.length>0&&rows.every(row=>row.Package==='local/panel/internal/appcatalog')&&!rows.some(row=>['skip','fail'].includes(row.Action)));
 assert(rows.every(row=>!row.Test||expected.includes(row.Test)));
 for(const action of ['run','pass']){
  const actual=rows.filter(row=>row.Action===action&&row.Test).map(row=>row.Test);
  assert.equal(actual.length,new Set(actual).size);assert.deepEqual(actual.sort(),[...expected].sort());
 }
 assert.equal(rows.filter(row=>row.Action==='pass'&&!row.Test).length,1);
 const names=JSON.parse(fs.readFileSync(root+'tools/analytics-query-execution.json')).Node_test_names;
 const executed=[...tap.matchAll(/^ok \d+ - (.+)$/gm)].map(m=>m[1]);
 assert.equal(names.length,12);assert.equal(names.filter(name=>name.startsWith('actual Vue ')).length,8);
 assert.equal(executed.length,12);assert.deepEqual(executed,names);
 for(const pattern of [/^# tests 12$/m,/^# pass 12$/m,/^# fail 0$/m,/^# cancelled 0$/m,/^# skipped 0$/m,/^# todo 0$/m])assert(pattern.test(tap));
 assert(!/^not ok|# SKIP|# TODO/m.test(tap));
 return {ok:true,architecture,actual_Go_PASS:13,actual_Node_PASS:12,actual_Vue_component_cases:8,skips:0,not_installed_acceptance:true};
}
if(process.argv[1]&&path.resolve(process.argv[1])===fileURLToPath(import.meta.url)){
 assert.equal(process.platform,'linux');assert.equal(process.argv.length,5);
 const read=n=>{const st=fs.lstatSync(n);assert(st.isFile()&&!st.isSymbolicLink()&&st.size>0&&st.size<4*1024*1024);return fs.readFileSync(n,'utf8');};
 const spec=JSON.parse(fs.readFileSync(root+'tools/analytics-query-execution.json')),index=JSON.parse(fs.readFileSync(root+'candidate/panel-integration-load-balance/source-sha256.json'));
 assert.equal(index.release.frozen_inputs_sha256,spec.source_inputs_sha256);assert.equal(Object.keys(index.files).length,spec.source_sdk_files);assert.deepEqual(index.test_overrides??{},{});
 console.log(JSON.stringify({...verifyAnalyticsQueryExecution(read(process.argv[2]).trim().split('\n').map(line=>JSON.parse(line)),read(process.argv[3]),process.argv[4]),source_inputs_sha256:spec.source_inputs_sha256}));
}
