import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
const root=fileURLToPath(new URL('..',import.meta.url));
export const offlineRecoveryExecution=JSON.parse(fs.readFileSync(root+'tools/files-sync-offline-recovery-execution.json','utf8'));
export function validateOfflineRecoveryEvidence(rows,python,architecture,spec=offlineRecoveryExecution){
 assert(['x86_64','aarch64'].includes(architecture));
 assert.equal(spec.format,1);assert.equal(spec.native_PASS,83);assert.equal(spec.native_top_level_tests,14);assert.equal(spec.python_PASS,91);
 const wanted=new Set(spec.native_tests);assert.equal(wanted.size,83);assert.equal([...wanted].filter(n=>!n.includes('/')).length,14);
 assert(Array.isArray(rows)&&rows.length>0&&rows.length<=20000);
 for(const row of rows){assert.equal(row.Package,spec.native_package);assert(!['skip','fail'].includes(row.Action));if(row.Test)assert(wanted.has(row.Test),'foreign native execution');}
 for(const action of ['run','pass']){const actual=rows.filter(r=>r.Action===action&&r.Test).map(r=>r.Test);assert.equal(actual.length,83);assert.equal(new Set(actual).size,83);assert.deepEqual([...new Set(actual)].sort(),[...wanted].sort());}
 assert.equal(rows.filter(r=>r.Action==='pass'&&!r.Test).length,1);
 assert.equal(python.format,1);assert.equal(python.platform,'Linux');assert.equal(python.uid,0);assert.equal(python.architecture,architecture);assert.equal(python.source_inputs_sha256,spec.source_inputs_sha256);assert.equal(python.installed_acceptance,false);assert.equal(python.ok,true);assert.equal(python.actual_tests,91);
 assert.deepEqual(Object.keys(python.groups).sort(),Object.keys(spec.python_groups).sort());
 for(const [name,expected] of Object.entries(spec.python_groups)){const actual=python.groups[name];assert.equal(actual.exit,0);assert.equal(actual.complete,true);assert.equal(actual.tests,expected.tests);assert.equal(actual.methods.length,new Set(actual.methods).size);assert.deepEqual([...actual.methods].sort(),expected.methods);for(const key of ['stdout_sha256','stderr_sha256'])assert.match(actual[key],/^[a-f0-9]{64}$/);}
 return {ok:true,architecture,actual_Root_Go_PASS:83,actual_Go_top_level_PASS:14,actual_Root_Python_PASS:91,skips:0,source_inputs_sha256:spec.source_inputs_sha256,normal_install_or_all50_commercial_acceptance:false};
}
function bounded(file,limit){const s=fs.lstatSync(file);assert(s.isFile()&&!s.isSymbolicLink()&&s.size>0&&s.size<=limit);return fs.readFileSync(file,'utf8');}
if(process.argv[1]&&path.resolve(process.argv[1])===fileURLToPath(import.meta.url)){
 assert.equal(process.argv.length,5);
 const index=JSON.parse(fs.readFileSync(root+'candidate/panel-integration-load-balance/source-sha256.json','utf8'));
 assert.equal(index.release.frozen_inputs_sha256,offlineRecoveryExecution.source_inputs_sha256);assert.equal(Object.keys(index.files).length,2451);assert.deepEqual(index.test_overrides??{},{});
 const rows=bounded(process.argv[2],16<<20).split('\n').filter(Boolean).map(line=>JSON.parse(line));
 console.log(JSON.stringify(validateOfflineRecoveryEvidence(rows,JSON.parse(bounded(process.argv[3],4<<20)),process.argv[4])));
}
