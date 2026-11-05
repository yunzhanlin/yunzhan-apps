import assert from'node:assert/strict';
import fs from'node:fs';
import path from'node:path';
import {fileURLToPath}from'node:url';
export function verifyEnterpriseKernelPredecessor(rows,ids,era){
 assert(['immediate-C60','legacy-C59'].includes(era));
 const prefix='TestPublishedCandidateRepositoryCurrentSignedManifestABI';
 const refused=era==='immediate-C60'?['enterprise-tamper-proof']:['enterprise-tamper-proof','website-tamper-proof'];
 assert.equal(ids.length,50);assert.equal(new Set(ids).size,50);assert(refused.every(id=>ids.includes(id)));
 assert(rows.length>0&&rows.every(row=>row.Package==='local/panel/internal/appcatalog'));
 assert(!rows.some(row=>row.Action==='skip'));
 assert.deepEqual(rows.filter(row=>row.Action==='fail'&&row.Test).map(row=>row.Test).sort(),[prefix,...refused.map(id=>prefix+'/'+id)].sort());
 assert.deepEqual(rows.filter(row=>row.Action==='pass'&&row.Test).map(row=>row.Test).sort(),ids.filter(id=>!refused.includes(id)).map(id=>prefix+'/'+id).sort());
 assert.deepEqual(rows.filter(row=>row.Action==='run'&&row.Test).map(row=>row.Test).sort(),[prefix,...ids.map(id=>prefix+'/'+id)].sort());
 assert.equal(rows.filter(row=>row.Action==='pass'&&!row.Test).length,0);
 assert.equal(rows.filter(row=>row.Action==='fail'&&!row.Test).length,1);
 assert(rows.some(row=>row.Output?.includes('enterprise-integrity-kernel-ownership-v1')),'Old compiled source must refuse the exact independent enterprise handler');
 if(era==='legacy-C59')assert(rows.some(row=>row.Output?.includes('integrity-kernel-inode-journal-v1')),'The original legacy source must still refuse the website handler');
 return {ok:true,predecessor:era,other_apps_passed:50-refused.length,exact_refused_apps:refused,old_source_unchanged:true,installed_or_store_acceptance:false};
}
if(process.argv[1]&&path.resolve(process.argv[1])===fileURLToPath(import.meta.url)){
 assert.equal(process.platform,'linux');assert.equal(process.argv.length,5);
 const file=process.argv[2];const s=fs.lstatSync(file);assert(s.isFile()&&!s.isSymbolicLink()&&s.size>0&&s.size<4*1024*1024);
 const rows=fs.readFileSync(file,'utf8').trim().split('\n').map(line=>JSON.parse(line));const ids=JSON.parse(fs.readFileSync(process.argv[3])).apps.map(app=>app.id);
 console.log(JSON.stringify(verifyEnterpriseKernelPredecessor(rows,ids,process.argv[4])));
}
