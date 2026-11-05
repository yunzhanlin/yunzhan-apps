import assert from'node:assert/strict';
import fs from'node:fs';
import path from'node:path';
import {fileURLToPath}from'node:url';
export function verifyIntegrityKernelPredecessor(rows,ids){
 const prefix='TestPublishedCandidateRepositoryCurrentSignedManifestABI';
 assert.equal(ids.length,50);assert.equal(new Set(ids).size,50);
 assert(ids.includes('website-tamper-proof'));
 assert(rows.length>0&&rows.every(row=>row.Package==='local/panel/internal/appcatalog'));
 assert(!rows.some(row=>row.Action==='skip'));
 assert.deepEqual(rows.filter(row=>row.Action==='fail'&&row.Test).map(row=>row.Test).sort(),[prefix,prefix+'/website-tamper-proof'].sort());
 assert.deepEqual(rows.filter(row=>row.Action==='pass'&&row.Test).map(row=>row.Test).sort(),ids.filter(id=>id!=='website-tamper-proof').map(id=>prefix+'/'+id).sort());
 assert.deepEqual(rows.filter(row=>row.Action==='run'&&row.Test).map(row=>row.Test).sort(),[prefix,...ids.map(id=>prefix+'/'+id)].sort());
 assert.equal(rows.filter(row=>row.Action==='pass'&&!row.Test).length,0);
 assert.equal(rows.filter(row=>row.Action==='fail'&&!row.Test).length,1);
 assert(rows.some(row=>row.Output?.includes('integrity-kernel-inode-journal-v1')),'The old handler must refuse the exact new kernel feature');
 return {ok:true,other49_passed:49,new_kernel_handler_refused:true,old_source_unchanged:true,installed_or_store_acceptance:false};
}
if(process.argv[1]&&path.resolve(process.argv[1])===fileURLToPath(import.meta.url)){
 assert.equal(process.platform,'linux');assert.equal(process.argv.length,4);
 const file=process.argv[2],catalog=process.argv[3];const s=fs.lstatSync(file);assert(s.isFile()&&!s.isSymbolicLink()&&s.size>0&&s.size<4*1024*1024);
 const rows=fs.readFileSync(file,'utf8').trim().split('\n').map(line=>JSON.parse(line));const ids=JSON.parse(fs.readFileSync(catalog)).apps.map(app=>app.id);
 console.log(JSON.stringify(verifyIntegrityKernelPredecessor(rows,ids)));
}
