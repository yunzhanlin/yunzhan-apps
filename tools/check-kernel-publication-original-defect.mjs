import assert from'node:assert/strict';
import fs from'node:fs';
import path from'node:path';
import{fileURLToPath}from'node:url';
const root=fileURLToPath(new URL('../',import.meta.url));
export const publicationOriginalDefect=JSON.parse(fs.readFileSync(root+'tools/kernel-publication-original-defect.json'));
export function verifyPublicationOriginalDefect(rows,architecture){
 assert(['x86_64','aarch64'].includes(architecture));
 const contract=publicationOriginalDefect,names=contract.expected_failed_tests,leaves=contract.expected_http409_tests;
 assert.equal(names.length,31);assert.equal(new Set(names).size,31);assert.equal(leaves.length,28);assert.equal(new Set(leaves).size,28);assert(leaves.every(n=>names.includes(n)));
 assert(rows.length>0&&rows.every(r=>r.Package==='local/panel/internal/executor'));
 assert(!rows.some(r=>['skip','pass'].includes(r.Action)),'Original production must reproduce each known failure, without skip or an unrelated passing suite');
 assert(rows.every(r=>!r.Test||names.includes(r.Test)),'Foreign tests cannot replace the original reproduction');
 for(const action of['run','fail']){
  const found=rows.filter(r=>r.Action===action&&r.Test).map(r=>r.Test);
  assert.equal(found.length,31);assert.equal(new Set(found).size,31);assert.deepEqual([...found].sort(),[...names].sort());
 }
 assert.equal(rows.filter(r=>r.Action==='fail'&&!r.Test).length,1,'Original Go package failure must be present');
 const witnesses=rows.filter(r=>r.Output?.includes('reader observed an unpublished private record: HTTP '));
 assert.equal(witnesses.length,28);assert.deepEqual(witnesses.map(r=>r.Test).sort(),[...leaves].sort());
 assert(witnesses.every(r=>r.Output.includes('reader observed an unpublished private record: HTTP 409 ')),'Only the original incomplete-record response proves this defect');
 return{original_defect_reproduced:true,architecture,original_failed_cases:31,actual_unpublished_record_observations:28,original_source_inputs_sha256:contract.original_source_inputs_sha256,published_source_inputs_sha256:contract.published_source_inputs_sha256,original_production_source_unchanged:true,explicit_test_only_overlay_files:1,normal_candidate_source_overlays:0,installed_or_store_acceptance:false};
}
if(process.argv[1]&&path.resolve(process.argv[1])===fileURLToPath(import.meta.url)){
 assert.equal(process.platform,'linux');assert.equal(process.argv.length,4);
 assert.equal(process.argv[3],process.arch==='x64'?'x86_64':process.arch==='arm64'?'aarch64':'unsupported');
 const file=process.argv[2],s=fs.lstatSync(file);assert(s.isFile()&&!s.isSymbolicLink()&&s.size>0&&s.size<4*1024*1024);
 const index=JSON.parse(fs.readFileSync(root+'candidate/panel-integration-load-balance/source-sha256.json'));
 assert.equal(index.release.frozen_inputs_sha256,publicationOriginalDefect.published_source_inputs_sha256);assert.equal(Object.keys(index.files).length,publicationOriginalDefect.published_source_sdk_files);
 console.log(JSON.stringify(verifyPublicationOriginalDefect(fs.readFileSync(file,'utf8').trim().split('\n').map(line=>JSON.parse(line)),process.argv[3])));
}
