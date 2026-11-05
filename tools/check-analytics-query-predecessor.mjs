import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import {fileURLToPath}from 'node:url';
export function verifyAnalyticsQueryPredecessor(rows,ids){
 const prefix='TestPublishedCandidateRepositoryCurrentSignedManifestABI',feature='website-analytics-query-context-v1';
 assert.equal(ids.length,50);assert.equal(new Set(ids).size,50);assert(ids.includes('website-analytics'));
 assert(rows.length>0&&rows.every(row=>row.Package==='local/panel/internal/appcatalog')&&!rows.some(row=>row.Action==='skip'));
 assert(rows.every(row=>!row.Test||row.Test===prefix||ids.some(id=>row.Test===prefix+'/'+id)));
 for(const action of ['run','pass','fail']){
  const wanted=action==='run'?[prefix,...ids.map(id=>prefix+'/'+id)]:action==='pass'?ids.filter(id=>id!=='website-analytics').map(id=>prefix+'/'+id):[prefix,prefix+'/website-analytics'];
  const actual=rows.filter(row=>row.Action===action&&row.Test).map(row=>row.Test);assert.equal(actual.length,new Set(actual).size);assert.deepEqual(actual.sort(),wanted.sort());
 }
 assert.equal(rows.filter(row=>row.Action==='fail'&&!row.Test).length,1);assert.equal(rows.filter(row=>row.Action==='pass'&&!row.Test).length,0);
 assert(rows.some(row=>row.Test===prefix+'/website-analytics'&&row.Output?.includes(feature)));
 return {ok:true,original_C62r4_unchanged:true,exact_missing_feature:feature,other49_apps_passed:true,only_analytics242_refused:true,not_installed_acceptance:true};
}
if(process.argv[1]&&path.resolve(process.argv[1])===fileURLToPath(import.meta.url)){
 assert.equal(process.platform,'linux');assert.equal(process.argv.length,4);
 const file=process.argv[2],st=fs.lstatSync(file);assert(st.isFile()&&!st.isSymbolicLink()&&st.size>0&&st.size<4*1024*1024);
 console.log(JSON.stringify(verifyAnalyticsQueryPredecessor(fs.readFileSync(file,'utf8').trim().split('\n').map(line=>JSON.parse(line)),JSON.parse(fs.readFileSync(process.argv[3])).apps.map(app=>app.id))));
}
