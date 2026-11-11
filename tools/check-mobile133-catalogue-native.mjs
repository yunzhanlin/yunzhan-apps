import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import {fileURLToPath}from 'node:url';
export function verifyMobile133Catalogue(rows,ids,mode){
 assert(['current133','retained132','C67-refuses133','latest-signed'].includes(mode));
 const prefix='TestPublishedCandidateRepositoryCurrentSignedManifestABI',negative=mode==='C67-refuses133';
 assert.equal(ids.length,50);assert.equal(new Set(ids).size,50);assert(ids.includes('mobile'));
 assert(rows.length>0&&rows.every(r=>r.Package==='local/panel/internal/appcatalog')&&!rows.some(r=>r.Action==='skip'));
 assert(rows.every(r=>!r.Test||r.Test===prefix||ids.some(id=>r.Test===prefix+'/'+id)));
 for(const action of ['run','pass','fail']){
  const wanted=action==='run'?[prefix,...ids.map(id=>prefix+'/'+id)]:action==='pass'?(negative?ids.filter(id=>id!=='mobile').map(id=>prefix+'/'+id):[prefix,...ids.map(id=>prefix+'/'+id)]):(negative?[prefix,prefix+'/mobile']:[]);
  const actual=rows.filter(r=>r.Action===action&&r.Test).map(r=>r.Test);assert.equal(actual.length,new Set(actual).size);assert.deepEqual(actual.sort(),wanted.sort());
 }
 assert.equal(rows.filter(r=>r.Action==='fail'&&!r.Test).length,negative?1:0);assert.equal(rows.filter(r=>r.Action==='pass'&&!r.Test).length,negative?0:1);
 if(negative)assert(rows.some(r=>r.Test===prefix+'/mobile'&&r.Output?.includes('actual compiled verifier rejects the candidate manifest 移动端新交付仅允许固定1.3.2、mobile-pwa目标及独立编译的原生交付处理器')));
 return{ok:true,mode,all50_passed:!negative,other49_passed:negative,only_mobile133_refused:negative,skips:0,not_installed_acceptance:true};
}
if(process.argv[1]&&path.resolve(process.argv[1])===fileURLToPath(import.meta.url)){
 assert.equal(process.platform,'linux');assert.equal(process.argv.length,5);const file=process.argv[2],st=fs.lstatSync(file);assert(st.isFile()&&!st.isSymbolicLink()&&st.size>0&&st.size<4*1024*1024);
 console.log(JSON.stringify(verifyMobile133Catalogue(fs.readFileSync(file,'utf8').trim().split('\n').map(s=>JSON.parse(s)),JSON.parse(fs.readFileSync(process.argv[3])).apps.map(a=>a.id),process.argv[4])));
}
