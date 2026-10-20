import assert from 'node:assert/strict';import {spawnSync}from'node:child_process';import fs from'node:fs';import path from'node:path';import{fileURLToPath}from'node:url';
export function verifyOldIntrusionRefusal(result,ids){
 assert.equal(result.status,1);assert(!result.error&&!result.signal);assert.equal(ids.length,50);assert.equal(new Set(ids).size,50);assert(ids.includes('anti-intrusion'));
 const events=result.stdout.trim().split('\n').map(line=>JSON.parse(line)),prefix='TestPublishedRepositoryCurrentSignedManifestABI';
 assert.deepEqual(events.filter(e=>e.Action==='fail'&&e.Test).map(e=>e.Test).sort(),[prefix,prefix+'/anti-intrusion']);
 assert.deepEqual(events.filter(e=>e.Action==='pass'&&e.Test).map(e=>e.Test).sort(),ids.filter(id=>id!=='anti-intrusion').map(id=>prefix+'/'+id).sort());
 assert(!events.some(e=>e.Action==='skip'));assert(events.some(e=>e.Output?.includes('面板处理器不支持 intrusion-preserving-journal-v2')));assert.equal(events.filter(e=>!e.Test&&e.Action==='fail').length,1);
 return {other49_passed:49,only_intrusion1_1_refused:true,old_compiled_runtime_unchanged:true};
}
if(process.argv[1]&&path.resolve(process.argv[1])===fileURLToPath(import.meta.url)){
 assert.equal(process.platform,'linux');const root=fileURLToPath(new URL('../',import.meta.url)),ids=JSON.parse(fs.readFileSync(root+'dist/catalog-v1.json')).apps.map(a=>a.id);
 const result=spawnSync('go',['test','-json','./internal/appcatalog','-run','^TestPublishedRepositoryCurrentSignedManifestABI$','-count=1','-args','-published-app-registry-root',root],{cwd:root+'panel-integration-hardening',encoding:'utf8',timeout:180000,maxBuffer:4<<20});
 process.stdout.write(result.stdout??'');process.stderr.write(result.stderr??'');console.log(JSON.stringify(verifyOldIntrusionRefusal(result,ids)));
}
