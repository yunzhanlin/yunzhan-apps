// Actual unmodified pre-runtime-package Linux handler must refuse only the
// new Nginx manifest. A catalog-level failure or any skipped/other failure is red.
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import {spawnSync} from 'node:child_process';
import {fileURLToPath} from 'node:url';
import {historicalMobileRepository} from './historical-mobile-repository.mjs';
export function verifyOldNginxRuntimeRefusal(result,ids){
 assert.equal(result.status,1);assert(!result.error&&!result.signal);
 assert.equal(ids.length,50);assert.equal(new Set(ids).size,50);assert(ids.includes('nginx'));
 const events=result.stdout.trim().split('\n').map(line=>JSON.parse(line)),prefix='TestPublishedRepositoryCurrentSignedManifestABI';
 assert.deepEqual(events.filter(e=>e.Action==='fail'&&e.Test).map(e=>e.Test).sort(),[prefix,prefix+'/nginx']);
 assert.deepEqual(events.filter(e=>e.Action==='pass'&&e.Test).map(e=>e.Test).sort(),ids.filter(id=>id!=='nginx').map(id=>prefix+'/'+id).sort());
 assert(!events.some(e=>e.Action==='skip'));
 assert(events.some(e=>e.Test===prefix+'/nginx'&&e.Output?.includes('actual compiled handler rejects current signed manifest 应用面板处理器要求无效')));
 assert.equal(events.filter(e=>!e.Test&&e.Action==='fail').length,1);
 return {other49_passed:49,only_Nginx1_30_6_refused:true,old_compiled_source_unchanged:true,not_application_installation:true};
}
if(process.argv[1]&&path.resolve(process.argv[1])===fileURLToPath(import.meta.url)){
 assert.equal(process.platform,'linux');
 const root=fileURLToPath(new URL('../',import.meta.url)),repository=historicalMobileRepository(process.argv.slice(2),root);
 const ids=JSON.parse(fs.readFileSync(path.join(repository,'dist/catalog-v1.json'))).apps.map(a=>a.id);
 const result=spawnSync('go',['test','-json','./internal/appcatalog','-run','^TestPublishedRepositoryCurrentSignedManifestABI$','-count=1','-args','-published-app-registry-root',repository],{cwd:path.join(root,'panel-integration-waf-descriptor'),encoding:'utf8',timeout:180000,maxBuffer:4<<20});
 process.stdout.write(result.stdout??'');process.stderr.write(result.stderr??'');console.log(JSON.stringify(verifyOldNginxRuntimeRefusal(result,ids)));
}
