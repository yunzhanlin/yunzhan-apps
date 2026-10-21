import assert from 'node:assert/strict';import fs from 'node:fs';import path from 'node:path';import {spawnSync} from 'node:child_process';import {fileURLToPath} from 'node:url';import {createHash,createPublicKey,verify} from 'node:crypto';
export function oldWAFRepositoryRoot(args,root){
 const predecessor='registry/reviewed-catalogs/before-nginx-runtime-package24bixw';
 assert(args.length===0||(args.length===2&&args[0]==='--repo-root'&&args[1]===predecessor),'Only the genuine reviewed predecessor may select the historical WAF-only boundary');
 if(!args.length)return root;
 const selected=path.join(root,predecessor),raw=fs.readFileSync(path.join(selected,'dist/catalog-v1.json')),pub=fs.readFileSync(path.join(selected,'signatures/catalog-v1.pub.pem')),sig=fs.readFileSync(path.join(selected,'signatures/catalog-v1.sig')).toString().trim(),bundle=JSON.parse(fs.readFileSync(path.join(selected,'signatures/catalog-v1.bundle.json'))),sha=b=>createHash('sha256').update(b).digest('hex');
 assert.equal(sha(raw),'18c83c0e2ef31d6cb81cb2230fffb30648bebe957adb4f3518dd9a39b11264cf');assert.equal(sha(pub),'659ea4edcecaf23a586e2ff371616fde5f6ee7c219fb70fa978816e2b10acf75');assert.equal(bundle.catalog,raw.toString());assert.equal(bundle.signature,sig);assert(verify(null,raw,createPublicKey(pub),Buffer.from(sig,'base64')));
 return selected;
}
export function verifyOldWAFHealthRefusal(result,ids){
 assert.equal(result.status,1);assert(!result.error&&!result.signal);assert.equal(ids.length,50);assert.equal(new Set(ids).size,50);assert(ids.includes('nginx-waf'));
 const events=result.stdout.trim().split('\n').map(line=>JSON.parse(line)),prefix='TestPublishedRepositoryCurrentSignedManifestABI';
 assert.deepEqual(events.filter(e=>e.Action==='fail'&&e.Test).map(e=>e.Test).sort(),[prefix,prefix+'/nginx-waf']);
 assert.deepEqual(events.filter(e=>e.Action==='pass'&&e.Test).map(e=>e.Test).sort(),ids.filter(id=>id!=='nginx-waf').map(id=>prefix+'/'+id).sort());assert(!events.some(e=>e.Action==='skip'));assert(events.some(e=>e.Output?.includes('面板处理器不支持 waf-bound-health-v1')));assert.equal(events.filter(e=>!e.Test&&e.Action==='fail').length,1);
 return {other49_passed:49,only_WAF2_5_2_refused:true,old_compiled_runtime_unchanged:true};
}
if(process.argv[1]&&path.resolve(process.argv[1])===fileURLToPath(import.meta.url)){
 assert.equal(process.platform,'linux');const root=fileURLToPath(new URL('../',import.meta.url)),selected=oldWAFRepositoryRoot(process.argv.slice(2),root),ids=JSON.parse(fs.readFileSync(path.join(selected,'dist/catalog-v1.json'))).apps.map(a=>a.id);
 const result=spawnSync('go',['test','-json','./internal/appcatalog','-run','^TestPublishedRepositoryCurrentSignedManifestABI$','-count=1','-args','-published-app-registry-root',selected],{cwd:root+'panel-integration-intrusion-admission',encoding:'utf8',timeout:180000,maxBuffer:4<<20});process.stdout.write(result.stdout??'');process.stderr.write(result.stderr??'');console.log(JSON.stringify(verifyOldWAFHealthRefusal(result,ids)));
}
