import test from 'node:test';import assert from 'node:assert/strict';import {readFileSync} from 'node:fs';import {createHash} from 'node:crypto';import ts from '../web/node_modules/typescript/lib/typescript.js';
import {dockerCreateStorageKey,readDockerCreateRequest,dockerCreateFingerprint} from '../web/src/dockerCreateRequest.ts';
const actor='a'.repeat(32),key='b'.repeat(32),fingerprint='c'.repeat(64),original={format:1,actor,key,fingerprint};
const randomExports={};new Function('exports',ts.transpileModule(readFileSync(new URL('../web/src/randomId.ts',import.meta.url),'utf8'),{compilerOptions:{target:ts.ScriptTarget.ES2022,module:ts.ModuleKind.CommonJS}}).outputText)(randomExports);
test('the REAL panel randomId UUIDv4 survives request retention; actor IDs stay strictly32-hex',()=>{
 for(let i=0;i<32;i++){const key=randomExports.randomId();assert.match(key,/^[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/);assert.deepEqual(readDockerCreateRequest(JSON.stringify({...original,key}),actor),{...original,key});assert.equal(dockerCreateStorageKey(key),'');}
 for(const key of ['e081af54-b8e5-3578-9c52-96cdad242f08','e081af54-b8e5-4578-7c52-96cdad242f08','../request','x'.repeat(128)])assert.equal(readDockerCreateRequest(JSON.stringify({...original,key}),actor),null);
});
test('retained create pointer is actor-bound, closed and contains neither Compose nor credentials',()=>{
 assert.equal(dockerCreateStorageKey(actor),'panel-docker-create-v1:'+actor);assert.deepEqual(readDockerCreateRequest(JSON.stringify(original),actor),original);
 for(const v of ['',null,undefined,'a'.repeat(31),'../other'])assert.equal(dockerCreateStorageKey(v),'');
 assert.equal(readDockerCreateRequest(JSON.stringify(original),'d'.repeat(32)),null);
 for(const v of [[],null,{}, {...original,format:2},{...original,key:'invalid'},{...original,fingerprint:'invalid'},{...original,compose:'private fixture'},{...original,password:'private fixture'},{...original,csrf:'private fixture'}])assert.equal(readDockerCreateRequest(JSON.stringify(v),actor),null);
 for(const raw of ['{','x'.repeat(513),'null','[]'])assert.equal(readDockerCreateRequest(raw,actor),null);
});
test('actual HTTP-compatible fingerprint binds the exact outgoing body without retaining its private fields',async()=>{
 const body={name:'fixture',template_id:'',host_port:0,compose:'services:\n  app:\n    image: fixture:1\n    environment:\n      PASSWORD: synthetic-fixture-only\n'};
 const digest=await dockerCreateFingerprint(body);assert.equal(digest,createHash('sha256').update(JSON.stringify(body)).digest('hex'));assert.notEqual(await dockerCreateFingerprint({...body,name:'different'}),digest);
 const pointer=JSON.stringify({...original,fingerprint:digest});assert(!pointer.includes('synthetic-fixture-only')&&!pointer.includes('compose')&&!pointer.includes('PASSWORD'));assert.deepEqual(Object.keys(JSON.parse(pointer)).sort(),['actor','fingerprint','format','key']);
});
test('normal release keeps both the pointer protocol and actual Vue callback lifecycle as mandatory gates',()=>{
 const release=readFileSync(new URL('../packaging/build-release.sh',import.meta.url),'utf8');assert(release.includes('node --test scripts/test-docker-create-requests.mjs'));assert(release.includes('node --test scripts/test-docker-scope.mjs'));
 const vue=readFileSync(new URL('../web/src/DockerManager.vue',import.meta.url),'utf8');assert(vue.includes('核对原创建任务')&&vue.includes('busy || Boolean(pendingCreate) || createBlocked ||'));assert(vue.includes('"/docker/project-requests/"+retained.key'));assert(!vue.includes('sessionStorage.setItem(storageKey,JSON.stringify(body))'));
});
test('actual shared API preserves an explicit pre-dispatch rejection without treating network errors or truthy strings as safe rejection',async()=>{
 const app=readFileSync(new URL('../web/src/App.vue',import.meta.url),'utf8'),code=ts.transpileModule(app.slice(app.indexOf('async function api<T>('),app.indexOf('const overviewReadGate =')),{compilerOptions:{target:ts.ScriptTarget.ES2022}}).outputText;
 for(const supplied of [true,false,'true',undefined]){
  const calls=[],b={assertFrontendMutationCurrent:()=>{},frontendReleaseStatus:{value:{kind:'current'}},csrf:{value:'fixture-session'},accessEpoch:1,registryRequestIdentity:{begin:()=>assert.fail('no registry request')},apiURL:p=>'/api'+p,randomId:()=>assert.fail('must keep explicit key'),user:{value:'fixture'},accessPlan:{value:{}},accountChanging:{value:false},clearAccessData:()=>assert.fail('no account change'),fetch:async(...args)=>{calls.push(args);return{ok:false,status:400,json:async()=>({error:'synthetic rejection',request_not_accepted:supplied})}}};
  const api=new Function(...Object.keys(b),code+';return api;')(...Object.values(b));
  await assert.rejects(api('/docker/projects','POST',{name:'fixture'},key),e=>e instanceof Error&&e.status===400&&e.requestNotAccepted===(supplied===true));
  assert.equal(calls.length,1);assert.equal(calls[0][1].headers['Idempotency-Key'],key);
 }
});
