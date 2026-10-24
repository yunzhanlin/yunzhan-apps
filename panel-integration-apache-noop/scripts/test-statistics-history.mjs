import {test} from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {statisticsHistoryNotice} from '../web/src/statisticsHistory.ts';
import ts from '../web/node_modules/typescript/lib/typescript.js';
const identitySource=readFileSync(new URL('../web/src/statisticsGeoIdentity.ts',import.meta.url),'utf8');
const identityJS=ts.transpileModule(identitySource,{compilerOptions:{target:ts.ScriptTarget.ES2022,module:ts.ModuleKind.ESNext}}).outputText;
const {StatisticsGeoRequestIdentity,IndexedStatisticsGeoStorage}=await import('data:text/javascript;base64,'+Buffer.from(identityJS).toString('base64'));
function atomicGeoStore(){const data=new Map();let tail=Promise.resolve();return{data,run(actor,write,change){const run=tail.then(()=>{const result=change(structuredClone(data.get(actor)),data.size);assert(!(!write&&(result.put||result.remove)));if(result.put)data.set(actor,structuredClone(result.put));if(result.remove)data.delete(actor);return structuredClone(result.result)});tail=run.catch(()=>{});return run;}}}
const geoActor='a'.repeat(32),geoKey='b'.repeat(32),geoJob='c'.repeat(32),geoSelection={action:'install',app_version:'2.6.0',app_manifest_sha256:'d'.repeat(64),installation_id:'e'.repeat(32),release:'2026-10',data_manifest_sha256:'f'.repeat(64)};
function actualGeoFunction(name){const source=readFileSync(new URL('../web/src/StatisticsGeoWorkspace.vue',import.meta.url),'utf8').split('<script setup lang="ts">')[1].split('</script>')[0],tree=ts.createSourceFile('geo.vue',source,ts.ScriptTarget.Latest,true,ts.ScriptKind.TS),node=tree.statements.find(n=>ts.isFunctionDeclaration(n)&&n.name?.text===name);assert(node);return ts.transpileModule(node.getText(tree),{compilerOptions:{target:ts.ScriptTarget.ES2022,module:ts.ModuleKind.ESNext}}).outputText;}
test('legacy gzip reports never claim import, while enabled pending archives remain partial',()=>{
 assert.match(statisticsHistoryNotice({history_compressed_sources:1}),/当前应用未启用压缩日志导入/);
 assert.match(statisticsHistoryNotice({history_compressed_sources:1,history_gzip_import_enabled:true}),/完整校验通过后才提交/);
 assert.match(statisticsHistoryNotice({history_compressed_sources:1,history_gzip_import_enabled:'true'}),/未启用/);
 assert.equal(statisticsHistoryNotice({history_compressed_sources:0,history_verified_compressed_sources:4,history_gzip_import_enabled:true}),undefined);
});
test('missing/conflicting/invalid inputs have precise notices without coercing unknown counters',()=>{
 const text=statisticsHistoryNotice({history_blocked_sources:2,history_missing_log:true,history_invalid_lines:1});
 for(const phrase of ['不会从头重置','没有可核对','旧压缩行','原始日志保留'])assert(text.includes(phrase));
 for(const value of [NaN,Infinity,-1,'2',false,null])assert.equal(statisticsHistoryNotice({history_compressed_sources:value}),undefined);
 assert.match(statisticsHistoryNotice({history_unsupported_rotation_sources:1}),/未静默忽略为完整历史/);
});
test('real report component uses native flags, Chinese counters and no forged enable action',()=>{
 const source=readFileSync(new URL('../web/src/AppModuleReport.vue',import.meta.url),'utf8');
 assert.match(source,/:title="statisticsHistoryNotice\(report\)"/);
 for(const phrase of ['请求标识去重已启用','识别并跳过的重复请求','旧版历史模式','完整校验过的压缩来源'])assert(source.includes(phrase));
 const helper=readFileSync(new URL('../web/src/statisticsHistory.ts',import.meta.url),'utf8');
 assert.doesNotMatch(helper,/fetch\(|localStorage|sessionStorage|Math.random/);
 const build=readFileSync(new URL('../packaging/build-release.sh',import.meta.url),'utf8');
 assert(build.includes('node --test scripts/test-statistics-history.mjs'));
});
test('geo write-ahead identity commits before use, survives reload and serializes concurrent tabs',async()=>{
 const store=atomicGeoStore();let generated=0;const one=new StatisticsGeoRequestIdentity(store,geoActor,()=>{generated++;return geoKey}),two=new StatisticsGeoRequestIdentity(store,geoActor,()=>{generated++;return'f'.repeat(32)});
 const [a,b]=await Promise.all([one.begin(geoSelection),two.begin({...geoSelection})]);assert.deepEqual(a,b);assert.equal(generated,1);assert.equal(store.data.size,1);assert.deepEqual(await two.read(),a);
 geoSelection.release='2026-11';assert.equal((await one.read()).selection.release,'2026-10');geoSelection.release='2026-10';
 await assert.rejects(two.begin({...geoSelection,installation_id:'f'.repeat(32)}));assert.equal((await one.read()).key,geoKey);
 const other=new StatisticsGeoRequestIdentity(store,'d'.repeat(32),()=>geoKey);assert.equal(await other.read(),undefined);assert.equal(store.data.size,1);
});
test('geo original job receipt and unknown/attention observations never release or rotate identity',async()=>{
 const store=atomicGeoStore(),i=new StatisticsGeoRequestIdentity(store,geoActor,()=>geoKey),original=await i.begin(geoSelection);await i.accepted(original,geoJob);assert.equal((await i.read()).job,geoJob);
 await assert.rejects(i.accepted(original,'f'.repeat(32)));assert.equal((await i.read()).job,geoJob);
 assert.equal((await i.observe({request_id:geoKey,job_id:'',state:'unknown',state_known:false})).job,geoJob);
 for(const state of ['queued','running','needs_attention'])assert.equal((await i.observe({request_id:geoKey,job_id:geoJob,selection:{...geoSelection},state,state_known:true})).job,geoJob);
 for(const change of [{request_id:'f'.repeat(32)},{job_id:'f'.repeat(32)},{selection:{...geoSelection,release:'2026-11'}},{state_known:'true'},{state:'invented'}])await assert.rejects(i.observe({request_id:geoKey,job_id:geoJob,selection:{...geoSelection},state:'succeeded',state_known:true,...change}));
 assert.equal((await i.read()).key,geoKey);await i.observe({request_id:geoKey,job_id:geoJob,selection:{...geoSelection},state:'succeeded',state_known:true});assert.equal(await i.read(),undefined);
});
test('geo corrupt storage, unavailable transaction, capacity and uncommitted writes fail closed',async()=>{
 for(const value of [null,{},[],{format:1,actor:geoActor,key:geoKey,selection:{...geoSelection},extra:'untrusted'},{format:1,actor:'f'.repeat(32),key:geoKey,selection:{...geoSelection}},{format:1,actor:geoActor,key:geoKey,selection:{...geoSelection,action:'delete'}}]){
  const s=atomicGeoStore();s.data.set(geoActor,value);const before=structuredClone(value),i=new StatisticsGeoRequestIdentity(s,geoActor,()=>geoKey);await assert.rejects(i.read());await assert.rejects(i.begin(geoSelection));assert.deepEqual(s.data.get(geoActor),before);
 }
 const unavailable={run:async()=>{throw Error('storage disabled')}};await assert.rejects(new StatisticsGeoRequestIdentity(unavailable,geoActor,()=>geoKey).begin(geoSelection));await assert.rejects(new IndexedStatisticsGeoStorage(undefined).run(geoActor,true,()=>({})));
 const full=atomicGeoStore();for(let n=0;n<128;n++)full.data.set('actor'+n,{});await assert.rejects(new StatisticsGeoRequestIdentity(full,geoActor,()=>geoKey).begin(geoSelection));assert.equal(full.data.size,128);
 for(const random of ['bad','x'.repeat(32),['b'.repeat(32)]])await assert.rejects(new StatisticsGeoRequestIdentity(atomicGeoStore(),geoActor,()=>random).begin(geoSelection));
 assert(identitySource.includes('tx.oncomplete=')&&identitySource.includes('durability:"strict"'));
 const tree=ts.createSourceFile('identity.ts',identitySource,ts.ScriptTarget.Latest,true,ts.ScriptKind.TS);let localAccess=false;const visit=node=>{if(ts.isIdentifier(node)&&node.text==='localStorage')localAccess=true;ts.forEachChild(node,visit)};visit(tree);assert(!localAccess,'no non-atomic localStorage access, comments are not accesses');assert(!identitySource.includes('fetch('));
});
test('actual geo refresh drops a stale outcome after another tab has finished the original request',async()=>{
 let gets=0;const refs={busy:{value:false},blocked:{value:false},generation:1,abort:new AbortController(),error:{value:''},outcome:{value:{state:'queued'}},pending:{value:{key:geoKey}},page:{},identity:()=>({read:async()=>undefined}),checkOriginal:async()=>{assert.equal(refs.pending.value,undefined)},props:{api:async(path,method)=>{assert.equal(path,'/software/website-statistics-v2/geodata');assert.equal(method,'GET');gets++;return{state:{stored:[]},jobs:[]}}}};
 await new Function(...Object.keys(refs),actualGeoFunction('refresh')+';return refresh;')(...Object.values(refs))();assert.equal(refs.outcome.value,undefined);assert.equal(refs.pending.value,undefined);assert.equal(refs.busy.value,false);assert.equal(refs.blocked.value,false);assert.equal(gets,1);
});
test('actual geo submit cannot POST before durable identity, and a lost response retains only the original request',async()=>{
 let commit,posts=0,committed=false;const wait=new Promise(resolve=>commit=resolve),original={key:geoKey,selection:{...geoSelection}},refs={busy:{value:false},blocked:{value:false},generation:3,abort:new AbortController(),error:{value:''},pending:{},identity:()=>({begin:async()=>{await wait;committed=true;return original},accepted:()=>assert.fail('no invented receipt')}),checkOriginal:()=>assert.fail('lost reply cannot invent original job'),refresh:()=>assert.fail('lost reply must retain original'),props:{api:async(path,method,body,key)=>{assert(committed);assert.equal(path,'/software/website-statistics-v2/geodata');assert.equal(method,'POST');assert.equal(key,geoKey);assert.deepEqual(body,geoSelection);posts++;throw Error('lost original reply')},onJob:()=>assert.fail('no original job receipt yet')}};
 const run=new Function(...Object.keys(refs),actualGeoFunction('submit')+';return submit;')(...Object.values(refs)),pendingRun=run(geoSelection);await Promise.resolve();assert.equal(posts,0);commit();await pendingRun;assert.equal(posts,1);assert.equal(refs.pending.value.key,geoKey);assert.equal(refs.busy.value,false);assert.match(refs.error.value,/保留原编号/);
});
test('actual geo actor reset cancels requests and clears every old private display without deleting durable records',()=>{
 const old=new AbortController(),refs={generation:1,abort:old,page:{value:{old:'actor'}},pending:{value:{key:geoKey}},outcome:{value:{state:'queued'}},busy:{value:true},blocked:{value:true},error:{value:'old'}};
 new Function(...Object.keys(refs),actualGeoFunction('reset')+';return reset;')(...Object.values(refs))();assert(old.signal.aborted);for(const name of ['page','pending','outcome'])assert.equal(refs[name].value,undefined);assert.equal(refs.busy.value,false);assert.equal(refs.blocked.value,false);assert.equal(refs.error.value,'');assert(!actualGeoFunction('reset').includes('.remove('));
 const parent=readFileSync(new URL('../web/src/AppModuleManager.vue',import.meta.url),'utf8');assert(parent.includes(':key="geoActor" :actor="geoActor"'));
});

