import {test} from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import ts from '../web/node_modules/typescript/lib/typescript.js';
import {readWafSites} from '../web/src/wafSites.ts';
const id=n=>n.toString(16).padStart(32,'0');
const site=(n,server='nginx')=>({id:id(n),name:'Fixture website',domain:`site-${n}.example.test`,status:'running',settings:{web_server:server,waf_enabled:true}});
const page=(n,offset=0)=>({sites:Array.from({length:n},(_,i)=>site(i+offset+1)),next_cursor:''});
test('actual reader uses only bounded WAF pages and publishes a complete stable inventory',async()=>{
 const first=page(128),second=page(2,128);first.next_cursor=id(128);const paths=[];
 const result=await readWafSites('nginx-waf',async path=>{paths.push(path);return paths.length===1?first:second;},()=>true);
 assert.equal(result.length,130);assert.deepEqual(paths,['/software/nginx-waf/sites',`/software/nginx-waf/sites?cursor=${id(128)}`]);
 assert.deepEqual(await readWafSites('nginx-waf',async()=>page(0),()=>true),[]);
 const apache={sites:[site(1,'apache')],next_cursor:''};assert.deepEqual(await readWafSites('apache-waf',async path=>{assert.equal(path,'/software/apache-waf/sites');return apache;},()=>true),apache.sites);
});
test('wrong engine, extra website/private fields and malformed pages fail closed',async()=>{
 await assert.rejects(readWafSites('other',async()=>{assert.fail('must not read');},()=>true));
 for(const value of [null,[],{}, {sites:[],next_cursor:'',secret:'extra'}, {sites:[],next_cursor:1}, page(129), {sites:[{...site(1),document_root:'/secret'}],next_cursor:''}, {sites:[site(1,'apache')],next_cursor:''}, {sites:[{...site(1),settings:{web_server:'nginx'}}],next_cursor:''}, {sites:[{...site(1),settings:{...site(1).settings,php:{}}}],next_cursor:''}, {sites:[{...site(1),id:'BAD'}],next_cursor:''}, {sites:[site(2),site(1)],next_cursor:''}, {sites:[site(1),site(1)],next_cursor:''}])await assert.rejects(readWafSites('nginx-waf',async()=>value,()=>true));
});
test('repeated, non-progressing, empty and malformed cursors cannot loop or claim success',async()=>{
 for(const cursor of ['bad',id(1),id(129)]){const value=page(128);value.next_cursor=cursor;await assert.rejects(readWafSites('nginx-waf',async()=>value,()=>true));}
 await assert.rejects(readWafSites('nginx-waf',async()=>({sites:[],next_cursor:id(128)}),()=>true));
 const first=page(128);first.next_cursor=id(128);let calls=0;
 await assert.rejects(readWafSites('nginx-waf',async()=>{calls++;return first;},()=>true));assert.equal(calls,2);
});
test('failed later page and disposal never return a partial inventory',async()=>{
 const first=page(128);first.next_cursor=id(128);let calls=0;
 await assert.rejects(readWafSites('nginx-waf',async()=>{if(++calls===2)throw new Error('actual network unavailable');return first;},()=>true),/network unavailable/);
 let live=false;await assert.rejects(readWafSites('nginx-waf',async()=>{assert.fail('disposed before read');},()=>live));
 live=true;calls=0;await assert.rejects(readWafSites('nginx-waf',async()=>{calls++;live=false;return first;},()=>live));assert.equal(calls,1);
});
test('physical pagination work is bounded to 32 pages without silently truncating',async()=>{
 let calls=0;await assert.rejects(readWafSites('nginx-waf',async()=>{const value=page(128,128*calls++);value.next_cursor=value.sites.at(-1).id;return value;},()=>true),/4096/);assert.equal(calls,32);
});
test('actual component refresh keeps previous complete inventory on rejection or disposal',async()=>{
 const source=readFileSync(new URL('../web/src/WafWorkspace.vue',import.meta.url),'utf8');
 const actual=source.slice(source.indexOf('async function refresh()'),source.indexOf('async function validate()'));
 const js=ts.transpileModule(actual,{compilerOptions:{target:ts.ScriptTarget.ES2022}}).outputText;
 for(const outcome of ['failure','disposed','success']){
  const old=[site(1)],next=[site(2)],bindings={busy:{value:false},dirty:{value:false},error:{value:''},sites:{value:old},disposed:false,engine:'nginx-waf',engineTimer:undefined,engines:{value:[]},history:{value:[]},loadConfig:async()=>{},
   readWafSites:async()=>{if(outcome==='failure')throw new Error('page unavailable');if(outcome==='disposed')bindings.disposed=true;return next;},
   props:{api:async()=>{assert.fail('must use minimal reader');}},refreshReport:async()=>{},refreshHistory:async()=>{},refreshEngines:async()=>{},refreshBodyReport:async()=>{},refreshBodyArchives:async()=>{},refreshBodyRotation:async()=>{},pollEngine:async()=>{}};
  await new Function('bindings','with(bindings){'+js+'\nreturn refresh;}')(bindings)();assert.equal(bindings.busy.value,false);
  assert.equal(bindings.sites.value,outcome==='success'?next:old);if(outcome==='failure')assert.match(bindings.error.value,/page unavailable/);
 }
 assert.doesNotMatch(actual,/props\.api[^\n]*\("\/sites"\)/);
 assert.match(readFileSync(new URL('../packaging/build-release.sh',import.meta.url),'utf8'),/test-waf-sites\.mjs/);
});
