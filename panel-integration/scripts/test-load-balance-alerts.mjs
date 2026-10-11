import {test} from 'node:test';import assert from 'node:assert/strict';import {readFileSync} from 'node:fs';import ts from '../web/node_modules/typescript/lib/typescript.js';
const read=p=>readFileSync(new URL('../'+p,import.meta.url),'utf8'),source=read('web/src/OutboundNotifications.vue');
const kindsLine=source.split('\n').find(l=>l.startsWith('const kinds = ')),draftLine=source.split('\n').find(l=>l.startsWith('const draft = ref('));
const state=()=>new Function('ref',kindsLine+'\n'+draftLine+'\nreturn {kinds,draft};')(value=>({value}));
test('actual notification editor offers health scope exactly once but never auto-subscribes existing or new default channels',()=>{
 const {kinds,draft}=state();assert.equal(kinds.filter(k=>k.id==='load-balance').length,1);assert.equal(kinds.find(k=>k.id==='load-balance').label,'负载均衡健康变化与事件缺口');assert(!draft.value.kinds.includes('load-balance'));
 assert(source.includes('draft.kinds.includes(\'load-balance\')'));for(const phrase of ['首次读取、新入口或配置修订建立基线','不补发先前记录','不代表实际流量已切换或整体恢复','不含域名、节点地址、正文或密钥'])assert(source.includes(phrase));
});
const start=source.indexOf('async function save()'),end=source.indexOf('async function toggle(',start);assert(start>=0&&end>start);
const actualSave=ts.transpileModule(source.slice(start,end),{compilerOptions:{target:ts.ScriptTarget.ES2022}}).outputText;
function editor(kinds){const {draft}=state();Object.assign(draft.value,{name:'owned scope fixture',url:'http://127.0.0.1:12345',secret:'fixture-signing-secret',kinds});const calls=[],notices=[],b={draft,saving:{value:false},smtpDraft:{value:{recipients:''}},editor:{value:true},props:{api:async(...args)=>calls.push(args)},ElMessage:{warning:x=>notices.push(['warning',x]),success:x=>notices.push(['success',x]),error:x=>notices.push(['error',x])},clearCredentials(){b.draft.value.secret='';},refresh:async()=>{}};return {b,calls,notices,save:new Function('b','with(b){'+actualSave+';return save;}')(b)};}
test('actual save sends only the explicitly selected health scope and clears write-only credentials after acknowledgement',async()=>{
 const e=editor(['load-balance']);await e.save();assert.equal(e.calls.length,1);assert.equal(e.calls[0][0],'/notification-channels');assert.equal(e.calls[0][1],'POST');assert.deepEqual(e.calls[0][2].kinds,['load-balance']);assert.equal(e.b.draft.value.secret,'');assert.equal(e.b.editor.value,false);assert.equal(e.b.saving.value,false);
 const no=editor([]);await no.save();assert.equal(no.calls.length,0);assert.equal(no.notices[0][0],'warning');
});
test('new frontend guard is mandatory and backend still scrubs arbitrary original health evidence',()=>{
 const builder=read('packaging/build-release.sh');assert(builder.includes('test-load-balance-alerts.mjs'));
 const manager=read('web/src/AppModuleManager.vue');assert(manager.includes('不自动订阅旧通道'));assert(manager.includes('健康告警与实际流量变更仍须分别核对'));
 const backend=read('internal/core/outbound_notifications.go');assert.match(backend,/case "load-balance":/);assert(backend.includes('不代表所有节点或业务已恢复'));assert(backend.includes('Source messages can include arbitrary task output'));
 const core=read('internal/core/outbound_load_balance.go');assert(core.includes('revision > entry.Revision'));assert(core.includes('sequence > entry.Sequence'));assert(core.includes('count >= 10000'));assert(core.includes('return tx.Commit()'));
});
