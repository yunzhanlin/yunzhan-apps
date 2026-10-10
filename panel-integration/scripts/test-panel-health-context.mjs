import {test} from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import ts from '../web/node_modules/typescript/lib/typescript.js';
async function load(name){const source=readFileSync(new URL('../web/src/'+name+'.ts',import.meta.url),'utf8');const output=ts.transpileModule(source,{compilerOptions:{target:ts.ScriptTarget.ES2022,module:ts.ModuleKind.ESNext}}).outputText;return import('data:text/javascript;base64,'+Buffer.from(output).toString('base64'));}
const {panelHealthState,panelSampleIsCurrent}=await load('panelHealth');
const {EpochReadGate}=await load('epochReadGate');
const {analyticsQueryContext,analyticsQueryMatches,restoreAnalyticsQuery}=await load('analyticsQueryContext');
const wall=Date.parse('2026-10-10T00:00:00Z');
const healthy=()=>({permitted:true,overview:{nginx_active:true,sampled_at:new Date(wall).toISOString()},readError:'',receivedAt:100,monotonicNow:5000,wallNow:wall});
const site='0123456789abcdef0123456789abcdef';
const report=()=>({site_id:site,filters:{from_time:'',to_time:'',search:'/failure',status_code:503,min_seconds:2,only_bots:true}});
test('server health ignores unrelated/catalog errors but refuses failed overview reads',()=>{
 assert.equal(panelHealthState({...healthy(),catalogError:'TLS timeout',operationError:'form invalid'}).kind,'ok');
 assert.deepEqual(panelHealthState({...healthy(),readError:'executor unavailable'}),{label:'服务器状态读取失败',kind:'error'});
 assert.equal(panelHealthState({...healthy(),permitted:false,readError:'old account error'}).label,'服务器状态未授权');
 assert.equal(panelHealthState({...healthy(),overview:null}).kind,'warning');
 assert.equal(panelHealthState({...healthy(),overview:{nginx_active:false,sampled_at:new Date(wall).toISOString()}}).label,'网站入口待检查');
});
test('stale, malformed and future-clock samples never display healthy',()=>{
 for(const change of [{receivedAt:null},{receivedAt:NaN},{monotonicNow:45101},{monotonicNow:99},{overview:{}},{overview:{nginx_active:'true',sampled_at:new Date(wall).toISOString()}},{overview:{nginx_active:true,sampled_at:'invalid'}},{wallNow:wall+90001},{wallNow:wall-30001}])assert.notEqual(panelHealthState({...healthy(),...change}).kind,'ok');
 assert.equal(panelHealthState({...healthy(),monotonicNow:45100}).kind,'ok');
});
test('sample labels are fresh only after authorized successful time-validated reads, independent of Nginx state',()=>{
 assert.equal(panelSampleIsCurrent(healthy()),true);
 assert.equal(panelSampleIsCurrent({...healthy(),overview:{nginx_active:false,sampled_at:new Date(wall).toISOString()}}),true);
 for(const change of [{permitted:false},{readError:'stalled executor'},{overview:null},{receivedAt:null},{overview:{}},{monotonicNow:45101},{wallNow:wall+90001}])assert.equal(panelSampleIsCurrent({...healthy(),...change}),false);
 const app=readFileSync(new URL('../web/src/App.vue',import.meta.url),'utf8');assert.doesNotMatch(app,/<span>实时采样<\/span>/);
 assert.match(app,/sampleIsCurrent \? "新鲜采样"/);assert.match(app,/最近记录的运行时间/);assert.match(app,/每 5 秒尝试采样，仅记录成功结果/);
 assert.match(app,/overview \? percent\(overview.cpu_percent\) : "—"/);
});
test('retained statistics queries restore only validated read filters and an authorized existing site',()=>{
 const value=report();value.password='NEVER';value.confirm='DELETE';value.action='remove';value.expected_revision=99;
 const context=analyticsQueryContext(value);assert.deepEqual(context,{site_id:site,...value.filters});
 assert.deepEqual(restoreAnalyticsQuery(context,[{id:site}]),context);assert.equal(restoreAnalyticsQuery(context,[{id:'another'}]),undefined);
 for(const secret of ['password','confirm','action','expected_revision'])assert(!Object.hasOwn(context,secret));
 const copy=restoreAnalyticsQuery(context,[{id:site}]);copy.search='changed';assert.equal(context.search,'/failure');
});
test('draft edits do not masquerade as retained report filters; Date fields compare canonically',()=>{
 const context=analyticsQueryContext(report());assert(analyticsQueryMatches(context,{...context}));
 for(const change of [{site_id:''},{search:''},{status_code:200},{min_seconds:1},{only_bots:false},{from_time:'2026-10-09T00:00:00Z'}])assert(!analyticsQueryMatches(context,{...context,...change}));
 const value=report();value.filters.from_time='2026-10-09T08:00:00+08:00';value.filters.to_time='2026-10-10T00:00:00Z';
 const timed=analyticsQueryContext(value);assert.equal(timed.from_time,'2026-10-09T00:00:00.000Z');assert(analyticsQueryMatches(timed,{...timed,from_time:new Date(timed.from_time)}));
});
test('malformed retained filters and secret/extra filter fields fail closed without coercion',()=>{
 for(const value of [null,[],{}, {...report(),site_id:'../../secret'}, {...report(),filters:{...report().filters,password:'secret'}}])assert.equal(analyticsQueryContext(value),undefined);
 for(const change of [{status_code:'503'},{status_code:99},{status_code:600},{status_code:200.5},{only_bots:'true'},{min_seconds:Infinity},{min_seconds:-1},{min_seconds:3601},{search:'汉'.repeat(86)},{from_time:'2026-02-30T00:00:00Z'},{from_time:'2026-10-10T00:00:00Z',to_time:'2026-10-09T00:00:00Z'}])assert.equal(analyticsQueryContext({...report(),filters:{...report().filters,...change}}),undefined);
});
test('UI separates server/catalog failure, resets health on account change, and visibly binds result context',()=>{
 const app=readFileSync(new URL('../web/src/App.vue',import.meta.url),'utf8');
 assert.match(app,/overviewReadError.value = ""; overviewReceivedAt.value = null/);assert.match(app,/permitted:canReadPath\(accessPlan.value,"\/overview"\)/);
 assert.doesNotMatch(app,/if \(error.value\) return \{ label: "连接异常"/);assert.doesNotMatch(app,/if \(!appRegistry.value.catalog.apps.length\) errors.push/);
 assert.match(app,/if \(epoch === accessEpoch && session === csrf.value\) overviewReadError.value/);
 const refresh=app.slice(app.indexOf('async function refresh(forceRegistry'),app.indexOf('async function login()'));
 assert(refresh.indexOf('void refreshOverview()')<refresh.indexOf('refreshing ||'));
 assert.doesNotMatch(refresh,/permittedRead<Overview>/);
 assert.match(app,/:class="\['server-status', healthState.kind\]"/);assert.doesNotMatch(app,/overview\?\.nginx_active \? "服务器在线"/);
 const manager=readFileSync(new URL('../web/src/AppModuleManager.vue',import.meta.url),'utf8');
 assert.match(manager,/restoreAnalyticsQuery\(analyticsQueryContext\(report.value\),sites.value\)/);assert.match(manager,/筛选条件已修改，尚未刷新/);
 const component=readFileSync(new URL('../web/src/AnalyticsQueryContext.vue',import.meta.url),'utf8');assert.match(component,/已返回报告的查询范围/);assert.doesNotMatch(component,/v-html|localStorage|sessionStorage/);
});
test('independent health read gate prevents duplicate polls and old-account release races',()=>{
 const gate=new EpochReadGate();const old=gate.acquire(1);assert.equal(typeof old,'function');assert.equal(gate.acquire(1),undefined);
 const fresh=gate.acquire(2);assert.equal(typeof fresh,'function');old();old();assert.equal(gate.acquire(2),undefined);
 fresh();assert.equal(typeof gate.acquire(2),'function');
});
test('pending unrelated reads cannot block health polling; failure releases the next poll',async()=>{
 const gate=new EpochReadGate();let unblock;const unrelated=new Promise(resolve=>{unblock=resolve});let settled=false;void unrelated.then(()=>{settled=true});
 const release=gate.acquire(3);await Promise.resolve();assert.equal(settled,false);release();
 const next=gate.acquire(3);assert.equal(typeof next,'function');try{await Promise.reject(new Error('executor deadline'));}catch{}finally{next();}
 const recovery=gate.acquire(3);assert.equal(typeof recovery,'function');recovery();assert.equal(settled,false);unblock();await unrelated;
});
