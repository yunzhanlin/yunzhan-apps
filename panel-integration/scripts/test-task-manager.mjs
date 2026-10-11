import {test} from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import ts from '../web/node_modules/typescript/lib/typescript.js';
import {taskSelection,taskTerminationNotice,taskProcessColumns,taskProcessRows} from '../web/src/taskManager.ts';
test('process columns prioritize operational identity and omit permission/sampling flags without mutating the report',()=>{
 const row={can_terminate:false,cpu_available:false,io_available:false,cpu_percent:null,memory:100,name:'worker',pid:42,read_rate:null,write_rate:null,state:'S',managed:true,start_time:123,token:'never-display'};
 assert.deepEqual(taskProcessColumns([row]),['name','pid','cpu_percent','memory','read_rate','write_rate','state','managed']);
 assert.equal(row.start_time,123);assert.equal(row.can_terminate,false);
 for(const invalid of [null,undefined,{},'processes'])assert.deepEqual(taskProcessColumns(invalid),[]);
 assert.deepEqual(taskProcessColumns([{name:'worker',pid:42},null,[]]),['name','pid']);
});
test('snapshot filter is bounded, case-insensitive and cannot create authorization or adopt an out-of-snapshot ticket',()=>{
 const root={pid:2,name:'RootWorker',start_time:100,managed:true,can_terminate:false};
 const app={pid:42,name:'NodeHTTP',start_time:101,managed:true,can_terminate:true};
 const foreign={pid:142,name:'Foreign',start_time:102,managed:false,can_terminate:false};
 const rows=[root,app,foreign];assert.deepEqual(taskProcessRows(rows,'  node  '),[app]);assert.equal(taskProcessRows(rows,'42').length,2);
 assert.deepEqual(taskProcessRows(rows,'',true),[root,app]);assert.deepEqual(taskProcessRows(rows,'', 'true'),rows);
 assert.equal(taskSelection(taskProcessRows(rows,'root')[0]),undefined);assert.strictEqual(taskProcessRows(rows,'node')[0],app);assert.deepEqual(taskSelection(app),{pid:42,start_time:101});
 assert.deepEqual(taskProcessRows(rows,'not present'),[]);assert.deepEqual(taskProcessRows(null),[]);
 const large=[...Array(500).fill(root),app];assert.equal(taskProcessRows(large).length,500);assert.deepEqual(taskProcessRows(large,'node'),[]);
 assert.deepEqual(rows,[root,app,foreign]);
});
test('selection only adopts a complete current non-root authorized process ticket',()=>{
 const row={pid:42,start_time:12345,managed:true,can_terminate:true};
 const selected=taskSelection(row);assert.deepEqual(selected,{pid:42,start_time:12345});assert(Object.isFrozen(selected));
 for(const value of [null,[],{}, {...row,pid:1},{...row,pid:'42'},{...row,pid:2147483648},{...row,start_time:0},{...row,start_time:Number.MAX_SAFE_INTEGER+1},{...row,managed:false},{...row,can_terminate:false}])assert.equal(taskSelection(value),undefined);
});
test('signal reply binds the original PID and does not claim exit',()=>{
 const reply={pid:42,signal:'SIGTERM',signal_accepted:true,exit_verified:false};
 assert.match(taskTerminationNotice(reply,42),/不能据此认定进程已退出/);
 for(const value of [null,[],{}, {...reply,pid:43},{...reply,pid:'42'},{...reply,signal:'SIGKILL'},{...reply,signal_accepted:false},{...reply,exit_verified:true},{...reply,secret:'extra'}, {pid:42,signal:'SIGTERM'}])assert.throws(()=>taskTerminationNotice(value,42),/可能已发送/);
});
const source=readFileSync(new URL('../web/src/AppModuleManager.vue',import.meta.url),'utf8');
test('material task snapshot update has an independent app patch version and translated PM2 runtime identity',()=>{
 const definitions=readFileSync(new URL('../internal/core/app_modules.go',import.meta.url),'utf8');
 assert.match(definitions,/case "task-manager":\s+version = "1\.2\.1"/);
 const report=readFileSync(new URL('../web/src/AppModuleReport.vue',import.meta.url),'utf8');
 assert.match(report,/pm2_version:\s*"PM2 版本"/);
});
test('actual component row selection clears prior identity on root/unknown rows and does not dispatch',()=>{
 const actual=source.slice(source.indexOf('function selected('),source.indexOf('function inputBody('));
 const js=ts.transpileModule(actual,{compilerOptions:{target:ts.ScriptTarget.ES2022}}).outputText;
 for(const safe of [true,false]){
  const notices=[];const bindings={clearWriteOnlyFields:()=>{},definition:{value:{id:'task-manager'}},form:{value:{pid:999,start_time:999}},activeTab:{value:'terminate'},taskSelection,ElMessage:{info:v=>notices.push(v)}};
  new Function('bindings','with(bindings){'+js+';return selected;}')(bindings)({pid:42,start_time:12345,managed:true,can_terminate:safe});
  assert.deepEqual(bindings.form.value,safe?{pid:42,start_time:12345}:{pid:0,start_time:0});assert.equal(bindings.activeTab.value,safe?'terminate':'processes');assert.equal(notices.length,1);
 }
});
test('actual component terminate uses one POST, validates before report and always clears current selection',async()=>{
 const actual=source.slice(source.indexOf('async function execute('),source.indexOf('async function reviewRemoteTicket('));
 const js=ts.transpileModule(actual,{compilerOptions:{target:ts.ScriptTarget.ES2022}}).outputText;
 for(const mode of ['accepted','wrong-pid','lost-reply','closed']){
  const calls=[],notices=[],original={pid:42,start_time:12345};
  const bindings={definition:{value:{id:'task-manager',actions:['run','terminate'],fields:[{key:'pid',kind:'identity'},{key:'start_time',kind:'identity'}]}},installedUnknown:{value:false},busy:{value:false},error:{value:''},canExecutePHP:()=>true,idsAccessGeneration:1,inputBody:()=>({...original}),form:{value:{...original}},report:{value:undefined},taskTerminationNotice,integrityModule:{value:false},ElMessage:{info:v=>notices.push(v),success:()=>assert.fail('signal is not an exit or green success receipt')},props:{api:async(path,method,body)=>{calls.push({path,method,body});assert.deepEqual(body,original);if(mode==='lost-reply')throw Error('reply unavailable; signal unknown');if(mode==='closed')bindings.idsAccessGeneration++;return{pid:mode==='wrong-pid'?43:42,signal:'SIGTERM',signal_accepted:true,exit_verified:false};}},setReport:value=>{bindings.report.value=value;}};
  await new Function('bindings','with(bindings){'+js+';return execute;}')(bindings)('terminate');
  assert.equal(calls.length,1);assert.equal(calls[0].path,'/app-modules/task-manager/terminate');assert.equal(calls[0].method,'POST');assert.equal(bindings.busy.value,false);
  if(mode==='accepted'){assert.equal(notices.length,1);assert.equal(bindings.report.value.exit_verified,false);assert.equal(bindings.error.value,'');}
  else {assert.equal(notices.length,0);assert.equal(bindings.report.value,undefined);if(mode!=='closed')assert.match(bindings.error.value,/无法完整核对|unavailable/);}
  assert.deepEqual(bindings.form.value,mode==='closed'?original:{pid:0,start_time:0});
 }
});
test('signed build includes guards and truthful partial/unknown/signal UI messages',()=>{
 assert.match(readFileSync(new URL('../packaging/build-release.sh',import.meta.url),'utf8'),/test-task-manager\.mjs/);
 for(const text of ['2000 条采样边界','连接数据暂不可核对','尚未核对退出'])assert(source.includes(text));
 const definitions=readFileSync(new URL('../internal/core/app_modules.go',import.meta.url),'utf8');assert.match(definitions,/"原进程 PID（从当前列表选择）", "identity"/);
 // Template/source wiring, not a claim of actual DOM, kernel or Core delivery.
});
test('actual report formatting preserves unknown counters, genuine zero and translated signal/limit labels',()=>{
 const report=readFileSync(new URL('../web/src/AppModuleReport.vue',import.meta.url),'utf8');
 const actual=report.slice(report.indexOf('function format('),report.indexOf('function rows('));
 const js=ts.transpileModule(actual,{compilerOptions:{target:ts.ScriptTarget.ES2022}}).outputText;
 const props={id:'task-manager',report:{connections_available:false}};
 const format=new Function('props',js+';return format;')(props);
 for(const key of ['cpu_percent','read_rate','write_rate']) {
  const flag=key==='cpu_percent'?'cpu_available':'io_available';
  for(const bad of [null,undefined,'0',NaN,Infinity,-1])assert.equal(format(key,bad,{[flag]:true}),'未知');
  assert.equal(format(key,0,{[flag]:false}),'未知');assert.equal(format(key,0),'未知');
  assert.notEqual(format(key,0,{[flag]:true}),'未知');
 }
 assert.equal(format('connections',''),'未取得，当前状态未知');props.report.connections_available=true;assert.equal(format('connections',''),'');
 for(const label of ['信号发送已接受','退出已核对','进程采样上限','进程展示上限','本次展示进程数','CPU 速率可核对','I/O 速率可核对'])assert(report.includes(label));
 assert(!report.includes('不能据此认定网站没有风险'));
});
test('actual task table no longer silently truncates 500 returned rows to the generic 200',()=>{
 const report=readFileSync(new URL('../web/src/AppModuleReport.vue',import.meta.url),'utf8');
 const js=ts.transpileModule(report.slice(report.indexOf('function rows('),report.indexOf('function columns(')),{compilerOptions:{target:ts.ScriptTarget.ES2022}}).outputText;
 const input=Array.from({length:501},(_,i)=>({pid:i+1,start_time:100}));
 assert.equal(new Function('props',js+';return rows;')({id:'task-manager'})(input).length,500);
 assert.equal(new Function('props',js+';return rows;')({id:'site-diagnosis'})(input).length,200);
});
test('actual report table uses snapshot filtering and ordered columns, with no request or signal side effects',()=>{
 const report=readFileSync(new URL('../web/src/AppModuleReport.vue',import.meta.url),'utf8');
 const actual=report.slice(report.indexOf('function rows('),report.indexOf('function columns('));const js=ts.transpileModule(actual,{compilerOptions:{target:ts.ScriptTarget.ES2022}}).outputText;
 const row={pid:42,name:'NodeHTTP',start_time:100,managed:true,can_terminate:true,cpu_available:false,cpu_percent:null};
 const bindings={props:{id:'task-manager'},taskProcessRows,taskQuery:{value:'node'},taskManagedOnly:{value:true}};
 const rows=new Function(...Object.keys(bindings),js+';return rows;')(...Object.values(bindings));assert.deepEqual(rows([row], 'processes'),[row]);
 bindings.taskQuery.value='missing';assert.deepEqual(rows([row],'processes'),[]);assert.deepEqual(rows([row],'history'),[row]);
 assert(report.includes(':data="rows(values,key)"'));assert(report.includes('return taskProcessColumns(values)'));assert(report.includes('仅筛选已返回快照，不重新采样，不代表全部进程'));assert(report.includes('包括不可终止项'));
 assert.doesNotMatch(actual,/fetch\(|props\.api|execute\(|terminateTask/);
});
test('actual monitoring helpers expose unknown rates, reject reused identity and label bounded snapshots',()=>{
 const monitor=readFileSync(new URL('../web/src/MonitoringManager.vue',import.meta.url),'utf8');
 const actual=monitor.slice(monitor.indexOf('function processCPU('),monitor.indexOf('const processSamplingNote'))+monitor.slice(monitor.indexOf('const bytes = ('),monitor.indexOf('const percent ='));
 const js=ts.transpileModule(actual,{compilerOptions:{target:ts.ScriptTarget.ES2022}}).outputText;
 const {processCPU,processIO,sameProcessIdentity,processSnapshotLabel}=new Function(js+';return {processCPU,processIO,sameProcessIdentity,processSnapshotLabel};')();
 const row={pid:42,name:'same',start_time:100,cpu_percent:0,read_rate:0,write_rate:0,cpu_available:true,io_available:true};
 assert.equal(processCPU(row),'0.0%');assert.equal(processIO(row,'read_rate'),'0 B/s');
 for(const value of [NaN,Infinity,-1]){assert.equal(processCPU({...row,cpu_percent:value}),'未知');assert.equal(processIO({...row,read_rate:value},'read_rate'),'未知');}
 assert.equal(processCPU({...row,cpu_available:false}),'未知');assert.equal(processIO({...row,io_available:false},'write_rate'),'未知');
 assert(sameProcessIdentity(row,{...row}));
 for(const current of [{...row,start_time:101},{...row,start_time:0},{...row,start_time:'100'},{...row,start_time:undefined},{...row,pid:43},{...row,name:'other'}])assert(!sameProcessIdentity(current,row));
 const complete={processes:[row],partial:false,display_limited:false,sample_limit:2000,display_limit:500,sampled_processes:1,displayed_processes:1};
 assert.match(processSnapshotLabel(complete),/本次采样 1 条，返回 1 条/);
 const limited={...complete,processes:Array(500).fill(row),sampled_processes:501,displayed_processes:500,partial:true,display_limited:true};
 assert.match(processSnapshotLabel(limited),/部分结果/);
 for(const bad of [undefined,{}, {...complete,displayed_processes:500},{...complete,sampled_processes:NaN},{...limited,partial:false}])assert.match(processSnapshotLabel(bad),/暂不可核对/);
 assert(monitor.includes('sameProcessIdentity(item,processDetail.value!)'));assert(monitor.includes('按当前排序展示前 20 条'));
 // Real component functions and template wiring, not a native/DOM acceptance.
});
test('actual monitor refresh retains a stale detail instead of adopting a reused PID or certifying failed reads',async()=>{
 const monitor=readFileSync(new URL('../web/src/MonitoringManager.vue',import.meta.url),'utf8');
 assert(monitor.includes('当前启动身份或进程状态无法核对，以下仅是最后一次记录'));
 assert(!monitor.includes('当前采样中未找到该进程，以下为最后一次记录'));
 const actual=monitor.slice(monitor.indexOf('function sameProcessIdentity('),monitor.indexOf('function processSnapshotLabel('))+monitor.slice(monitor.indexOf('async function refresh('),monitor.indexOf('function editSettings('));
 const js=ts.transpileModule(actual,{compilerOptions:{target:ts.ScriptTarget.ES2022}}).outputText;
 const original={pid:42,name:'same',start_time:100,memory:4096};
 for(const mode of ['valid','reused','failed']) {
  const row={...original,start_time:mode==='reused'?101:100,memory:8192};
  const bindings={props:{api:async(path)=>{if(mode==='failed')throw Error('actual fixture read failed');if(path.startsWith('/monitor/history'))return {points:[],settings:{}};if(path==='/monitor/alerts')return{alerts:[],events:[]};if(path==='/monitor/services')return{services:[]};return {processes:[row],tcp_connections:null};}},range:{value:'1h'},points:{value:[]},settings:{value:{}},alerts:{value:[]},events:{value:[]},services:{value:[]},processes:{value:[original]},processSnapshot:{value:undefined},processSampleStale:{value:true},processDetailOpen:{value:true},processDetail:{value:{...original}},processDetailStale:{value:false},processDetailAt:{value:0},tcpConnections:{value:null},error:{value:''}};
  await new Function('bindings','with(bindings){'+js+';return refresh;}')(bindings)();
  assert.equal(bindings.processSampleStale.value,mode==='failed');assert.equal(bindings.processDetailStale.value,mode!=='valid');
  assert.equal(bindings.processDetail.value.start_time,100);assert.equal(bindings.processDetail.value.memory,mode==='valid'?8192:4096);
  if(mode==='failed')assert.match(bindings.error.value,/read failed/);
 }
});
