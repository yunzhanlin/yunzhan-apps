import {test} from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import ts from '../web/node_modules/typescript/lib/typescript.js';
const source=readFileSync(new URL('../web/src/AppModuleManager.vue',import.meta.url),'utf8');
const reportSource=readFileSync(new URL('../web/src/AppModuleReport.vue',import.meta.url),'utf8');
const compile=file=>ts.transpileModule(readFileSync(new URL('../web/src/'+file,import.meta.url),'utf8'),{compilerOptions:{target:ts.ScriptTarget.ES2022,module:ts.ModuleKind.ESNext}}).outputText;
const resourcesURL='data:text/javascript;base64,'+Buffer.from(compile('resourceMetrics.ts')).toString('base64');
const {resourcePercent,resourceSeries}=await import(resourcesURL);
const dailyJS=compile('dailyReportView.ts').replace(/(['"])\.\/resourceMetrics\1/g,JSON.stringify(resourcesURL));
const {dailySummary,dailySnapshot,dailyWorkerMessage}=await import('data:text/javascript;base64,'+Buffer.from(dailyJS).toString('base64'));
test('actual dedicated daily view distinguishes missing counters from observed zero and directory inventory',()=>{
 const keys=['sites','running_sites','certificates_due_14_days','failed_site_jobs','failed_runtime_jobs','audit_events_24h'];
 assert(dailySummary(Object.fromEntries(keys.map(key=>[key,0]))).counts.every(v=>v.value===0));
 assert.equal(dailySummary({sites:0}).counts.filter(v=>v.value===null).length,5);
 for(const v of [null,NaN,-1,1.5,'0',Infinity,1e9+1])assert.equal(dailySummary({sites:v}).counts[0].value,null);
 assert.equal(dailySnapshot({reports:[],report_contents_verified:false}),false);
 assert.equal(dailySnapshot({history:[]}),false);assert(dailySnapshot({sites:0}));
 assert.match(reportSource,/<DailyReportSummary v-else-if="id==='daily-report' && dailySnapshot\(report\)"/);
 assert.match(readFileSync(new URL('../web/src/DailyReportSummary.vue',import.meta.url),'utf8'),/缺失数据不表示零值/);
 assert.match(reportSource,/report.report_contents_verified===false/);
});
test('actual resource presentation preserves unknown first samples, explicit zero and chart gaps',()=>{
 for(const v of [null,undefined,NaN,Infinity,-1,101,'0'])assert.equal(resourcePercent(v,true),null);
 assert.equal(resourcePercent(0,true,true),0);assert.equal(resourcePercent(0,undefined,true),null);assert.equal(resourcePercent(50,false),null);assert.equal(resourcePercent(50,'true'),null);assert.equal(resourcePercent(50),50);
 assert.deepEqual(resourceSeries([0,10,null,20,30]),['0,180 180,164','540,148 720,132']);assert.deepEqual(resourceSeries([null,null]),[]);assert.deepEqual(resourceSeries([0]),[]);
 const view=dailySummary({resources:{cpu_percent:0,memory_percent:0,memory_available:true,disk_available:4096,disk_percent:50,disk_percent_available:false}});
 assert.deepEqual(view.metrics.map(v=>v.value),[null,0,null]);
 const app=readFileSync(new URL('../web/src/App.vue',import.meta.url),'utf8');assert.match(app,/v-for="\(points,index\) in series\('cpu'\)"/);assert.doesNotMatch(app,/Number\(percent\(overview/);
});
test('actual daily traffic and security view refuses malformed or partial metadata as complete healthy data',()=>{
 const day={date:'2026-10-11',requests:0,bytes:0};assert.equal(dailySummary({traffic:{days:[day]}}).trafficDays.length,1);
 for(const days of [[day,day],[{...day,date:'2026-02-31'}],[{...day,requests:-1}],[{...day,bytes:'0'}]])assert.equal(dailySummary({traffic:{days}}).trafficDays,undefined);
 assert(dailySummary({traffic:{days:[],partial:true}}).trafficPartial);
 assert.equal(dailySummary({security:[{id:'nginx-waf',installed:true,healthy:true,state_unknown:true}]}).security[0].state,'待核对');
 assert.equal(dailySummary({security:[{id:'nginx-waf',installed:false,healthy:true}]}).security[0].state,'未安装');
});
test('actual worker status presentation requires a live fresh observation and never certifies delivery',()=>{
 for(const v of [null,{}, {running:true,fresh:false,state:'saved',report_day:'2026-10-11'},{running:false,fresh:true,state:'saved',report_day:'2026-10-11'},{running:true,fresh:true,state:'generation_failed'},{running:true,fresh:true,state:'saved_partial'},{running:true,fresh:true,state:'saved',report_day:'2026-02-31'}])assert.equal(dailyWorkerMessage(v).observed,false);
 const now=Date.parse('2026-10-11T12:00:00Z'),value={running:true,fresh:true,state:'saved',report_day:'2026-10-11',checked_at:'2026-10-11T12:00:00Z'};
 const known=dailyWorkerMessage(value,now);assert(known.observed);assert.match(known.message,/不代表邮件或 Webhook 已送达/);
 assert(dailyWorkerMessage(value,now+130000).observed);assert(!dailyWorkerMessage(value,now+130001).observed);assert(!dailyWorkerMessage(value,now-1).observed);
 for(const at of [undefined,null,'invalid','2026-02-31T12:00:00Z','2026-10-11T12:00:00.000Z','2026-10-11T12:00:00+00:00'])assert(!dailyWorkerMessage({...value,checked_at:at},now).observed);
 for(const clock of [NaN,Infinity,-Infinity])assert(!dailyWorkerMessage(value,clock).observed);
 const manager=readFileSync(new URL('../web/src/AppModuleManager.vue',import.meta.url),'utf8');assert.match(manager,/dailyWorkerMessage\(dailyWorker.value,reportExportNow.value\)/);assert.match(manager,/reportExportNow.value=Date.now\(\)/);
});
test('actual module actions refuse an unknown install identity before any dispatch',async()=>{
 for(const [name,next,args] of [['execute','async function reviewRemoteTicket',['run']],['uninstall','async function install',[]],['install','defineExpose',[]]]){
  const start=source.indexOf('async function '+name+'('),end=source.indexOf(next,start);assert(start>=0&&end>start);
  const js=ts.transpileModule(source.slice(start,end),{compilerOptions:{target:ts.ScriptTarget.ES2022}}).outputText;
  const bindings={definition:{value:{id:'task-manager'}},installedUnknown:{value:true},installed:{value:false},busy:{value:false},canExecutePHP:()=>true,props:{api:()=>assert.fail('unknown record dispatched'),onInstall:()=>assert.fail('unknown record installed')}};
  await new Function('bindings','with(bindings){'+js+';return '+name+';}')(bindings)(...args);
  assert.equal(bindings.busy.value,false);
 }
});
test('unknown record presentation is distinct from known uninstalled and disables install',()=>{
 assert(source.includes('安装状态待核对'));
 assert(source.includes('不能据此认定未安装'));
 assert.match(source,/:disabled="busy \|\| installedUnknown"/);
 assert.match(source,/installedUnknown.value = !page.status \|\| page.status.id !== id/);
 assert.match(source,/typeof page.status.installed !== 'boolean'/);
 assert.match(source,/installed.value = !installedUnknown.value && page.status.installed === true/);
});
test('actual history refresh clears stale result, preserves readonly query and ignores late account replies',async()=>{
 const start=source.indexOf('async function refreshHistory('),end=source.indexOf('function tabChanged(',start);assert(start>=0&&end>start);
 const js=ts.transpileModule(source.slice(start,end),{compilerOptions:{target:ts.ScriptTarget.ES2022}}).outputText;
 const make=(api)=>{const bindings={definition:{value:{id:'file-monitor'}},busy:{value:false},historyOffset:{value:50},historyLimit:{value:50},historyFilter:{value:{search:'literal%_marker',site_id:'a'.repeat(32)}},history:{value:{total:99,stale:true}},error:{value:''},scopedHistory:{value:true},visible:{value:true},idsAccessGeneration:1,props:{api}};return {bindings,run:new Function('bindings','with(bindings){'+js+';return refreshHistory;}')(bindings)};};
 let resolve;
 const fixture=make((url,...args)=>{assert(url.startsWith('/app-modules/file-monitor/history?'));assert(url.includes('search=literal%25_marker'));assert.equal(args.length,0);return new Promise(r=>resolve=r);});
 const pending=fixture.run(true);assert.equal(fixture.bindings.history.value,undefined);assert.equal(fixture.bindings.historyOffset.value,0);
 fixture.bindings.idsAccessGeneration++;resolve({total:1,read_only:true});await pending;assert.equal(fixture.bindings.history.value,undefined);assert.equal(fixture.bindings.busy.value,false);
 const failed=make(async()=>{throw new Error('original evidence cannot be verified');});await failed.run();assert.equal(failed.bindings.history.value,undefined);assert.match(failed.bindings.error.value,/original evidence/);
 const success=make(async()=>({total:2,read_only:true}));await success.run();assert.deepEqual(success.bindings.history.value,{total:2,read_only:true});
});
test('actual fresh business result clears report warning while untrusted saved report is withheld',()=>{
 const start=source.indexOf('function setReport('),end=source.indexOf('async function show(',start);assert(start>=0&&end>start);
 const js=ts.transpileModule(source.slice(start,end),{compilerOptions:{target:ts.ScriptTarget.ES2022}}).outputText;
 const remembered=[],context={generation:1,installationID:'d'.repeat(32)};
 const bindings={reportStateUnknown:{value:true},report:{value:undefined},definition:{value:{id:'daily-report'}},platformHealthSnapshot:{remember:(value,scope)=>remembered.push({value,scope})},platformSnapshotContext:()=>context};
 const setReport=new Function('bindings','with(bindings){'+js+';return setReport;}')(bindings);setReport({result:{fresh:true}});
 assert.equal(bindings.reportStateUnknown.value,false);assert.deepEqual(bindings.report.value,{fresh:true});
 assert.deepEqual(remembered,[],'Other modules must not enter the platform snapshot cache');
 bindings.definition.value.id='platform-ops';setReport({result:{hosts:[],checked_at:'2026-10-15T20:00:00Z',scope:'fixture'}});assert.deepEqual(remembered,[{value:bindings.report.value,scope:context}]);
 assert.match(source,/reportStateUnknown.value = page.report_state_unknown === true/);
 assert.match(source,/!installedUnknown.value && !reportStateUnknown.value && page.report !== null/);
 assert.match(source,/原报告待核对，未据此认定执行成功、失败或没有执行/);
 assert.match(source,/reportStateUnknown.value \? undefined : initialModuleInspection/);
});
