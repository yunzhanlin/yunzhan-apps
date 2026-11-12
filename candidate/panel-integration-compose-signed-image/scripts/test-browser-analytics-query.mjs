import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {createRequire} from 'node:module';
import ts from '../web/node_modules/typescript/lib/typescript.js';
import {browserAnalyticsQuery,browserAnalyticsQueryParams,browserAnalyticsReportMatches,browserAnalyticsQueryFence} from '../web/src/browserAnalyticsQuery.ts';

const site='a'.repeat(32),other='b'.repeat(32);
const start=new Date('2026-11-01T00:00:00Z'),end=new Date('2026-11-02T00:00:00Z');
test('an unfinished or reversed time range cannot silently become a default query',()=>{
 for(const pair of[[start,null],[null,end],[new Date(NaN),end],[start,'2026-11-02'],[end,start],[start,start]]){
  const query=browserAnalyticsQuery(site,...pair);assert(query.problem);assert.throws(()=>browserAnalyticsQueryParams(query));
 }
 const empty=browserAnalyticsQuery(site,null,undefined);assert.equal(empty.problem,'');assert.equal(browserAnalyticsQueryParams(empty).toString(),'');
 assert(browserAnalyticsQuery('',start,end).problem);assert(browserAnalyticsQuery('../other',start,end).problem);
});
test('picker milliseconds normalize to the actual collector second without mutating the picker dates',()=>{
 const a=new Date('2026-11-01T08:00:00.999+08:00'),b=new Date('2026-11-02T08:00:00.001+08:00');
 const query=browserAnalyticsQuery(site,a,b);assert.equal(query.problem,'');assert.equal(query.from,start.toISOString());assert.equal(query.to,end.toISOString());
 assert.equal(a.getMilliseconds(),999);assert.equal(b.getMilliseconds(),1);assert.equal(query.key,browserAnalyticsQuery(site,start,end).key);
 assert.notEqual(query.key,browserAnalyticsQuery(other,start,end).key);assert.notEqual(query.key,browserAnalyticsQuery(site,null,null).key);
 assert(Object.isFrozen(query));
});
test('an explicit report must carry the same actual instants as its selected range',()=>{
 const query=browserAnalyticsQuery(site,start,end);
 assert(browserAnalyticsReportMatches(query,{from:'2026-11-01T08:00:00+08:00',to:'2026-11-02T00:00:00Z'}));
 for(const report of[null,[],{},{from:'2026-11-01',to:end.toISOString()},{from:end.toISOString(),to:start.toISOString()},{from:'2026-10-31T00:00:00Z',to:end.toISOString()},{from:start.toISOString(),to:'2026-11-03T00:00:00Z'}])assert.equal(browserAnalyticsReportMatches(query,report),false);
 assert(browserAnalyticsReportMatches(browserAnalyticsQuery(site,null,null),{from:start.toISOString(),to:end.toISOString()}));
 assert.equal(browserAnalyticsReportMatches(browserAnalyticsQuery(site,start,null),{from:start.toISOString(),to:end.toISOString()}),false);
});
test('a late request is obsolete even if inputs return A to B to A',async()=>{
 const fence=browserAnalyticsQueryFence(),a=browserAnalyticsQuery(site,start,end),b=browserAnalyticsQuery(other,start,end);
 const first=fence.capture(a.key);let resolve;const pending=new Promise(r=>resolve=r);
 fence.invalidate();const second=fence.capture(b.key);fence.invalidate();const third=fence.capture(a.key);
 resolve('old report');await pending;
 assert.equal(fence.current(first,a.key),false);assert.equal(fence.current(second,b.key),false);assert(fence.current(third,a.key));
 assert.equal(fence.current(third,b.key),false);fence.invalidate();assert.equal(fence.current(third,a.key),false);
});

const require=createRequire(new URL('../web/package.json',import.meta.url));
const {parse,compileScript}=require('@vue/compiler-sfc');
const {createRenderer,defineComponent,h,nextTick}=require('vue');
const source=readFileSync(new URL('../web/src/AnalyticsWorkspace.vue',import.meta.url),'utf8');
const compiled=compileScript(parse(source).descriptor,{id:'qa-browser-analytics-query',inlineTemplate:true});
let js=ts.transpileModule(compiled.content,{compilerOptions:{target:ts.ScriptTarget.ES2022,module:ts.ModuleKind.ESNext}}).outputText;
js=js.replace(/from ['"]vue['"]/g,'from '+JSON.stringify(new URL('../web/node_modules/vue/index.mjs',import.meta.url).href));
for(const name of['analyticsHTMLState','randomId','browserAnalyticsQuery'])js=js.replace(new RegExp('from [\'"]\\./'+name+'[\'"]','g'),'from '+JSON.stringify(new URL('../web/src/'+name+'.ts',import.meta.url).href));
for(const name of['AnalyticsHTMLEngine','AnalyticsPerformanceReport','AnalyticsPeriodComparison','AnalyticsHeatmapOverlay'])js=js.replace(new RegExp('import '+name+' from [\'"]\\./'+name+'\\.vue[\'"];?'),'const '+name+'={render(){return null;}};');
const component=(await import('data:text/javascript;base64,'+Buffer.from(js).toString('base64'))).default;
const flush=async()=>{await nextTick();await Promise.resolve();await nextTick();};
function node(type,text=''){return {type,text,props:{},children:[],parent:null};}
function harness(installedVersion='2.4.1'){
 const requests=[],warnings=[];
 const insert=(child,parent,anchor=null)=>{if(child.parent){const n=child.parent.children.indexOf(child);if(n>=0)child.parent.children.splice(n,1);}child.parent=parent;const at=anchor?parent.children.indexOf(anchor):-1;parent.children.splice(at<0?parent.children.length:at,0,child);};
 const renderer=createRenderer({
  createElement:type=>node(type),createText:text=>node('#text',text),createComment:text=>node('#comment',text),
  setText:(n,text)=>{n.text=text;},setElementText:(n,text)=>{n.children=[];n.text=text;},
  patchProp:(n,key,old,value)=>{n.props[key]=value;},insert,
  remove:n=>{if(n.parent){const i=n.parent.children.indexOf(n);if(i>=0)n.parent.children.splice(i,1);}n.parent=null;},
  parentNode:n=>n.parent,nextSibling:n=>n.parent?.children[n.parent.children.indexOf(n)+1]||null,
  insertStaticContent:(text,parent,anchor)=>{const n=node('#static',text);insert(n,parent,anchor);return[n,n];},
 });
 const root=node('root');
 const api=async(path,method)=>{
  assert(!method||method==='GET','Source query tests must not invoke a mutation');
  if(path.endsWith('/config'))return {site_id:site,key:'c'.repeat(32),enabled:false,clicks:false,retention_days:30,revision:1};
  return new Promise((resolve,reject)=>requests.push({path,resolve,reject}));
 };
 const app=renderer.createApp(component,{api,installed:true,installedVersion,sites:[{id:site,name:'Owned query unit site',domain:'owned.example.test'}]});
 app.config.warnHandler=(msg)=>warnings.push(msg);
 for(const name of['el-select','el-option','el-date-picker','el-button','el-tabs','el-tab-pane','el-descriptions','el-descriptions-item','el-table','el-form','el-form-item','el-input','el-input-number','el-switch','el-empty','el-alert','el-pagination']){
  app.component(name,defineComponent({inheritAttrs:false,setup(_,{attrs,slots}){return()=>h(name,{...attrs},slots.default?.());}}));
 }
 app.component('el-table-column',defineComponent({inheritAttrs:false,setup(_,{attrs}){return()=>h('el-table-column',{...attrs});}}));
 app.directive('loading',{});app.mount(root);
 const all=(type)=>{const result=[];const walk=n=>{if(n.type===type)result.push(n);for(const c of n.children)walk(c);};walk(root);return result;};
 const text=n=>n.text+n.children.map(text).join('');
 const button=label=>{const n=all('el-button').find(n=>text(n).trim()===label);assert(n,'Button missing: '+label);return n;};
 const update=(n,value)=>{const fn=n.props['onUpdate:modelValue'];assert.equal(typeof fn,'function');fn(value);};
 return {requests,all,text,button,update,root,
  async select(){update(all('el-select').find(n=>n.props['aria-label']==='统计网站'),site);await flush();},
  async range(a,b){
   const inputs=all('el-date-picker'),legacy=inputs.find(n=>n.props.type==='datetimerange');
   if(legacy)update(legacy,a===null&&b===null?null:[a,b]);
   else {update(inputs.find(n=>n.props.id==='analytics-report-from'),a);update(inputs.find(n=>n.props.id==='analytics-report-to'),b);}
   await flush();
  },
  async resolve(index,pv=11,overrides={}){
   const request=requests[index];assert(request);const url=new URL(request.path,'http://owned.test');
   const from=url.searchParams.get('from')||start.toISOString(),to=url.searchParams.get('to')||end.toISOString();
   request.resolve({source:'browser-telemetry',from,to,partial:false,sampled_events:1,overview:{pv,uv:1,sessions:1,active_visitors:0,clicks:0,bounce_rate:0,avg_engagement_seconds:0,unique_network_peers:1},pages:[],sources:[],browsers:[],devices:[],entry_pages:[],exit_pages:[],hours:[],campaigns:[],sessions:[],heatmap:[],performance:{},limitations:[],...overrides});await flush();
  },
  stop(){app.unmount();assert.deepEqual(warnings,[]);},
 };
}
test('actual Vue date edits hide the old report and block its export until the current query completes',async()=>{
 const ui=harness();try{
  await ui.select();assert.equal(ui.requests.length,1);await ui.resolve(0,11);
  assert(ui.all('strong').some(n=>ui.text(n)==='11'));assert.equal(ui.button('导出统计').props.disabled,false);
  const a=new Date('2026-11-03T00:00:00Z'),b=new Date('2026-11-04T00:00:00Z');await ui.range(a,b);
  assert.equal(ui.requests.length,1);assert.equal(ui.all('strong').some(n=>ui.text(n)==='11'),false,'Previous report remained visible under new dates');
  assert.equal(ui.button('导出统计').props.disabled,true);assert.equal(ui.button('刷新统计').props.disabled,false);
  void ui.button('刷新统计').props.onClick();await flush();assert.equal(ui.requests.length,2);
  const request=new URL(ui.requests[1].path,'http://owned.test');assert.equal(request.searchParams.get('from'),a.toISOString());assert.equal(request.searchParams.get('to'),b.toISOString());
  await ui.resolve(1,22);assert(ui.all('strong').some(n=>ui.text(n)==='22'));assert.equal(ui.button('导出统计').props.disabled,false);
 }finally{ui.stop();}
});
test('actual Vue discards an old response after dates change A to B to A',async()=>{
 const ui=harness();try{
  await ui.select();await ui.resolve(0,11);await ui.range(start,end);
  void ui.button('刷新统计').props.onClick();await flush();assert.equal(ui.requests.length,2);
  await ui.range(new Date('2026-11-03T00:00:00Z'),new Date('2026-11-04T00:00:00Z'));await ui.range(start,end);
  await ui.resolve(1,33);assert.equal(ui.all('strong').some(n=>ui.text(n)==='33'),false);assert.equal(ui.button('导出统计').props.disabled,true);
  void ui.button('刷新统计').props.onClick();await flush();assert.equal(ui.requests.length,3);await ui.resolve(2,44);assert(ui.all('strong').some(n=>ui.text(n)==='44'));
 }finally{ui.stop();}
});
test('actual Vue rejects an unrelated returned time range and does not send an incomplete range',async()=>{
 const ui=harness();try{
  await ui.select();await ui.resolve(0,11);await ui.range(start,null);
  assert.equal(ui.button('刷新统计').props.disabled,true);assert.equal(ui.button('导出统计').props.disabled,true);assert.equal(ui.button('计算真实漏斗').props.disabled,true);
  await ui.range(start,end);void ui.button('刷新统计').props.onClick();await flush();await ui.resolve(1,55,{from:'2026-10-01T00:00:00Z'});
  assert.equal(ui.all('strong').some(n=>ui.text(n)==='55'),false);assert.equal(ui.button('导出统计').props.disabled,true);
  assert(ui.all('el-alert').some(n=>String(n.props.title).includes('时间范围与查询不一致')));
 }finally{ui.stop();}
});
test('actual Vue funnel export requires the requested paths and window as well as the current dates',async()=>{
 const ui=harness();try{
  await ui.select();await ui.resolve(0,11);await ui.range(start,end);
  const response=paths=>({source:'browser-telemetry',from:start.toISOString(),to:end.toISOString(),window_minutes:30,sampled_pageviews:3,unique_pageviews:3,partial:false,ordering_uncertain_sessions:0,completed_sessions:1,duration_seconds:{},limitations:[],steps:paths.map(path=>({path,sessions:1,overall_rate:100,previous_rate:100,drop_off:0}))});
  void ui.button('计算真实漏斗').props.onClick();await flush();assert.equal(ui.requests.length,2);
  const request=new URL(ui.requests[1].path,'http://owned.test');assert.deepEqual(request.searchParams.getAll('step'),['/','/checkout','/success']);assert.equal(request.searchParams.get('window_minutes'),'30');
  ui.requests[1].resolve(response(['/','/checkout','/unrelated']));await flush();assert.equal(ui.button('导出漏斗').props.disabled,true);
  assert(ui.all('el-alert').some(n=>String(n.props.title).includes('页面或时限与查询不一致')));
  void ui.button('计算真实漏斗').props.onClick();await flush();ui.requests[2].resolve(response(['/','/checkout','/success']));await flush();assert.equal(ui.button('导出漏斗').props.disabled,false);
  await ui.range(new Date('2026-11-03T00:00:00Z'),new Date('2026-11-04T00:00:00Z'));assert.equal(ui.button('导出漏斗').props.disabled,true);
 }finally{ui.stop();}
});

const heatCount=(ui,name)=>{const n=ui.all('dd').find(n=>n.props['data-testid']===name);return n?ui.text(n):undefined;};
const heatTable=ui=>ui.all('el-table').find(n=>n.props['aria-label']==='点击坐标明细');
const heatSelect=ui=>ui.all('el-select').find(n=>n.props['aria-label']==='热图页面');
test('actual Vue heatmap exposes selected-page totals and readable frequency-ordered coordinates without changing the report',async()=>{
 const ui=harness();try{
  await ui.select();assert.equal(heatCount(ui,'heatmap-clicks'),undefined);assert.equal(heatSelect(ui),undefined);
  const points=Object.freeze([{path:'/one',x:0,y:5,count:2},{path:'/two',x:10,y:10,count:99},{path:'/one',x:10,y:15,count:5}].map(Object.freeze));
  await ui.resolve(0,11,{heatmap:points});
  assert.equal(heatCount(ui,'heatmap-clicks'),'7');assert.equal(heatCount(ui,'heatmap-cells'),'2');
  assert.deepEqual(heatTable(ui).props.data.map(p=>[p.x,p.y,p.count]),[[10,15,5],[0,5,2]]);
  assert.equal(ui.all('svg').find(n=>n.props.class==='analytics-heatmap').props['aria-label'],'/one 点击坐标分布，共 7 次点击，2 个网格');
  ui.update(heatSelect(ui),'/two');await flush();assert.equal(heatCount(ui,'heatmap-clicks'),'99');assert.equal(heatCount(ui,'heatmap-cells'),'1');
  assert.deepEqual(heatTable(ui).props.data.map(p=>p.path),['/two']);assert.deepEqual(points.map(p=>p.count),[2,99,5]);
 }finally{ui.stop();}
});
test('actual Vue bounds heatmap details to twenty cells and resets pagination when the page changes',async()=>{
 const ui=harness();try{
  await ui.select();const points=Array.from({length:41},(_,i)=>({path:'/many',x:i%20*5,y:Math.floor(i/20)*5,count:i+1}));
  await ui.resolve(0,11,{heatmap:[...points,{path:'/other',x:95,y:95,count:3}]});
  assert.equal(heatCount(ui,'heatmap-clicks'),'861');assert.equal(heatCount(ui,'heatmap-cells'),'41');assert.equal(heatTable(ui).props.data.length,20);assert.equal(heatTable(ui).props.data[0].count,41);
  const pager=ui.all('el-pagination')[0];assert.equal(pager.props.total,41);assert.equal(pager.props['page-size'],20);assert.equal(typeof pager.props['onUpdate:currentPage'],'function');
  pager.props['onUpdate:currentPage'](3);await flush();assert.deepEqual(heatTable(ui).props.data.map(p=>p.count),[1]);
  ui.update(heatSelect(ui),'/other');await flush();assert.equal(heatCount(ui,'heatmap-clicks'),'3');assert.equal(ui.all('el-pagination').length,0);assert.equal(heatTable(ui).props.data.length,1);
  ui.update(heatSelect(ui),'/many');await flush();assert.equal(heatTable(ui).props.data[0].count,41);assert.equal(heatTable(ui).props.data.length,20);
 }finally{ui.stop();}
});
test('actual Vue hides heatmap totals, old page labels and details as soon as its query changes',async()=>{
 const ui=harness();try{
  await ui.select();await ui.resolve(0,11,{heatmap:[{path:'/old-page',x:0,y:0,count:7}]});assert.equal(heatCount(ui,'heatmap-clicks'),'7');
  await ui.range(start,end);assert.equal(heatCount(ui,'heatmap-clicks'),undefined);assert.equal(heatSelect(ui),undefined);assert.equal(heatTable(ui),undefined);assert.equal(ui.all('svg').filter(n=>n.props.class==='analytics-heatmap').length,0);
  void ui.button('刷新统计').props.onClick();await flush();await ui.resolve(1,11,{heatmap:[{path:'/current-page',x:25,y:25,count:4}]});assert.equal(heatCount(ui,'heatmap-clicks'),'4');assert.equal(heatSelect(ui).props.modelValue,'/current-page');
 }finally{ui.stop();}
});
test('actual Vue distinguishes an unqueried heatmap from a current report with no clicks',async()=>{
 const ui=harness();try{
  assert.equal(heatCount(ui,'heatmap-clicks'),undefined);assert.equal(heatTable(ui),undefined);
  await ui.select();await ui.resolve(0,11);assert.equal(heatCount(ui,'heatmap-clicks'),'0');assert.equal(heatCount(ui,'heatmap-cells'),'0');assert.equal(heatSelect(ui).props.disabled,true);assert.equal(heatTable(ui),undefined);assert.equal(ui.all('el-pagination').length,0);
  assert(ui.all('el-empty').some(n=>n.props.description==='当前网站和时间范围没有点击记录。'));
 }finally{ui.stop();}
});

test('actual heatmap isolates responsive layouts and retains unclassified historic clicks',async()=>{
 const ui=harness('2.4.4');try{
  await ui.select();
  const cells=[
   {path:'/page',viewport:'narrow',x:10,y:5,count:2},
   {path:'/page',viewport:'wide',x:10,y:5,count:5},
   {path:'/page',viewport:'unknown',x:10,y:5,count:11},
   {path:'/other',viewport:'medium',x:25,y:25,count:7},
  ];
  await ui.resolve(0,11,{heatmap:[{path:'/page',x:10,y:5,count:18}],heatmap_layouts:{points:cells,partial:true}});
  const width=()=>ui.all('el-select').find(n=>n.props['aria-label']==='热图屏宽');
  assert.equal(heatCount(ui,'heatmap-clicks'),'2');
  ui.update(width(),'wide');await flush();assert.equal(heatCount(ui,'heatmap-clicks'),'5');
  ui.update(width(),'unknown');await flush();assert.equal(heatCount(ui,'heatmap-clicks'),'11');
  ui.update(heatSelect(ui),'/other');await flush();
  assert.equal(width().props.modelValue,'medium');assert.equal(heatCount(ui,'heatmap-clicks'),'7');
  assert(ui.all('el-alert').some(n=>String(n.props.title).includes('点击热图达到采样或容量上限')));
 }finally{ui.stop();}
});
