import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {createRequire} from 'node:module';
import ts from '../web/node_modules/typescript/lib/typescript.js';
import {analyticsMetricText,analyticsPerformanceRows} from '../web/src/analyticsPerformance.ts';
import {beforeLoadBalanceStreamBuild} from './release-build-baseline.mjs';
const require=createRequire(new URL('../web/package.json',import.meta.url));
const {parse,compileScript}=require('@vue/compiler-sfc');
const {createSSRApp}=require('vue');
const {renderToString}=require('@vue/server-renderer');
const source=readFileSync(new URL('../web/src/AnalyticsPerformanceReport.vue',import.meta.url),'utf8');
const compiled=compileScript(parse(source).descriptor,{id:'qa-analytics-performance',inlineTemplate:true});
const js=ts.transpileModule(compiled.content,{compilerOptions:{target:ts.ScriptTarget.ES2022,module:ts.ModuleKind.ESNext}}).outputText
 .replace(/from ['"]vue['"]/g,'from '+JSON.stringify(new URL('../web/node_modules/vue/index.mjs',import.meta.url).href))
 .replaceAll('from "./analyticsPerformance"','from '+JSON.stringify(new URL('../web/src/analyticsPerformance.ts',import.meta.url).href));
const component=(await import('data:text/javascript;base64,'+Buffer.from(js).toString('base64'))).default;
const row=(path,kind='spa',value=150)=>({path,kind,navigations:1,metrics:kind==='spa'?{route_ready_ms:{samples:1,p75:value}}:{inp:{samples:0},cls:{samples:1,p75:0}}});
const pages=rows=>({rows,partial:false,sampled_visits:rows.length,group_limit:100});

test('normal build requires the new gate once in its original position and retains all historical gates',()=>{
 const build=readFileSync(new URL('../packaging/build-release.sh',import.meta.url),'utf8');
 const line='(cd "$BUILD_ROOT" && /opt/homebrew/bin/node --test scripts/test-analytics-performance.mjs) 2>&1 | tee -a "$STAGE/$NAME/BUILD_CHECKS.txt"\n';
 const session='(cd "$BUILD_ROOT" && /opt/homebrew/bin/node --test scripts/test-analytics-session.mjs) 2>&1 | tee -a "$STAGE/$NAME/BUILD_CHECKS.txt"\n';
 assert.equal(build.split(session+line).length,2);assert.equal(build.split(line).length,2);assert.doesNotThrow(()=>beforeLoadBalanceStreamBuild(build));
 for(const text of[build.replace(line,''),build.replace(line,line+line),build.replace(line,line.replace('--test','--test-only')),build.replace(session+line,line+session)])assert.throws(()=>beforeLoadBalanceStreamBuild(text));
 assert(beforeLoadBalanceStreamBuild(build.replace('go vet ./...','unreviewed-command ./...')).includes('unreviewed-command ./...'),'unknown changes must remain visible to the original whole-script digest');
});

test('metric text distinguishes missing values, measured zero and actual sample units',()=>{
 assert.equal(analyticsMetricText(undefined,'inp'),'无样本');assert.equal(analyticsMetricText({samples:0,p75:0},'inp'),'无样本');
 assert.equal(analyticsMetricText({samples:1,p75:0},'route_ready_ms'),'0.0 ms · 1 个样本');assert.equal(analyticsMetricText({samples:2,p75:0},'cls'),'0.000 · 2 个样本');
 for(const metric of[{samples:1},{samples:-1,p75:0},{samples:1.2,p75:1},{samples:5001,p75:1},{samples:1,p75:NaN},{samples:1,p75:Infinity},{samples:1,p75:-1},{samples:1,p75:300001}])assert.equal(analyticsMetricText(metric,'route_ready_ms'),'未核实');
 assert.equal(analyticsMetricText({samples:1,p75:101},'cls'),'未核实');
});
test('actual page filter separates SPA and document groups without changing source report',()=>{
 const report=pages([row('/catalog'),row('/CATALOG/detail','document'),row('/other')]),original=JSON.stringify(report);
 assert.equal(analyticsPerformanceRows(report,'',' catalog ').length,2);assert.deepEqual(analyticsPerformanceRows(report,'spa','catalog').map(v=>v.path),['/catalog']);assert.equal(analyticsPerformanceRows(report,'document','catalog').length,1);
 assert.equal(analyticsPerformanceRows(report,'','missing').length,0);assert.equal(analyticsPerformanceRows(undefined,'','').length,0);assert.equal(JSON.stringify(report),original);
 assert.equal(analyticsPerformanceRows(pages(Array.from({length:101},(_,i)=>row('/'+i))),'','').length,100);
});
test('actual Vue render labels original document separately and never invents route Core Web Vitals',async()=>{
 const html=await renderToString(createSSRApp(component,{documentMetrics:{inp:{samples:0}},pages:pages([row('/route','spa',0),row('/document','document')])}));
 assert.match(html,/完整文档性能/);assert.match(html,/SPA 路由/);assert.match(html,/0\.0 ms · 1 个样本/);assert.match(html,/0\.000 · 1 个样本/);assert.match(html,/无样本/);
 assert.match(html,/不代表路由的 LCP 或 INP/);assert.match(html,/currentRoute/);assert.match(html,/routeReady/);assert.match(html,/返回 true 表示已尝试发送/);
});
test('actual Vue render preserves partial warning and escapes untrusted paths',async()=>{
 const report=pages([row('/<img src=x onerror=unexpected>')]);report.partial=true;
 const html=await renderToString(createSSRApp(component,{documentMetrics:{},pages:report}));
 assert.match(html,/当前为部分结果/);assert.match(html,/role="status"/);assert(!html.includes('<img src=x'));assert.match(html,/&lt;img/);
 assert.match(html,/aria-label="性能访问类型"/);assert.match(html,/aria-label="性能页面路径"/);
});
test('actual Vue render remains readable with an older report or no page samples',async()=>{
 const legacy=await renderToString(createSSRApp(component,{documentMetrics:{ttfb:{samples:1,p75:82}}}));assert.match(legacy,/82\.0 ms/);assert.match(legacy,/已有完整文档指标保留/);
 const empty=await renderToString(createSSRApp(component,{documentMetrics:{},pages:pages([])}));assert.match(empty,/没有性能样本/);assert(!empty.includes('0.0 ms'));
});

test('displayed integration example waits for real application completion and preserves its result and failure',async()=>{
 const start=source.indexOf('const integration=`')+'const integration=`'.length,end=source.indexOf('`;',start);assert(start>20&&end>start);
 const example=source.slice(start,end),ticket={id:'owned-route-ticket'};
 for(const namespace of[undefined,{existing:true},{currentRoute:'legacy',routeReady:'legacy'},{routePerformanceVersion:1,currentRoute(){throw Error('owned telemetry failure')},routeReady(){} }]){
  const wrapper=new Function('window',example+';return renderTrackedRoute;')({yunzhanAnalytics:namespace});let calls=0;const result={original:true};assert.equal(await wrapper(async()=>{calls++;return result}),result);assert.equal(calls,1);
 }
 let readyCalls=0,resolve,started=0;const api={routePerformanceVersion:1,currentRoute(){started++;return ticket},routeReady(id){assert.equal(id,ticket.id);readyCalls++;return true}};
 const wrapper=new Function('window',example+';return renderTrackedRoute;')({yunzhanAnalytics:api});const pending=wrapper(()=>new Promise(r=>resolve=r));assert.equal(started,1);assert.equal(readyCalls,0);const result={actual:'render-result'};resolve(result);assert.equal(await pending,result);assert.equal(readyCalls,1);
 const error=Error('original application failure');await assert.rejects(wrapper(async()=>{throw error}),v=>v===error);assert.equal(readyCalls,1);
 api.routeReady=()=>{throw Error('owned post-render telemetry failure')};assert.equal(await wrapper(async()=>result),result);
});
