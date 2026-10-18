import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import vm from "node:vm";
import { webcrypto, createHash } from "node:crypto";

const code=readFileSync(new URL("../internal/core/analytics_tracker.js",import.meta.url),"utf8");
const vitals=readFileSync(new URL("../internal/core/analytics_vendor/web-vitals-6.2.3.iife.js",import.meta.url),"utf8");
const provenance=JSON.parse(readFileSync(new URL("../internal/core/analytics_vendor/source.json",import.meta.url),"utf8"));
for(const [file,digest] of Object.entries(provenance.files))assert.equal(createHash("sha256").update(readFileSync(new URL(`../internal/core/analytics_vendor/${file}`,import.meta.url))).digest("hex"),digest,`pinned vendor identity: ${file}`);
function fixture(privacy={},inp=false,overrides={}) {
  let clock=0;
  const sent=[],timers=new Map(),windowEvents=new Map(),documentEvents=new Map(),observers=new Map();
  let nextTimer=0;
  const storage=()=>{const values=new Map();return {getItem:k=>values.get(k)||null,setItem:(k,v)=>values.set(k,v)}};
  const on=(events,k,v)=>events.set(k,[...(events.get(k)||[]),v]);
  const off=(events,k,v)=>events.set(k,(events.get(k)||[]).filter(callback=>callback!==v));
  const document={currentScript:{src:"https://analytics.example/__yunzhan/analytics/tracker.js?site="+"a".repeat(32)+"&key="+"b".repeat(32)},title:"Test",referrer:"https://source.example/search?private=secret",visibilityState:"visible",prerendering:false,readyState:"complete",documentElement:{scrollWidth:1000,scrollHeight:1000},addEventListener:(k,v)=>on(documentEvents,k,v)};
  const location={origin:"https://analytics.example",pathname:"/first",search:"?token=secret&utm_campaign=launch"};
  class Observer {
    static supportedEntryTypes=["paint","largest-contentful-paint","layout-shift",...(inp?["event","first-input"]:[])];
    constructor(callback){this.callback=callback;}
    observe({type}){observers.set(type,this.callback);}
    takeRecords(){return []}
    disconnect(){}
  }
  class Element {closest(){return null}}
  const history={pushState(_state,_unused,url){location.pathname=url},replaceState(_state,_unused,url){location.pathname=url}};
  const context={config:{site:"a".repeat(32),key:"b".repeat(32),clicks:true},navigator:privacy,document,location,history,localStorage:storage(),sessionStorage:storage(),crypto:webcrypto,Uint8Array,URL,URLSearchParams,Element,PerformanceObserver:Observer,innerWidth:1000,innerHeight:1000,
    performance:{now:()=>clock,getEntriesByType:type=>type==="navigation"?[{responseStart:50,startTime:0}]:[],interactionCount:0},
    setInterval:fn=>{timers.set(++nextTimer,fn);return nextTimer},clearInterval:id=>timers.delete(id),
    setTimeout:fn=>{fn();return ++nextTimer},clearTimeout:()=>{},queueMicrotask:fn=>fn(),
    addEventListener:(k,v)=>on(windowEvents,k,v),removeEventListener:(k,v)=>off(windowEvents,k,v),
    fetch:(url,options)=>{sent.push({url,options,event:JSON.parse(options.body)});return Promise.resolve({status:204})},
    window:{addEventListener:(k,v)=>on(windowEvents,k,v)}};
  if(inp){class Timing{};Timing.prototype.interactionId=0;context.PerformanceEventTiming=Timing;}
  if(overrides.src!==undefined)document.currentScript.src=overrides.src;
  if(overrides.config!==undefined)context.config=overrides.config;
  const execute=()=>vm.runInNewContext(`(()=>{${vitals}\n${code}\n})();`,context);
  execute();
  const dispatch=(events,name,event)=>{for(const callback of [...(events.get(name)||[])])callback({type:name,timeStamp:clock,...event})};
  return {context,sent,timers,observers,execute,advance:n=>clock+=n,documentEvent:name=>{dispatch(documentEvents,name,{});dispatch(windowEvents,name,{})},windowEvent:(name,event={})=>dispatch(windowEvents,name,event)};
}

for(const privacy of [{doNotTrack:"1"},{globalPrivacyControl:true}]) {const f=fixture(privacy);assert.equal(f.sent.length,0);assert.equal(f.timers.size,0);}
const f=fixture();
assert.equal(f.sent.length,1);
assert.equal(f.sent[0].event.kind,"pageview");
assert.equal(f.sent[0].event.referer,"https://source.example");
assert.equal(f.sent[0].event.campaign,"launch");
assert.ok(!JSON.stringify(f.sent).includes("private=secret"));
assert.equal(f.sent[0].options.credentials,"omit");
assert.equal(f.sent[0].options.mode,"same-origin");
const firstPage=f.sent[0].event.page_id;
f.advance(12000);f.context.history.pushState(null,"","/second");
assert.equal(f.sent.filter(x=>x.event.kind==="pageview").length,2);
assert.notEqual(f.sent.at(-1).event.page_id,firstPage);
assert.equal(f.sent.at(-2).event.duration,12);
f.context.document.visibilityState="hidden";f.documentEvent("visibilitychange");f.windowEvent("pagehide");
assert.equal(f.timers.size,0);
const performances=f.sent.filter(x=>x.event.kind==="performance");
assert.ok(performances.every(x=>x.event.page_id===firstPage && x.event.path==="/first"));
assert.equal(performances.at(-1).event.cls_available,true);
assert.equal(performances.at(-1).event.cls,0);
f.context.document.visibilityState="visible";f.windowEvent("pageshow",{persisted:true});
assert.equal(f.timers.size,1);
assert.equal(f.sent.filter(x=>x.event.kind==="pageview").length,3);
assert.notEqual(f.sent.at(-1).event.page_id,firstPage);
f.advance(30000);for(const timer of f.timers.values())timer();
assert.equal(f.sent.at(-1).event.kind,"engagement");
assert.equal(f.sent.at(-1).event.duration,30);
assert.equal(f.sent.at(-1).event.path,"/second");
f.observers.get("layout-shift")({getEntries:()=>[{startTime:13000,value:.1,hadRecentInput:false},{startTime:13200,value:.2,hadRecentInput:false},{startTime:19000,value:.1,hadRecentInput:false}]});
f.windowEvent("pagehide");
assert.ok(Math.abs(f.sent.at(-1).event.cls-.3)<1e-9);
// Execute the actual pinned standard library, not a fake onINP callback.
const inp=fixture({},true);
const interactions=(count,entries)=>{inp.context.performance.interactionCount=count;inp.observers.get("event")({getEntries:()=>entries})};
interactions(1,[{entryType:"event",interactionId:7,duration:600,startTime:40,target:{private:"typed-card-number"}}]);
let score=inp.sent.at(-1).event;assert.equal(score.inp,600);assert.equal(score.inp_available,true);
const firstSequence=score.performance_seq,firstNavigation=score.page_id;
interactions(2,[{entryType:"event",interactionId:14,duration:200,startTime:100}]);
interactions(50,[{entryType:"event",interactionId:350,duration:120,startTime:500}]);
score=inp.sent.at(-1).event;assert.equal(score.inp,200);assert.ok(score.performance_seq>firstSequence);
assert.equal(score.page_id,firstNavigation);
assert.ok(!JSON.stringify(inp.sent).includes("typed-card-number"));
inp.context.history.pushState(null,"","/next-route");
interactions(51,[{entryType:"event",interactionId:357,duration:400,startTime:800}]);
score=inp.sent.at(-1).event;assert.equal(score.path,"/first");assert.equal(score.page_id,firstNavigation);
inp.windowEvent("pagehide");inp.advance(60000);inp.windowEvent("pageshow",{persisted:true});
interactions(52,[{entryType:"event",interactionId:364,duration:320,startTime:60010}]);
score=inp.sent.at(-1).event;assert.notEqual(score.page_id,firstNavigation);assert.equal(score.path,"/next-route");assert.equal(score.inp,320);
assert.ok(f.sent.filter(x=>x.event.kind==="performance").every(x=>x.event.inp_available===false));
const auto=fixture({},false,{src:"https://analytics.example/__yunzhan/analytics/auto.js?site="+"a".repeat(32)});
assert.equal(auto.sent.length,1);assert.ok(auto.sent[0].url.startsWith("https://analytics.example/__yunzhan/analytics/event?"));
const samePush=auto.context.history.pushState;auto.execute();
auto.context.document.currentScript.src="https://analytics.example/__yunzhan/analytics/tracker.js?site="+"a".repeat(32)+"&key="+"b".repeat(32);auto.execute();
assert.equal(auto.sent.length,1);assert.equal(auto.timers.size,1);assert.equal(auto.context.history.pushState,samePush);
auto.context.history.pushState(null,"","/another");assert.equal(auto.sent.filter(x=>x.event.kind==="pageview").length,2);
for(const overrides of [{src:"https://evil.example/__yunzhan/analytics/auto.js"},{src:"https://analytics.example/collect/not-a-tracker.js"},{config:{site:"bad",key:"b".repeat(32),clicks:true}}]){const rejected=fixture({},false,overrides);assert.equal(rejected.sent.length,0);assert.equal(rejected.timers.size,0);assert.equal(rejected.observers.size,0);}
console.log("PASS analytics tracker: privacy, same-origin, SPA, BFCache, CLS and actual pinned INP grouping/outliers/document identity");
