import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import vm from "node:vm";
import { webcrypto } from "node:crypto";

const code=readFileSync(new URL("../internal/core/analytics_tracker.js",import.meta.url),"utf8");
function fixture(privacy={}) {
  let clock=0;
  const sent=[],timers=new Map(),windowEvents=new Map(),documentEvents=new Map(),observers=new Map();
  let nextTimer=0;
  const storage=()=>{const values=new Map();return {getItem:k=>values.get(k)||null,setItem:(k,v)=>values.set(k,v)}};
  const document={currentScript:{src:"https://analytics.example/__yunzhan/analytics/tracker.js?site="+"a".repeat(32)+"&key="+"b".repeat(32)},title:"Test",referrer:"https://source.example/search?private=secret",visibilityState:"visible",documentElement:{scrollWidth:1000,scrollHeight:1000},addEventListener:(k,v)=>documentEvents.set(k,v)};
  const location={pathname:"/first",search:"?token=secret&utm_campaign=launch"};
  class Observer {
    static supportedEntryTypes=["paint","largest-contentful-paint","layout-shift"];
    constructor(callback){this.callback=callback;}
    observe({type}){observers.set(type,this.callback);}
  }
  class Element {closest(){return null}}
  const history={pushState(_state,_unused,url){location.pathname=url},replaceState(_state,_unused,url){location.pathname=url}};
  const context={config:{site:"a".repeat(32),key:"b".repeat(32),clicks:true},navigator:privacy,document,location,history,localStorage:storage(),sessionStorage:storage(),crypto:webcrypto,Uint8Array,URL,URLSearchParams,Element,PerformanceObserver:Observer,innerWidth:1000,innerHeight:1000,
    performance:{now:()=>clock,getEntriesByType:()=>[{responseStart:50,startTime:0}]},
    setInterval:fn=>{timers.set(++nextTimer,fn);return nextTimer},clearInterval:id=>timers.delete(id),
    fetch:(url,options)=>{sent.push({url,options,event:JSON.parse(options.body)});return Promise.resolve({status:204})},
    window:{addEventListener:(k,v)=>windowEvents.set(k,v)}};
  vm.runInNewContext(`(()=>{${code}\n})();`,context);
  return {context,sent,timers,observers,advance:n=>clock+=n,documentEvent:name=>documentEvents.get(name)?.(),windowEvent:(name,event={})=>windowEvents.get(name)?.(event)};
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
console.log("PASS analytics tracker: privacy, same-origin, SPA, BFCache, navigation identity and CLS session windows");
