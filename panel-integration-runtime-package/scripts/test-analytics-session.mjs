// Actual embedded tracker, closed synthetic browser clock/storage only.
// This does not claim native browser, real30-minute waiting or provider proof.
import test from 'node:test';import assert from 'node:assert/strict';import vm from 'node:vm';import{readFileSync}from'node:fs';import{webcrypto}from'node:crypto';
import{computed}from'../web/node_modules/vue/index.mjs';
const tracker=readFileSync(new URL('../internal/core/analytics_tracker.js',import.meta.url),'utf8'),idle=1800000,start=1792340000000;
function fixture({seed,wall=start,storage,deny=false,privacy={}}={}){
 let now=wall,clock=0,writes=0;const sent=[],timers=new Map(),documentEvents=new Map(),windowEvents=new Map();let sequence=0;
 const values=storage??new Map();if(seed!==undefined)values.set('yz.analytics.session',JSON.stringify(seed));
 const sessionStorage={getItem(key){if(deny)throw Error('storage denied');return values.get(key)||null},setItem(key,value){if(deny)throw Error('storage denied');writes++;values.set(key,value)}};
 const localValues=new Map(),localStorage={getItem:key=>localValues.get(key)||null,setItem:(key,value)=>localValues.set(key,value)};
 const listen=(events,name,callback)=>events.set(name,[...(events.get(name)||[]),callback]);
 const location={origin:'https://analytics.example',pathname:'/first',search:'?token=never-collected'};
 const document={currentScript:{src:'https://analytics.example/__yunzhan/analytics/tracker.js'},title:'Session fixture',referrer:'',visibilityState:'visible',documentElement:{scrollWidth:1000,scrollHeight:1000},addEventListener:(name,callback)=>listen(documentEvents,name,callback)};
 class Element{closest(){return null}}
 class Observer{static supportedEntryTypes=[];constructor(){}observe(){}}
 class Clock extends Date{static now(){return now}}
 const history={pushState(_a,_b,value){location.pathname=value},replaceState(_a,_b,value){location.pathname=value}};
 const context={config:{site:'a'.repeat(32),key:'b'.repeat(32),clicks:true},navigator:privacy,document,location,history,localStorage,sessionStorage,crypto:webcrypto,Uint8Array,URL,URLSearchParams,Date:Clock,Element,PerformanceObserver:Observer,innerWidth:1000,innerHeight:1000,performance:{now:()=>clock,getEntriesByType:()=>[]},setInterval:callback=>{timers.set(++sequence,callback);return sequence},clearInterval:key=>timers.delete(key),fetch:(url,options)=>{sent.push({url,options,event:JSON.parse(options.body)});return Promise.resolve({status:204})},window:{addEventListener:(name,callback)=>listen(windowEvents,name,callback)}};
 vm.runInNewContext('(()=>{'+tracker+'})();',context);
 const advance=delta=>{now+=delta;clock+=Math.max(0,delta)},dispatch=(events,name,event={})=>{for(const callback of [...(events.get(name)||[])])callback(event)};
 return{sent,values,context,now:()=>now,writes:()=>writes,advance,tick(delta=30000){advance(delta);for(const callback of [...timers.values()])callback()},visibility(value){document.visibilityState=value;dispatch(documentEvents,'visibilitychange')},windowEvent:(name,event={})=>dispatch(windowEvents,name,event)};
}
test('actual foreground engagement refreshes persisted activity without changing original session',()=>{
 const f=fixture({seed:{id:'c'.repeat(32),last:start-1000}}),session=f.sent[0].event.session;f.tick();
 assert.equal(session,'c'.repeat(32));assert.equal(f.sent.at(-1).event.session,session);assert.equal(JSON.parse(f.values.get('yz.analytics.session')).last,f.now());
});
test('active long-lived SPA and following full document load retain the genuine active session',()=>{
 const f=fixture(),session=f.sent[0].event.session;for(let i=0;i<100;i++)f.tick();
 f.context.history.pushState(null,'','/second');assert.equal(f.sent.at(-1).event.session,session);
 const next=fixture({storage:f.values,wall:f.now()+1000});assert.equal(next.sent[0].event.session,session);assert.notEqual(next.sent[0].event.page_id,f.sent[0].event.page_id);
});
test('hidden inactivity rotates on genuine foreground activity with a new journey pageview first',()=>{
 const f=fixture(),old=f.sent[0].event;f.visibility('hidden');f.advance(idle+1);f.visibility('visible');const begin=f.sent.length;f.tick();
 const added=f.sent.slice(begin).map(row=>row.event);assert.deepEqual(added.map(row=>row.kind),['pageview','engagement']);assert.notEqual(added[0].session,old.session);assert.notEqual(added[0].page_id,old.page_id);assert.equal(added[1].session,added[0].session);assert.equal(added[1].page_id,added[0].page_id);assert.equal(added[1].duration,30);
});
test('late document performance never extends idle session and remains bound to original document session',()=>{
 const f=fixture(),old=f.sent[0].event,stamp=JSON.parse(f.values.get('yz.analytics.session')).last;
 f.visibility('hidden');f.advance(idle+1);f.windowEvent('pagehide');assert.equal(JSON.parse(f.values.get('yz.analytics.session')).last,stamp);assert.equal(f.sent.at(-1).event.kind,'performance');assert.equal(f.sent.at(-1).event.session,old.session);
 f.visibility('visible');f.windowEvent('pageshow',{persisted:true});const restored=f.sent.at(-1).event;assert.equal(restored.kind,'pageview');assert.notEqual(restored.session,old.session);
 f.windowEvent('pagehide');const metric=f.sent.at(-1).event;assert.equal(metric.kind,'performance');assert.equal(metric.session,restored.session);assert.equal(metric.page_id,restored.page_id);
});
test('a resumed same-document session cannot steal the original document performance identity',()=>{
 const f=fixture(),original=f.sent[0].event;f.visibility('hidden');f.advance(idle+1);f.visibility('visible');f.tick();const resumed=f.sent.at(-1).event;
 assert.notEqual(resumed.session,original.session);f.windowEvent('pagehide');const metric=f.sent.at(-1).event;
 assert.equal(metric.kind,'performance');assert.equal(metric.session,original.session);assert.equal(metric.page_id,original.page_id);assert.equal(metric.path,original.path);assert.notEqual(metric.page_id,resumed.page_id);
});
test('storage denial retains in-memory continuity and permits exactly one new session after inactivity',()=>{
 const f=fixture({deny:true}),old=f.sent[0].event.session;f.tick();assert.equal(f.sent.at(-1).event.session,old);f.visibility('hidden');f.advance(idle+1);f.visibility('visible');f.tick();const next=f.sent.at(-1).event.session;assert.notEqual(next,old);f.tick();assert.equal(f.sent.at(-1).event.session,next);assert.equal(f.writes(),0);
});
test('future corrupted timestamp and wall-clock reversal cannot pin an immortal session',()=>{
 const f=fixture({seed:{id:'d'.repeat(32),last:start+idle}});assert.notEqual(f.sent[0].event.session,'d'.repeat(32));const old=f.sent[0].event.session;f.advance(-1000);f.context.history.pushState(null,'','/after-clock-adjustment');assert.notEqual(f.sent.at(-1).event.session,old);assert.equal(JSON.parse(f.values.get('yz.analytics.session')).last,f.now());
});
test('session boundary is exact and passive telemetry cannot reset the240-document event budget',()=>{
 const f=fixture(),old=f.sent[0].event.session;f.advance(idle);f.context.history.pushState(null,'','/boundary');assert.notEqual(f.sent.at(-1).event.session,old);
 const busy=fixture();for(let i=0;i<260;i++)busy.tick();assert.equal(busy.sent.length,240);const writes=busy.writes();busy.advance(idle+1);busy.context.history.pushState(null,'','/over-budget');assert.equal(busy.sent.length,240);assert.equal(busy.writes(),writes);
 assert(!JSON.stringify(busy.sent).includes('never-collected'));assert(busy.sent.every(row=>row.options.credentials==='omit'&&row.options.mode==='same-origin'));
});
test('privacy opt-outs do not create sessions or schedule background activity',()=>{
 for(const privacy of[{doNotTrack:'1'},{globalPrivacyControl:true}]){const f=fixture({privacy});assert.equal(f.sent.length,0);assert.equal(f.writes(),0);f.tick();assert.equal(f.sent.length,0);}
});
test('actual Vue HTML opt-in remains available only for installed exact2.3.0 or2.3.1, not future aliases',()=>{
 const component=readFileSync(new URL('../web/src/AnalyticsWorkspace.vue',import.meta.url),'utf8'),lines=component.split('\n').filter(line=>line.startsWith('const htmlSupported='));assert.equal(lines.length,1);
 const actual=new Function('props','computed',lines[0]+';return htmlSupported.value;');
 for(const version of['2.3.0','2.3.1']){assert.equal(actual({installed:true,installedVersion:version},computed),true);assert.equal(actual({installed:false,installedVersion:version},computed),false);}
 for(const version of['','2.2.0','2.3','02.3.1','2.3.1-compat1','2.3.2','2.4.0'])assert.equal(actual({installed:true,installedVersion:version},computed),false,version);
});
