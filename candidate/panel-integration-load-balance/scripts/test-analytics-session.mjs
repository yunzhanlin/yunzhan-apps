// Actual embedded tracker, closed synthetic browser clock/storage only.
// This does not claim native browser, real30-minute waiting or provider proof.
import test from 'node:test';import assert from 'node:assert/strict';import vm from 'node:vm';import{readFileSync}from'node:fs';import{webcrypto}from'node:crypto';
import{computed}from'../web/node_modules/vue/index.mjs';
const tracker=readFileSync(new URL('../internal/core/analytics_tracker.js',import.meta.url),'utf8'),idle=1800000,start=1792340000000;
function fixture({seed,wall=start,storage,deny=false,privacy={},namespace}={}){
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
 if(namespace!==undefined)context.window.yunzhanAnalytics=namespace;
 vm.runInNewContext('(()=>{'+tracker+'})();',context);
 const advance=delta=>{now+=delta;clock+=Math.max(0,delta)},dispatch=(events,name,event={})=>{for(const callback of [...(events.get(name)||[])])callback(event)};
 return{sent,values,context,now:()=>now,writes:()=>writes,advance,tick(delta=30000){advance(delta);for(const callback of [...timers.values()])callback()},visibility(value){document.visibilityState=value;dispatch(documentEvents,'visibilitychange')},windowEvent:(name,event={})=>dispatch(windowEvents,name,event)};
}
test('navigation sequence survives SPA visits and a following full document without changing the session',()=>{
 const f=fixture(),first=f.sent[0].event;assert.equal(first.navigation_seq,1);
 f.context.history.pushState(null,'','/second');const second=f.sent.at(-1).event;assert.equal(second.navigation_seq,2);assert.equal(second.session,first.session);
 const next=fixture({storage:f.values,wall:f.now()+1000});assert.equal(next.sent[0].event.navigation_seq,3);assert.equal(next.sent[0].event.session,first.session);
 assert.equal(JSON.parse(next.values.get('yz.analytics.session')).navigation_seq,3);
});
test('a restored document advances past another document counter instead of reusing its old value',()=>{
 const f=fixture(),session=f.sent[0].event.session;f.windowEvent('pagehide');
 const other=fixture({storage:f.values,wall:f.now()+500});assert.equal(other.sent[0].event.navigation_seq,2);
 f.advance(1000);f.windowEvent('pageshow',{persisted:true});const restored=f.sent.at(-1).event;
 assert.equal(restored.kind,'pageview');assert.equal(restored.navigation_seq,3);assert.equal(restored.session,session);
});
test('genuine inactivity or clock reversal resets navigation order only with a new session',()=>{
 for(const delta of[idle,-1000]){
  const f=fixture(),original=f.sent[0].event;f.context.history.pushState(null,'','/second');f.advance(delta);f.context.history.pushState(null,'','/new-session');
  const visit=f.sent.filter(row=>row.event.kind==='pageview').at(-1).event;assert.notEqual(visit.session,original.session);assert.equal(visit.navigation_seq,1);
 }
});
test('corrupted persisted navigation counters retain the active session but never invent ordering metadata',()=>{
 for(const navigation_seq of[null,-1,'2',1.25,1000000001]){
  const id='e'.repeat(32),f=fixture({seed:{id,last:start-1000,navigation_seq}});assert.equal(f.sent[0].event.session,id);assert.equal(f.sent[0].event.navigation_seq,undefined);
  f.context.history.pushState(null,'','/unknown-order');assert.equal(f.sent.at(-1).event.navigation_seq,undefined);assert.equal(JSON.parse(f.values.get('yz.analytics.session')).navigation_seq,null);
  f.advance(idle);f.context.history.pushState(null,'','/genuine-new-session');const next=f.sent.filter(row=>row.event.kind==='pageview').at(-1).event;assert.notEqual(next.session,id);assert.equal(next.navigation_seq,1);
 }
});
test('navigation order saturates without wrapping, changing the session or resetting the event budget',()=>{
 const f=fixture({seed:{id:'f'.repeat(32),last:start-1,navigation_seq:999999999}}),session=f.sent[0].event.session;assert.equal(f.sent[0].event.navigation_seq,1000000000);
 f.context.history.pushState(null,'','/after-limit');assert.equal(f.sent.at(-1).event.navigation_seq,undefined);assert.equal(f.sent.at(-1).event.session,session);
 for(let i=0;i<300;i++)f.context.history.pushState(null,'','/route-'+i);assert.equal(f.sent.length,240);assert(f.sent.slice(1).every(row=>row.event.navigation_seq===undefined));
});
test('passive metrics and engagement never claim an extra browser navigation',()=>{
 const f=fixture();f.tick();f.context.history.pushState(null,'','/route');const ticket=f.context.window.yunzhanAnalytics.currentRoute();f.advance(10);f.context.window.yunzhanAnalytics.routeReady(ticket.id);f.windowEvent('pagehide');
 assert.deepEqual(f.sent.filter(row=>row.event.kind==='pageview').map(row=>row.event.navigation_seq),[1,2]);
 assert(f.sent.filter(row=>row.event.kind!=='pageview').every(row=>row.event.navigation_seq===undefined));
 const denied=fixture({deny:true});denied.context.history.pushState(null,'','/next');assert.equal(denied.sent.at(-1).event.navigation_seq,2);assert.equal(denied.writes(),0);
});
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
test('actual Vue HTML opt-in retains exact known versions including2.4.1, rejecting aliases and future revisions',()=>{
 const component=readFileSync(new URL('../web/src/AnalyticsWorkspace.vue',import.meta.url),'utf8'),lines=component.split('\n').filter(line=>line.startsWith('const htmlSupported='));assert.equal(lines.length,1);
 const actual=new Function('props','computed',lines[0]+';return htmlSupported.value;');
 for(const version of['2.3.0','2.3.1','2.3.2','2.4.0','2.4.1']){assert.equal(actual({installed:true,installedVersion:version},computed),true);assert.equal(actual({installed:false,installedVersion:version},computed),false);}
 for(const version of['','2.2.0','2.3','02.3.1','02.3.2','2.3.1-compat1','2.3.2-compat1','2.3.2+build','2.3.3','2.4.0+build','2.4.0-compat1','2.4.1-compat1','2.4.1+build','02.4.1','2.4.2'])assert.equal(actual({installed:true,installedVersion:version},computed),false,version);
 assert.equal(actual({installed:true},computed),false);
});

test('SPA readiness is explicit, numeric and bound to its own page, never the original document',()=>{
 const f=fixture(),api=f.context.window.yunzhanAnalytics,doc=f.sent[0].event;assert.equal(api.routePerformanceVersion,1);
 assert.equal(api.currentRoute(),null);f.advance(10);f.context.history.pushState(null,'','/catalog');
 const ticket=api.currentRoute(),visit=f.sent.at(-1).event;assert.equal(ticket.path,'/catalog');assert.deepEqual(Object.keys(ticket).sort(),['id','path']);assert(Object.isFrozen(ticket));
 f.advance(420);const stamp=JSON.parse(f.values.get('yz.analytics.session')).last;
 assert.equal(api.routeReady(ticket.id),true);const route=f.sent.at(-1).event;
 assert.equal(route.kind,'route-performance');assert.equal(route.route_ready_ms,420);assert.equal(route.page_id,visit.page_id);assert.equal(route.path,'/catalog');assert.equal(route.session,visit.session);
 assert.equal(JSON.parse(f.values.get('yz.analytics.session')).last,stamp);assert(!JSON.stringify(route).includes(ticket.id));assert.equal(api.routeReady(ticket.id),false);assert.equal(api.currentRoute(),null);
 f.windowEvent('pagehide');const standard=f.sent.at(-1).event;assert.equal(standard.kind,'performance');assert.equal(standard.page_id,doc.page_id);assert.equal(standard.path,doc.path);assert.equal(standard.route_ready_ms,undefined);
});
test('async completion from a superseded route cannot record readiness for the next route',()=>{
 const f=fixture(),api=f.context.window.yunzhanAnalytics;f.context.history.pushState(null,'','/a');const old=api.currentRoute();f.advance(80);f.context.history.replaceState(null,'','/b');const current=api.currentRoute();
 assert.notEqual(old.id,current.id);const before=f.sent.length;assert.equal(api.routeReady(old.id),false);assert.equal(f.sent.length,before);f.advance(50);assert.equal(api.routeReady(current.id),true);assert.equal(f.sent.at(-1).event.path,'/b');assert.equal(f.sent.at(-1).event.route_ready_ms,50);
});
test('hiding, pagehide, BFCache restoration and session replacement invalidate original route tickets',()=>{
 for(const mode of['hidden','pagehide','bfcache','session']){
  const f=fixture(),api=f.context.window.yunzhanAnalytics;f.context.history.pushState(null,'','/route');const ticket=api.currentRoute();
  if(mode==='hidden'){f.visibility('hidden');f.visibility('visible');}
  if(mode==='pagehide')f.windowEvent('pagehide');
  if(mode==='bfcache'){f.windowEvent('pagehide');f.windowEvent('pageshow',{persisted:true});}
  if(mode==='session'){f.advance(idle+1);f.tick();}
  const before=f.sent.length;assert.equal(api.routeReady(ticket.id),false,mode);assert.equal(f.sent.length,before);assert.equal(api.currentRoute(),null);
 }
});
test('same-path and query or fragment activity does not fabricate a new route timing',()=>{
 const f=fixture(),api=f.context.window.yunzhanAnalytics;f.context.history.pushState(null,'','/same');const ticket=api.currentRoute(),before=f.sent.length;
 f.context.location.search='?token=private-never-retained';f.context.history.replaceState(null,'','/same');f.windowEvent('hashchange');assert.equal(f.sent.length,before);assert.equal(api.currentRoute().id,ticket.id);
 f.advance(5);api.routeReady(ticket.id);assert(!JSON.stringify(f.sent).includes('private-never-retained'));
});
test('route timing admits measured zero and exact five-minute boundary but rejects expiry or invalid clocks',()=>{
 for(const delay of[0,300000]){const f=fixture(),api=f.context.window.yunzhanAnalytics;f.context.history.pushState(null,'','/valid');const ticket=api.currentRoute();f.advance(delay);assert.equal(api.routeReady(ticket.id),true);assert.equal(f.sent.at(-1).event.route_ready_ms,delay);}
 for(const clock of[()=>NaN,()=>Infinity,()=>-1]){const f=fixture(),api=f.context.window.yunzhanAnalytics;f.context.history.pushState(null,'','/invalid');const ticket=api.currentRoute();f.context.performance.now=clock;const before=f.sent.length;assert.equal(api.routeReady(ticket.id),false);assert.equal(f.sent.length,before);}
 const f=fixture(),api=f.context.window.yunzhanAnalytics;f.context.history.pushState(null,'','/expired');const ticket=api.currentRoute();f.advance(300001);assert.equal(api.routeReady(ticket.id),false);
});
test('readiness obeys the original240-event budget without resetting it or the idle activity clock',()=>{
 const f=fixture(),api=f.context.window.yunzhanAnalytics;for(let i=0;i<237;i++)f.tick();f.context.history.pushState(null,'','/last');const ticket=api.currentRoute();assert.equal(f.sent.length,239);const writes=f.writes();
 assert.equal(api.routeReady(ticket.id),true);assert.equal(f.sent.length,240);assert.equal(f.writes(),writes);assert.equal(api.routeReady(ticket.id),false);f.context.history.pushState(null,'','/later');assert.equal(api.currentRoute(),null);assert.equal(f.sent.length,240);
});
test('readiness never replaces an existing website namespace or creates a collector after privacy opt-out',()=>{
 const namespace={existing:true},f=fixture({namespace});assert.equal(f.context.window.yunzhanAnalytics,namespace);f.context.history.pushState(null,'','/next');assert.equal(f.sent.filter(row=>row.event.kind==='route-performance').length,0);
 for(const privacy of[{doNotTrack:'1'},{globalPrivacyControl:true}]){const p=fixture({privacy});assert.equal(p.context.window.yunzhanAnalytics,undefined);assert.equal(p.sent.length,0);}
});
test('a route is sent at most once even after a transport exception and invalid tickets cannot emit it',()=>{
 const f=fixture(),api=f.context.window.yunzhanAnalytics;f.context.history.pushState(null,'','/throw');const ticket=api.currentRoute(),before=f.sent.length;
 for(const id of[undefined,null,{},'',42,'x'.repeat(32)])assert.equal(api.routeReady(id),false);assert.equal(f.sent.length,before);
 let calls=0;f.context.fetch=()=>{calls++;throw Error('owned synchronous transport failure')};assert.equal(api.routeReady(ticket.id),false);assert.equal(api.routeReady(ticket.id),false);assert.equal(calls,1);
});
test('navigation after throttled foreground inactivity creates only one fresh pageview and one route ticket',()=>{
 const f=fixture(),api=f.context.window.yunzhanAnalytics,session=f.sent[0].event.session;f.advance(idle+1);const before=f.sent.length;f.context.history.pushState(null,'','/new-session');
 const added=f.sent.slice(before).map(row=>row.event),visits=added.filter(v=>v.kind==='pageview');assert.equal(visits.length,1);assert.notEqual(visits[0].session,session);assert.equal(visits[0].path,'/new-session');assert.equal(api.currentRoute().path,'/new-session');
});
