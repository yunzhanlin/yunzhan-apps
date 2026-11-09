"use strict";
// First-party telemetry only. No forms, text selections, cookies, DOM recording,
// fingerprinting, third-party URLs or full query strings are collected.
if (navigator.doNotTrack === "1" || navigator.globalPrivacyControl === true) return;
const script = document.currentScript;
if (!script || !script.src) return;
const endpoint = new URL(script.src);
if(endpoint.origin!==location.origin || !/\/(?:tracker|auto)\.js$/.test(endpoint.pathname))return;
endpoint.pathname = endpoint.pathname.replace(/(?:tracker|auto)\.js$/, "event");
endpoint.search = new URLSearchParams({site: config.site, key: config.key}).toString();
const valid = value => typeof value === "string" && /^[a-f0-9]{32}$/.test(value);
if(!valid(config.site)||!valid(config.key))return;
// Manual and automatic tags may coexist during migration. Only one collector
// per document may hook history, observers or timers; the marker has no secrets.
const activeSlot=Symbol.for("yunzhan.analytics.active-document");
if(window[activeSlot]!==undefined)return;
window[activeSlot]=config.site;
const identifier = () => [...crypto.getRandomValues(new Uint8Array(16))].map(v=>v.toString(16).padStart(2,"0")).join("");
let visitor, session, sessionLast=Date.now(), navigationSequence=0, navigationSequenceKnown=true;
const navigationSequenceLimit=1000000000;
const validNavigationSequence=value=>Number.isSafeInteger(value)&&value>=0&&value<=navigationSequenceLimit;
try {
  let data = JSON.parse(localStorage.getItem("yz.analytics.visitor") || "null");
  if (!data || !valid(data.id) || !Number.isFinite(data.created) || Date.now()-data.created>90*86400000) {
    data = {id:identifier(),created:Date.now()};
    localStorage.setItem("yz.analytics.visitor",JSON.stringify(data));
  }
  visitor = data.id;
} catch { visitor=identifier(); }
try {
  const data = JSON.parse(sessionStorage.getItem("yz.analytics.session") || "null");
  if(data&&valid(data.id)&&Number.isSafeInteger(data.last)&&data.last>=0&&data.last<=sessionLast&&sessionLast-data.last<1800000){
    session=data.id;
    if(data.navigation_seq!==undefined){
      if(validNavigationSequence(data.navigation_seq))navigationSequence=data.navigation_seq;
      else navigationSequenceKnown=false;
    }
  }
} catch {}
if(!session)session=identifier();
let routeMeasurement=null;
const syncNavigationSequence=now=>{
  try{
    const data=JSON.parse(sessionStorage.getItem("yz.analytics.session")||"null");
    if(!data||data.id!==session||!Number.isSafeInteger(data.last)||data.last<0||data.last>now||data.navigation_seq===undefined)return;
    if(validNavigationSequence(data.navigation_seq))navigationSequence=Math.max(navigationSequence,data.navigation_seq);
    else navigationSequenceKnown=false;
  }catch{} // Storage denial keeps the current in-memory order, without retries.
};
const persistSession=()=>{try{sessionStorage.setItem("yz.analytics.session",JSON.stringify({id:session,last:sessionLast,navigation_seq:navigationSequenceKnown?navigationSequence:null}));}catch{}};
// Foreground engagement/clicks/visits refresh an existing session, including in
// a long-lived SPA. Storage denial must not destroy in-memory continuity.
// A future/corrupt persisted clock or real clock reversal cannot pin a session.
const touchSession=()=>{
  const now=Date.now(),changed=now<sessionLast||now-sessionLast>=1800000;
  if(changed){session=identifier();routeMeasurement=null;navigationSequence=0;navigationSequenceKnown=true;}
  else syncNavigationSequence(now); // A restored document must not reuse an earlier visit's counter.
  sessionLast=now;persistSession();return changed;
};
let path=location.pathname, title=(document.title || "").slice(0,128),pageID=identifier();
const navigation={path,title,page_id:pageID,session};
let foregroundLoad=document.visibilityState==="visible",restoredAt=0,windowStart=0,lastShift=0,windowValue=0;
let stopped=false, clicks=0, sent=0;
const metrics={ttfb:0,fcp:0,lcp:0,cls:0,cls_available:false,inp:0,inp_available:false};
const send = (kind, fields={}) => {
  if (stopped || sent>=240) return;
  // A late performance flush belongs to its original document/session and is
  // not evidence of renewed user activity. Never let it extend the idle clock.
  if(kind!=="performance"&&kind!=="route-performance"&&touchSession()&&kind!=="pageview"){
    pageID=identifier();pageview();
    // The new visit may consume the final document-budget event. Do not send
    // event241 or reset the budget when a logical session changes.
    if(stopped||sent>=240)return;
  }
  sent++;
  let navigationOrder={};
  if(kind==="pageview"){
    if(navigationSequenceKnown&&navigationSequence<navigationSequenceLimit)navigationOrder={navigation_seq:++navigationSequence};
    else navigationSequenceKnown=false; // Never wrap, reset the budget or fabricate an ordering claim.
    persistSession();
  }
  const body=JSON.stringify({id:identifier(),page_id:pageID,visitor,session,kind,path,title,...fields,...(kind==="performance"||kind==="route-performance"?{performance_seq:sent}:{}),...navigationOrder});
  // Same-origin reverse proxy is required. Do not send panel cookies or retry
  // failed beacons. The host's CSP and privacy policy remain authoritative.
  try { fetch(endpoint.href,{method:"POST",body,headers:{"Content-Type":"application/json"},credentials:"omit",cache:"no-store",keepalive:true,redirect:"error",mode:"same-origin"}).then(r=>{if(r.status===429||r.status===503)stopped=true;}).catch(()=>{});return true; } catch {return false;}
};
const pageview=() => {
  routeMeasurement=null;
  path=location.pathname;title=(document.title || "").slice(0,128);
  let referer="",campaign="";
  try {if(document.referrer){const u=new URL(document.referrer);if(u.protocol==="http:"||u.protocol==="https:")referer=u.origin;}}catch{}
  // Only the named, short campaign label is retained. Search queries and other
  // URL parameters, including tokens and account identifiers, are omitted.
  campaign=(new URLSearchParams(location.search).get("utm_campaign") || "").replace(/[\r\n\x00]/g,"").slice(0,64);
  send("pageview",{referer,campaign});
};
let visibleSince=document.visibilityState==="visible"?performance.now():null;
const engagement=()=>{
  if(visibleSince===null)return;
  const now=performance.now(),duration=Math.min(30,Math.max(0,(now-visibleSince)/1000));visibleSince=now;
  if(duration>=1)send("engagement",{duration});
};
pageview();
let timer=setInterval(engagement,30000);
const sendPerformance=()=>send("performance",{...navigation,...metrics});
document.addEventListener("visibilitychange",()=>{
  if(document.visibilityState==="hidden"){routeMeasurement=null;engagement();visibleSince=null;sendPerformance();}
  else visibleSince=performance.now();
});
window.addEventListener("pagehide",()=>{routeMeasurement=null;engagement();visibleSince=null;sendPerformance();clearInterval(timer);timer=null;});
// A persisted pageshow is a new perceived visit, not an ordinary load event.
// Restart engagement and CLS; navigation/paint times are unknown on restoration.
window.addEventListener("pageshow",event=>{if(event.persisted){
  foregroundLoad=document.visibilityState==="visible";restoredAt=performance.now();visibleSince=foregroundLoad?restoredAt:null;
  pageID=identifier();pageview();Object.assign(navigation,{path,title,page_id:pageID,session});
  metrics.ttfb=metrics.fcp=metrics.lcp=metrics.cls=metrics.inp=0;metrics.inp_available=false;windowStart=lastShift=windowValue=0;
  try{metrics.cls_available=foregroundLoad&&PerformanceObserver.supportedEntryTypes.includes("layout-shift");}catch{metrics.cls_available=false;}
  if(timer===null)timer=setInterval(engagement,30000);
}});
// A website must explicitly mark its own route as ready. Two animation frames,
// history changes or a timer are not proof that asynchronous content rendered.
// Only a fresh opaque ticket is exposed, never visitor/session/site secrets.
// A stale async completion cannot label the next route, a hidden visit, or a
// restored document. No timing is emitted before that explicit integration.
const currentRoute=()=>{
  const r=routeMeasurement,now=performance.now();
  if(!r||stopped||sent>=240||document.visibilityState!=="visible"||location.pathname!==r.path||pageID!==r.page_id||session!==r.session||!Number.isFinite(now)||now<r.started||now-r.started>300000)return null;
  return Object.freeze({id:r.id,path:r.path});
};
const routeReady=id=>{
  const current=currentRoute();
  if(!current||typeof id!=="string"||id!==current.id)return false;
  const r=routeMeasurement,elapsed=performance.now()-r.started;
  if(!Number.isFinite(elapsed)||elapsed<0||elapsed>300000)return false;
  routeMeasurement=null; // One attempt, no automatic retry or duplicate score.
  return send("route-performance",{path:r.path,title:r.title,page_id:r.page_id,session:r.session,route_ready_ms:elapsed})===true;
};
try {
  if(!("yunzhanAnalytics" in window))Object.defineProperty(window,"yunzhanAnalytics",{value:Object.freeze({routePerformanceVersion:1,currentRoute,routeReady}),configurable:true});
} catch {} // Never replace a website's existing namespace or block its router.
// Standard navigation/paint/INP metrics stay bound to the original document.
const route=()=>{if(location.pathname!==path){
  const started=performance.now();engagement();
  // An engagement after real inactivity can already start the new page visit.
  if(location.pathname!==path){pageID=identifier();pageview();}
  if(document.visibilityState==="visible"&&Number.isFinite(started))routeMeasurement={id:identifier(),started,path,title,page_id:pageID,session};
}};
window.addEventListener("popstate",route);
window.addEventListener("hashchange",route);
for(const name of ["pushState","replaceState"]){
  const original=history[name];history[name]=function(...args){const result=original.apply(this,args);route();return result;};
}
if(config.clicks)document.addEventListener("click",event=>{
  if(clicks>=100||!event.isTrusted)return;
  const target=event.target;
  if(!(target instanceof Element)||target.closest("input,textarea,select,[contenteditable],[data-analytics-ignore]"))return;
  const width=Math.max(document.documentElement.scrollWidth,innerWidth),height=Math.max(document.documentElement.scrollHeight,innerHeight);
  if(!width||!height)return;
  clicks++;send("click",{x:Math.min(100,Math.max(0,event.pageX/width*100)),y:Math.min(100,Math.max(0,event.pageY/height*100))});
},{passive:true});
try {
  const navigation=performance.getEntriesByType("navigation")[0];
  if(navigation&&foregroundLoad)metrics.ttfb=Math.min(300000,Math.max(0,navigation.responseStart-navigation.startTime));
  const observe=(type,handler)=>{if(!PerformanceObserver.supportedEntryTypes.includes(type))return;const observer=new PerformanceObserver(list=>handler(list.getEntries()));observer.observe({type,buffered:true});};
  observe("paint",entries=>{if(!foregroundLoad||restoredAt)return;for(const entry of entries)if(entry.name==="first-contentful-paint")metrics.fcp=Math.min(300000,entry.startTime);});
  observe("largest-contentful-paint",entries=>{if(!foregroundLoad||restoredAt)return;for(const entry of entries)metrics.lcp=Math.min(300000,entry.startTime);});
  // CLS uses the maximum 5s session window with gaps below 1s, not the lifetime
  // sum. No element identity or visual contents are sent with these values.
  metrics.cls_available=foregroundLoad&&PerformanceObserver.supportedEntryTypes.includes("layout-shift");
  observe("layout-shift",entries=>{if(!foregroundLoad)return;for(const entry of entries){if(entry.hadRecentInput||entry.startTime<restoredAt)continue;if(entry.startTime-lastShift<1000&&entry.startTime-windowStart<5000)windowValue+=entry.value;else{windowStart=entry.startTime;windowValue=entry.value;}lastShift=entry.startTime;metrics.cls=Math.min(100,Math.max(metrics.cls,windowValue));}});
} catch {}
// Only the standard numeric INP value is retained. The library's attribution,
// event entries, navigation URL, DOM target and metric ID are never sent. It
// accounts for interaction grouping, long-visit outliers and BFCache resets.
// Unsupported browsers and visits with no measured interaction stay unknown,
// rather than being assigned a fabricated zero. This is document INP, not an
// invented per-SPA-route metric; navigation below remains the document visit.
try {
  webVitals.onINP(metric=>{
    if(!foregroundLoad||!Number.isFinite(metric.value)||metric.value<0)return;
    metrics.inp=Math.min(300000,metric.value);metrics.inp_available=true;
    // Visibility listeners may run before the library flushes pending entries.
    // A value-change callback emits the final update with a monotonic sequence.
    sendPerformance();
  },{reportAllChanges:true,durationThreshold:40});
} catch {}
