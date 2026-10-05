"use strict";
// First-party telemetry only. No forms, text selections, cookies, DOM recording,
// fingerprinting, third-party URLs or full query strings are collected.
if (navigator.doNotTrack === "1" || navigator.globalPrivacyControl === true) return;
const script = document.currentScript;
if (!script || !script.src) return;
const endpoint = new URL(script.src);
endpoint.pathname = endpoint.pathname.replace(/tracker\.js$/, "event");
endpoint.search = new URLSearchParams({site: config.site, key: config.key}).toString();
const valid = value => typeof value === "string" && /^[a-f0-9]{32}$/.test(value);
const identifier = () => [...crypto.getRandomValues(new Uint8Array(16))].map(v=>v.toString(16).padStart(2,"0")).join("");
let visitor, session;
try {
  let data = JSON.parse(localStorage.getItem("yz.analytics.visitor") || "null");
  if (!data || !valid(data.id) || !Number.isFinite(data.created) || Date.now()-data.created>90*86400000) {
    data = {id:identifier(),created:Date.now()};
    localStorage.setItem("yz.analytics.visitor",JSON.stringify(data));
  }
  visitor = data.id;
} catch { visitor=identifier(); }
try {
  let data = JSON.parse(sessionStorage.getItem("yz.analytics.session") || "null");
  if (!data || !valid(data.id) || !Number.isFinite(data.last) || Date.now()-data.last>1800000) data={id:identifier()};
  data.last=Date.now();session=data.id;
  sessionStorage.setItem("yz.analytics.session",JSON.stringify(data));
} catch { session=identifier(); }
let path=location.pathname, title=(document.title || "").slice(0,128),pageID=identifier();
const navigation={path,title,page_id:pageID};
let foregroundLoad=document.visibilityState==="visible",restoredAt=0,windowStart=0,lastShift=0,windowValue=0;
let stopped=false, clicks=0, sent=0;
const metrics={ttfb:0,fcp:0,lcp:0,cls:0,cls_available:false};
const send = (kind, fields={}) => {
  if (stopped || sent>=240) return;
  sent++;
  const body=JSON.stringify({id:identifier(),page_id:pageID,visitor,session,kind,path,title,...fields});
  // Same-origin reverse proxy is required. Do not send panel cookies or retry
  // failed beacons. The host's CSP and privacy policy remain authoritative.
  try { fetch(endpoint.href,{method:"POST",body,headers:{"Content-Type":"application/json"},credentials:"omit",cache:"no-store",keepalive:true,redirect:"error",mode:"same-origin"}).then(r=>{if(r.status===429||r.status===503)stopped=true;}).catch(()=>{}); } catch {}
};
const pageview=() => {
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
  if(document.visibilityState==="hidden"){engagement();visibleSince=null;sendPerformance();}
  else visibleSince=performance.now();
});
window.addEventListener("pagehide",()=>{engagement();visibleSince=null;sendPerformance();clearInterval(timer);timer=null;});
// A persisted pageshow is a new perceived visit, not an ordinary load event.
// Restart engagement and CLS; navigation/paint times are unknown on restoration.
window.addEventListener("pageshow",event=>{if(event.persisted){
  foregroundLoad=document.visibilityState==="visible";restoredAt=performance.now();visibleSince=foregroundLoad?restoredAt:null;
  pageID=identifier();pageview();Object.assign(navigation,{path,title,page_id:pageID});
  metrics.ttfb=metrics.fcp=metrics.lcp=metrics.cls=0;windowStart=lastShift=windowValue=0;
  try{metrics.cls_available=foregroundLoad&&PerformanceObserver.supportedEntryTypes.includes("layout-shift");}catch{metrics.cls_available=false;}
  if(timer===null)timer=setInterval(engagement,30000);
}});
// Navigation timing is for the original document only, not SPA route changes.
const route=()=>{if(location.pathname!==path){engagement();pageID=identifier();pageview();}};
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
