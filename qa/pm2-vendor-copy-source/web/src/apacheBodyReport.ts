export const apacheBodyCounting = "rule_matches_not_unique_requests_or_confirmed_http_blocks";
export const apacheBodyScope = "fixed_numeric_metadata_only_not_activation_health_or_request_receipts";
export interface ApacheBodyEvent {time:string;engine_version:string;site_id:string;rule_id:number;phase:number;severity:number;mode:"block"|"observe";intercepted_mark:boolean}
export interface ApacheBodyReport {events:ApacheBodyEvent[];available:boolean;partial:boolean;rejected_lines:number;log_bytes:number;max_bytes:number;capacity_near_limit:boolean;metadata_best_effort:boolean;rule_matches:number;scanned:number;rules:{name:string;count:number}[];sites:{name:string;count:number}[];from:string;to:string;page:number;limit:number;counting_contract:string;scope:string}
export interface ApacheBodyFilter {site_id:string;rule:string;phase:string;from:string;to:string}
const id=(v:unknown):v is string=>typeof v==="string" && /^[a-f0-9]{32}$/.test(v);
const integer=(v:unknown,min:number,max:number):v is number=>typeof v==="number" && Number.isSafeInteger(v) && v>=min && v<=max;
const record=(v:unknown):v is Record<string,unknown>=>v!==null && typeof v==="object" && !Array.isArray(v);
const exact=(v:Record<string,unknown>,keys:string[])=>Object.keys(v).length===keys.length && keys.every(k=>Object.hasOwn(v,k));
const numberText=(v:string,max:number)=>/^[1-9][0-9]*$/.test(v) && integer(Number(v),1,max);
const utc=(v:unknown):v is string=>typeof v==="string" && /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?Z$/.test(v) && Number.isFinite(Date.parse(v));

export function apacheBodyReportURL(filter:ApacheBodyFilter,page:number,limit=50):string {
  if(!exact(filter as unknown as Record<string,unknown>,["site_id","rule","phase","from","to"]) || !integer(page,1,10000) || !integer(limit,1,1000) || (filter.site_id!=="" && !id(filter.site_id)) || (filter.rule!=="" && !numberText(filter.rule,99999999)) || (filter.phase!=="" && !numberText(filter.phase,5)))throw Error("Apache 数值记录筛选字段无效");
  const q=new URLSearchParams({page:String(page),limit:String(limit)});
  for(const key of ["site_id","rule","phase"] as const)if(filter[key])q.set(key,filter[key]);
  for(const key of ["from","to"] as const)if(filter[key]){if(!utc(filter[key]))throw Error("时间必须是有效 UTC 时间");q.set(key,filter[key]);}
  if(filter.from && filter.to && (Date.parse(filter.from)>=Date.parse(filter.to) || Date.parse(filter.to)-Date.parse(filter.from)>90*86400000))throw Error("时间范围应大于零且不超过 90 天");
  return `/software/apache-waf/body-report?${q}`;
}

export function apacheBodyReportValid(v:unknown,page:number,limit=50):v is ApacheBodyReport {
  if(!record(v) || !exact(v,["events","available","partial","rejected_lines","log_bytes","max_bytes","capacity_near_limit","metadata_best_effort","rule_matches","scanned","rules","sites","from","to","page","limit","counting_contract","scope"]))return false;
  if(v.counting_contract!==apacheBodyCounting || v.scope!==apacheBodyScope || v.metadata_best_effort!==true || v.page!==page || v.limit!==limit || !integer(v.rule_matches,0,5000) || !integer(v.scanned,v.rule_matches,5000) || !integer(v.rejected_lines,0,4194304) || !integer(v.log_bytes,0,33554432) || v.max_bytes!==33554432 || typeof v.available!=="boolean" || typeof v.partial!=="boolean" || typeof v.capacity_near_limit!=="boolean" || !utc(v.from) || !utc(v.to) || Date.parse(v.from)>=Date.parse(v.to) || Date.parse(v.to)-Date.parse(v.from)>90*86400000 || !Array.isArray(v.events) || v.events.length>limit || v.events.length>v.rule_matches)return false;
  if((!v.available && (v.scanned!==0 || v.log_bytes!==0)) || (!v.partial && (v.rejected_lines>0 || v.capacity_near_limit)))return false;
  if(!v.events.every(e=>record(e) && exact(e,["time","engine_version","site_id","rule_id","phase","severity","mode","intercepted_mark"]) && utc(e.time) && Date.parse(e.time)>=Date.parse(v.from as string) && Date.parse(e.time)<=Date.parse(v.to as string) && e.engine_version==="2.9.15-yz5" && id(e.site_id) && integer(e.rule_id,1,99999999) && integer(e.phase,1,5) && integer(e.severity,0,7) && (e.mode==="block" || e.mode==="observe") && typeof e.intercepted_mark==="boolean" && (!e.intercepted_mark || e.mode==="block")))return false;
  for(const [key,rules] of [["rules",true],["sites",false]] as const){
    const rows=v[key];if(!Array.isArray(rows) || rows.length>v.rule_matches)return false;
    const seen=new Set<string>();let total=0;
    for(const row of rows){if(!record(row) || !exact(row,["name","count"]) || typeof row.name!=="string" || !(rules?numberText(row.name,99999999):id(row.name)) || seen.has(row.name) || !integer(row.count,1,v.rule_matches))return false;seen.add(row.name);total+=row.count;}
    if(total!==v.rule_matches)return false;
  }
  return true;
}
