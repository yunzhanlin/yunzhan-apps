export type WAFFilters={site_id:string;ip:string;rule:string;action:string};
export type WAFRange={from:string;to:string};
export type WAFDraft=WAFFilters & Partial<WAFRange>;
const fields=['site_id','ip','rule','action'] as const;
const hour=3600_000;
function seconds(value: Date):string {
 return value.toISOString().replace(/\.\d{3}Z$/,'Z');
}
export function wafDraft(filters: WAFFilters,range?:[Date,Date]|null):WAFDraft {
 const draft={...filters,ip:filters.ip.trim()};
 if(!range)return draft;
 if(range.length!==2 || !range.every(value=>value instanceof Date && Number.isFinite(value.getTime())))throw Error('请选择有效的起止时间。');
 const from=seconds(range[0]),to=seconds(range[1]);
 if(from>=to || Date.parse(to)-Date.parse(from)>90*24*hour)throw Error('日志查询的开始时间必须早于结束时间，范围最多 90 天。');
 return {...draft,from,to};
}
export function wafReportSearch(draft:WAFDraft,page:number,limit:number,window?:WAFRange):string {
 const q=new URLSearchParams({page:String(page),limit:String(limit)});
 for(const key of fields)if(draft[key])q.set(key,draft[key]);
 const actual=window||draft;
 if(actual.from&&actual.to){q.set('from',actual.from);q.set('to',actual.to);}
 return q.toString();
}
const nonnegative=(v:unknown):v is number=>typeof v==='number'&&Number.isSafeInteger(v)&&v>=0;
const utc=(v:unknown):v is string=>typeof v==='string'&&/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/.test(v)&&Number.isFinite(Date.parse(v))&&seconds(new Date(v))===v;
export function wafReportScope(reply:unknown,draft:WAFDraft,page:number,limit:number,window?:WAFRange):WAFRange|undefined {
 if(!reply||typeof reply!=='object'||Array.isArray(reply))return;
 const r=reply as Record<string,unknown>,f=r.filters as Record<string,unknown>|undefined;
 if(!f||typeof f!=='object'||Array.isArray(f)||!fields.every(k=>f[k]===draft[k]))return;
 const {from,to}=r;
 if(!utc(from)||!utc(to)||from>=to||Date.parse(to)-Date.parse(from)>90*24*hour||r.page!==page||r.limit!==limit)return;
 const requested=window||draft;
 if(requested.from&&requested.to&&(from!==requested.from||to!==requested.to))return;
 if(!requested.from && Date.parse(to)-Date.parse(from)!==24*hour)return;
 const {total,scanned,blocked,observed,sources,events}=r;
 if(!nonnegative(total)||!nonnegative(scanned)||!nonnegative(blocked)||!nonnegative(observed)||!nonnegative(sources)||
  blocked+observed!==total||total>scanned||sources>total||typeof r.partial!=='boolean'||!Array.isArray(events)||
  events.length!==Math.min(limit,Math.max(0,total-(page-1)*limit)))return;
 return {from,to};
}
