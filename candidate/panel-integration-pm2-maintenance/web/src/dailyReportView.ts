import {resourcePercent} from './resourceMetrics';
const object=(v:unknown):Record<string,unknown>|undefined=>v!==null&&typeof v==='object'&&!Array.isArray(v)?v as Record<string,unknown>:undefined;
const count=(v:unknown):number|null=>typeof v==='number'&&Number.isSafeInteger(v)&&v>=0&&v<=1e9?v:null;
const validDay=(v:unknown):v is string=>typeof v==='string'&&/^\d{4}-\d{2}-\d{2}$/.test(v)&&!Number.isNaN(Date.parse(v+'T00:00:00Z'))&&new Date(v+'T00:00:00Z').toISOString().slice(0,10)===v;
export function dailySnapshot(value:unknown):boolean {
 const r=object(value);return !!r&&!Array.isArray(r.reports)&&!Array.isArray(r.history);
}
export function dailySummary(value:unknown) {
 const r=object(value)||{},resources=object(r.resources)||{};
 const counts=[['sites','网站总数'],['running_sites','运行网站'],['failed_site_jobs','失败网站任务'],['failed_runtime_jobs','失败运行时任务'],['certificates_due_14_days','14 天内到期证书'],['audit_events_24h','24 小时审计事件']].map(([key,label])=>({key,label,value:count(r[key])}));
 const metrics=[['cpu_percent','cpu_available','CPU 使用率'],['memory_percent','memory_available','内存使用率'],['disk_percent','disk_percent_available','磁盘使用率']].map(([key,flag,label])=>{
  return {key,label,value:resourcePercent(resources[key],resources[flag],key==='cpu_percent')};
 });
 const traffic=object(r.traffic),days=traffic?.days;
 const seen=new Set<string>();
 const trafficValid=Array.isArray(days)&&days.length<=31&&days.every(day=>{const d=object(day);if(!d||typeof d.date!=='string'||!/^\d{4}-\d{2}-\d{2}$/.test(d.date)||Number.isNaN(Date.parse(d.date+'T00:00:00Z'))||new Date(d.date+'T00:00:00Z').toISOString().slice(0,10)!==d.date||seen.has(d.date)||count(d.requests)===null||typeof d.bytes!=='number'||!Number.isSafeInteger(d.bytes)||d.bytes<0)return false;seen.add(d.date);return true;});
 return {counts,metrics,createdAt:typeof r.created_at==='string'&&!Number.isNaN(Date.parse(r.created_at))?r.created_at:undefined,trafficDays:trafficValid?days as {date:string;bytes:number;requests:number}[]:undefined,trafficPartial:traffic?.partial===true,trafficFailed:typeof r.traffic_error==='string',securityFailed:typeof r.security_error==='string',security:Array.isArray(r.security)&&r.security.length<=128?r.security.map(v=>{const row=object(v)||{};return {id:typeof row.id==='string'?row.id:'身份待核对',state:row.state_unknown===true||typeof row.installed!=='boolean'||typeof row.healthy!=='boolean'?'待核对':!row.installed?'未安装':row.healthy?'状态检查通过':'状态异常'};}):undefined};
}

export function dailyWorkerMessage(value:unknown,now=Date.now()):{message:string;observed:boolean} {
 const r=object(value);
 if(!r)return {message:'后台生成状态尚未核对；打开此页不会生成或改写日报。',observed:false};
 if(r.running!==true)return {message:'后台生成进程尚未启动或已停止；原报告仍可读取，不据此认定自动生成正在运行。',observed:false};
 const checked=typeof r.checked_at==='string'&&/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/.test(r.checked_at)?Date.parse(r.checked_at):NaN;
 if(r.fresh!==true||!Number.isFinite(now)||!Number.isFinite(checked)||new Date(checked).toISOString().replace(/\.000Z$/,'Z')!==r.checked_at||checked>now||now-checked>130000)return {message:'后台生成状态尚未核对或已过期；保留原报告，不以旧状态认定正常。',observed:false};
 if(r.state==='saved'&&validDay(r.report_day))return {message:`后台已核对 ${r.report_day} 的保存日报；不代表邮件或 Webhook 已送达。`,observed:true};
 const messages:Record<string,string>={starting:'后台生成进程正在准备，尚未完成核对。',status_unknown:'应用身份或运行状态待核对；后台未生成或覆盖日报。',inactive:'应用未安装或未启用；后台不生成日报。',blocked_original:'今日原日报无法核对；已保留原记录，后台未重新生成或覆盖。',generation_failed:'后台生成失败：资源、业务读取或原子保存未完成；没有据此认定日报已生成。',saved_partial:'日报已保存，但部分来源采集失败；查看保存报告，不能据此认定全量采集正常。'};
 return {message:messages[String(r.state)]||'后台生成状态无法核对；不据此认定成功。',observed:false};
}
