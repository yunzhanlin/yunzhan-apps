import {platformReadKnown} from './platformManagementReceipt.ts';

export type PlatformMetric = {label:string; percent:number|null; capacity?:string};
export type PlatformHostView = {
  source:Record<string,any>; id:string; url:string; passed:boolean;
  error:string; status?:number; complete:boolean; metrics:PlatformMetric[];
  hostname:string; system:string; nginx:string; sampledAt:string; reportAt:string;
};
export type PlatformFleetView = {
  checkedAt:string; stale:boolean; hosts:PlatformHostView[];
  passed:number; failed:number; unknownMetrics:number;
};
const object=(v:unknown):v is Record<string,any>=>!!v&&typeof v==='object'&&!Array.isArray(v);
const percent=(v:unknown):v is number=>typeof v==='number'&&Number.isFinite(v)&&v>=0&&v<=100;
const count=(v:unknown):v is number=>typeof v==='number'&&Number.isSafeInteger(v)&&v>=0;
const text=(v:unknown)=>typeof v==='string'&&v.length<=256&&!/[\x00-\x1f\x7f]/.test(v)?v:'';
const stamp=(v:unknown):v is string=>typeof v==='string'&&/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/.test(v)&&Number.isFinite(Date.parse(v))&&new Date(v).toISOString().replace(/\.000Z$/,'Z')===v;
export function platformBytes(v:unknown):string {
  if(!count(v))return '未知';
  const units=['B','KiB','MiB','GiB','TiB','PiB'];let n=v,i=0;
  while(n>=1024&&i<units.length-1){n/=1024;i++;}
  return `${n.toFixed(i?1:0)} ${units[i]}`;
}
// A view of the exact returned snapshot, never a new sampler or a mutation.
// Unknown availability cannot become 0%. Identity/ordering/SHA are untouched.
export function platformFleetView(value:unknown,now=Date.now()):PlatformFleetView|undefined {
  if(!platformReadKnown('run',value)||!object(value)||!Number.isFinite(now))return;
  const hosts:PlatformHostView[]=[];
  for(const row of value.hosts){
    if(row.status!==undefined&&(!Number.isInteger(row.status)||row.status<100||row.status>599))return;
    let metrics:PlatformMetric[]=['CPU','内存','磁盘'].map(label=>({label,percent:null}));
    let hostname='',system='',nginx='未知',sampledAt='',reportAt='',complete=false;
    if(row.healthy){
      const h=row.report.health;
      if(!stamp(h.sampled_at)||!count(h.cpu_cores)||h.cpu_cores<1||h.cpu_cores>65536||typeof h.nginx_active!=='boolean')return;
      const fields=[['CPU','cpu_available','cpu_percent'],['内存','memory_available','memory_percent'],['磁盘','disk_percent_available','disk_percent']];
      metrics=[];
      for(const [label,flag,key] of fields){
        if(typeof h[flag]!=='boolean'||(h[flag]? !percent(h[key]):h[key]!==null))return;
        const metric:PlatformMetric={label,percent:h[flag]?h[key]:null};
        if(h[flag]&&label!=='CPU'){
          const prefix=label==='内存'?'memory':'disk',total=h[prefix+'_total'],used=h[prefix+'_used'];
          if(!count(total)||total===0||!count(used)||used>total)return;
          metric.capacity=`${platformBytes(used)} / ${platformBytes(total)}`;
        }
        metrics.push(metric);
      }
      complete=metrics.every(m=>m.percent!==null);
      if(row.telemetry_complete!==complete)return;
      hostname=text(h.hostname);system=[text(h.os),text(h.arch)].filter(Boolean).join(' · ');
      nginx=h.nginx_active?'运行中':'未运行';sampledAt=h.sampled_at;reportAt=row.report.time;
    }
    hosts.push({source:row,id:row.id,url:row.url,passed:row.healthy,error:row.healthy?'':row.error,status:row.status,complete,metrics,hostname,system,nginx,sampledAt,reportAt});
  }
  const age=now-Date.parse(value.checked_at);
  return {checkedAt:value.checked_at,stale:age>120000||age< -30000,hosts,passed:hosts.filter(h=>h.passed).length,failed:hosts.filter(h=>!h.passed).length,unknownMetrics:hosts.filter(h=>!h.complete).length};
}
export function platformHostFilter(hosts:PlatformHostView[],query:string,state:string):PlatformHostView[]{
  const q=query.slice(0,128).trim().toLocaleLowerCase();
  return hosts.filter(h=>(!q||[h.id,h.url,h.hostname,h.system].some(s=>s.toLocaleLowerCase().includes(q)))&&(state==='failed'?!h.passed:state==='unknown'?!h.complete:true));
}
