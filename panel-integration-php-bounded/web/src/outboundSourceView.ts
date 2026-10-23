export interface OutboundSourceRow {id:string;event_id:string;state:'source_blocked'|'source_resolved';attempts:0;http_status:0;error:string;created_at:number;completed_at:number;day:string;source_sha:string;channel_revision:number}
const object=(v:unknown):v is Record<string,unknown>=>!!v&&typeof v==='object'&&!Array.isArray(v)&&Object.getPrototypeOf(v)===Object.prototype;
const id=(v:unknown):v is string=>typeof v==='string'&&/^[a-f0-9]{32}$/.test(v);
const sha=(v:unknown):v is string=>typeof v==='string'&&/^[a-f0-9]{64}$/.test(v);
const integer=(v:unknown,min=0,max=Number.MAX_SAFE_INTEGER):v is number=>typeof v==='number'&&Number.isSafeInteger(v)&&v>=min&&v<=max;
const day=(v:unknown):boolean=>typeof v==='string'&&(v===''||/^\d{4}-\d{2}-\d{2}$/.test(v)&&Number.isFinite(Date.parse(v+'T00:00:00Z'))&&new Date(v+'T00:00:00Z').toISOString().slice(0,10)===v);
const sourceKeys=['id','event_id','state','attempts','http_status','error','created_at','completed_at','day','source_sha','channel_revision'];
const exact=(v:Record<string,unknown>,keys:string[])=>Object.keys(v).length===keys.length&&keys.every(k=>Object.hasOwn(v,k));
const deliveryKeys=['id','event_id','state','attempts','http_status','error','created_at','completed_at'];
const summaryKeys=['kind','event_type','title','message','severity','event_created_at','test'];
function deliverySummaryValid(v:Record<string,unknown>):boolean {
 const supplied=summaryKeys.some(k=>Object.hasOwn(v,k));
 if(!supplied)return exact(v,deliveryKeys); // Explicit legacy wire format, not fabricated summary.
 if(!exact(v,[...deliveryKeys,...summaryKeys])||typeof v.kind!=='string'||!['test','schedule','remote','monitor','integrity','sync','daily','php-security','load-balance','load-balance-traffic','load-balance-source'].includes(v.kind)||typeof v.event_type!=='string'||typeof v.title!=='string'||v.title.length<1||v.title.length>120||typeof v.message!=='string'||v.message.length<1||v.message.length>256||!['info','warning','critical'].includes(String(v.severity))||!integer(v.event_created_at,1)||typeof v.test!=='boolean')return false;
 if(v.kind==='load-balance-source')return ['source_unavailable','source_ready'].includes(v.event_type);
 if(v.kind==='load-balance-traffic')return ['','traffic_committed','traffic_recovered','traffic_pending','worker_observation'].includes(v.event_type);
 return v.event_type==='';
}
export function outboundSourceInventory(value:unknown):{rows:OutboundSourceRow[];total:number}|undefined {
 if(!object(value)||!Array.isArray(value.deliveries)||value.deliveries.length>100||!Array.isArray(value.blocked_sources)||value.blocked_sources.length>100||!integer(value.blocked_source_total,value.blocked_sources.length,10000)||value.blocked_source_limit!==100)return;
 const seen=new Set<string>(),events=new Set<string>();
 for(const b of value.blocked_sources){
  if(!object(b)||!exact(b,sourceKeys)||!id(b.id)||seen.has(b.id)||!id(b.event_id)||events.has(b.event_id)||!['source_blocked','source_resolved'].includes(String(b.state))||b.attempts!==0||b.http_status!==0||!sha(b.source_sha)||!integer(b.channel_revision,1)||!integer(b.created_at,1)||!integer(b.completed_at)||typeof b.error!=='string'||b.error.length>256||!day(b.day)||b.state==='source_blocked'&&b.completed_at!==0||b.state==='source_resolved'&&Number(b.completed_at)<1)return;
  seen.add(b.id);events.add(b.event_id);
 }
 const delivered=new Set<string>();
 for(const d of value.deliveries){
  if(!object(d)||!deliverySummaryValid(d)||!id(d.id)||seen.has(d.id)||!id(d.event_id)||delivered.has(d.event_id)||!['pending','running','succeeded','failed','cancelled'].includes(String(d.state))||!integer(d.attempts,0,6)||!integer(d.http_status,0,599)||!integer(d.created_at,1)||!integer(d.completed_at)||typeof d.error!=='string'||d.error.length>2048)return;
  if(value.blocked_sources.some(b=>b.event_id===d.event_id&&b.state==='source_blocked'))return;
  seen.add(d.id);delivered.add(d.event_id);
 }
 return {rows:value.blocked_sources as unknown as OutboundSourceRow[],total:value.blocked_source_total};
}
export function outboundSourceReplyMatches(row:Pick<OutboundSourceRow,'id'|'event_id'>,value:unknown):boolean {
 return object(value)&&exact(value,['id','event_id','state','delivery_id','already_resolved'])&&value.id===row.id&&value.event_id===row.event_id&&value.state==='resolved'&&id(value.delivery_id)&&typeof value.already_resolved==='boolean';
}
