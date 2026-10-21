export interface IntrusionAction { name:string; ports:number[]; protocol:string; scope_verified:boolean; kernel_scope_verified:boolean; kernel_scope_deferred:boolean; kernel_ipv4:boolean; kernel_ipv6:boolean; detail:string }
export interface IntrusionCurrent {format:1;checked_at:string;installed:boolean;version:string;service_active:boolean;config_matches:boolean;healthy:boolean;kernel_scope_verified:boolean;kernel_scope_deferred:boolean;active_bans_known:boolean;active_bans:number;ssh_effective_ports:number[];ssh_listening_ports:number[];ssh_ports_match:boolean;actions:IntrusionAction[];settings:Record<string,number>;runtime_settings:Record<string,number>;warnings:string[];detail:string}
export interface IntrusionTransaction {id:string;sha256:string;action:string;started_at:string;finished_at:string;state:string;before_settings:Record<string,number>;target_settings:Record<string,number>;before_ports:number[];target_ports:number[];ssh_observed_ports:number[];duration_changes_existing_bans:boolean;recovery_permitted:boolean;detail:string}
export interface IntrusionWorkspace {format:1;checked_at:string;state_known:boolean;current:IntrusionCurrent|null;pending:IntrusionTransaction|null;history:IntrusionTransaction[];retained_temporaries:number;ban_duration_semantics:string;detail:string}
export interface IntrusionRequest {id:string;action:string;state:string;created_at:string;request_sha256:string}
export interface IntrusionRequests {actor_id:string;entries:IntrusionRequest[];next_cursor:string;read_only:true}
const object=(v:unknown):v is Record<string,unknown>=>!!v&&typeof v==="object"&&!Array.isArray(v)&&[Object.prototype,null].includes(Object.getPrototypeOf(v));
const keys=(v:Record<string,unknown>,fields:string[])=>Object.keys(v).sort().join(",")===[...fields].sort().join(",");
const text=(v:unknown):v is string=>typeof v==="string"&&new TextEncoder().encode(v).length<=16384;
export const intrusionID=(v:unknown):v is string=>typeof v==="string"&&/^[a-f0-9]{32}$/.test(v);
const digest=(v:unknown)=>typeof v==="string"&&/^[a-f0-9]{64}$/.test(v);
const stamp=(v:unknown)=>typeof v==="string"&&/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/.test(v)&&Number.isFinite(Date.parse(v))&&new Date(v).toISOString().replace(".000Z","Z")===v;
const integer=(v:unknown,min:number,max:number):v is number=>typeof v==="number"&&Number.isSafeInteger(v)&&v>=min&&v<=max;
const ports=(v:unknown,empty=false):v is number[]=>Array.isArray(v)&&v.length<=(16)&&v.length>=(empty?0:1)&&v.every((p,i)=>integer(p,1,65535)&&(i===0||p>v[i-1]));
const settings=(v:unknown,empty=false)=>object(v)&&(empty&&Object.keys(v).length===0||keys(v,["max_retry","find_time_minutes","ban_time_minutes"])&&integer(v.max_retry,2,20)&&integer(v.find_time_minutes,1,1440)&&integer(v.ban_time_minutes,10,10080));
const bools=(v:Record<string,unknown>,names:string[])=>names.every(n=>typeof v[n]==="boolean");
function action(v:unknown):boolean {
  return object(v)&&keys(v,["name","ports","protocol","scope_verified","kernel_scope_verified","kernel_scope_deferred","kernel_ipv4","kernel_ipv6","detail"])&&text(v.name)&&text(v.protocol)&&text(v.detail)&&ports(v.ports,true)&&bools(v,["scope_verified","kernel_scope_verified","kernel_scope_deferred","kernel_ipv4","kernel_ipv6"])&&!(v.kernel_scope_verified&&v.kernel_scope_deferred);
}
function current(v:unknown):boolean {
  if(!object(v)||!keys(v,["format","checked_at","installed","version","service_active","config_matches","healthy","kernel_scope_verified","kernel_scope_deferred","active_bans_known","active_bans","ssh_effective_ports","ssh_listening_ports","ssh_ports_match","actions","settings","runtime_settings","warnings","detail"])||v.format!==1||!stamp(v.checked_at)||!text(v.detail)||!bools(v,["installed","service_active","config_matches","healthy","kernel_scope_verified","kernel_scope_deferred","active_bans_known","ssh_ports_match"])||!text(v.version)||!ports(v.ssh_effective_ports,true)||!ports(v.ssh_listening_ports,true)||!integer(v.active_bans,0,4096)||!settings(v.settings,!v.installed)||!Array.isArray(v.actions)||v.actions.length>16||!v.actions.every(action)||!Array.isArray(v.warnings)||v.warnings.length>64||!v.warnings.every(text)||!object(v.runtime_settings)||Object.keys(v.runtime_settings).some(k=>!["maxretry","findtime","bantime"].includes(k))||!Object.values(v.runtime_settings).every(n=>integer(n,1,604800)))return false;
  if(v.installed&&!["1.0","1.0.0","1.1.0"].includes(v.version))return false;
  if(!v.installed&&(v.version!==""||v.healthy||v.service_active||v.config_matches))return false;
  if(v.ssh_ports_match&&(!v.ssh_effective_ports.length||JSON.stringify(v.ssh_effective_ports)!==JSON.stringify(v.ssh_listening_ports)))return false;
  if(v.healthy&&(!v.actions.length||v.actions.some(a=>!object(a)||a.scope_verified!==true||a.kernel_scope_verified!==true||JSON.stringify(a.ports)!==JSON.stringify(v.ssh_listening_ports))))return false;
  if(v.kernel_scope_verified&&v.kernel_scope_deferred)return false;
  return !v.healthy||(v.installed===true&&v.service_active===true&&v.config_matches===true&&v.ssh_ports_match===true&&v.kernel_scope_verified===true&&v.active_bans_known===true&&v.warnings.length===0&&Object.keys(v.runtime_settings).length===3);
}
function transaction(v:unknown,pending:boolean):v is IntrusionTransaction {
  if(!object(v)||!keys(v,["id","sha256","action","started_at","finished_at","state","before_settings","target_settings","before_ports","target_ports","ssh_observed_ports","duration_changes_existing_bans","recovery_permitted","detail"])||!intrusionID(v.id)||!digest(v.sha256)||!["install","configure","update","uninstall"].includes(String(v.action))||!stamp(v.started_at)||!text(v.detail)||!bools(v,["duration_changes_existing_bans","recovery_permitted"])||!settings(v.before_settings)||!settings(v.target_settings)||!ports(v.before_ports)||!ports(v.target_ports)||!ports(v.ssh_observed_ports))return false;
  if(!object(v.before_settings)||!object(v.target_settings)||v.duration_changes_existing_bans!==(v.before_settings.ban_time_minutes!==v.target_settings.ban_time_minutes))return false;
  return pending ? ["pending","committed_pending_cleanup","rolled_back_pending_cleanup"].includes(String(v.state))&&v.finished_at==="" : ["committed","rolled_back"].includes(String(v.state))&&stamp(v.finished_at)&&String(v.finished_at)>=String(v.started_at)&&v.recovery_permitted===false;
}
export function decodeIntrusionWorkspace(v:unknown):IntrusionWorkspace {
  const bad=()=>new Error("防入侵完整状态不可核对；未采用旧状态、默认值或部分安装结论。");
  if(!object(v)||!keys(v,["format","checked_at","state_known","current","pending","history","retained_temporaries","ban_duration_semantics","detail"])||v.format!==1||!stamp(v.checked_at)||typeof v.state_known!=="boolean"||!integer(v.retained_temporaries,0,128)||!text(v.ban_duration_semantics)||!text(v.detail)||!Array.isArray(v.history)||v.history.length>128||!v.history.every(t=>transaction(t,false))||new Set(v.history.map(t=>t.id)).size!==v.history.length)throw bad();
  if(v.pending!==null){if(!transaction(v.pending,true)||v.state_known||v.current!==null)throw bad();}
  else if(!v.state_known||!current(v.current))throw bad();
  return v as unknown as IntrusionWorkspace;
}
export function decodeIntrusionRequests(v:unknown,cursor=""):IntrusionRequests {
  const bad=()=>new Error("当前账户原请求目录不可核对；未恢复任务或重新提交。");
  if(cursor!==""&&!intrusionID(cursor)||!object(v)||!keys(v,["actor_id","entries","next_cursor","read_only"])||!intrusionID(v.actor_id)||v.read_only!==true||!Array.isArray(v.entries)||v.entries.length>20||typeof v.next_cursor!=="string")throw bad();
  let previous=cursor;
  for(const row of v.entries){if(!object(row)||!keys(row,["id","action","state","created_at","request_sha256"])||!intrusionID(row.id)||row.id<=previous||!["configure","uninstall","recover"].includes(String(row.action))||!["queued","running","succeeded","failed","needs_attention","cancelled"].includes(String(row.state))||!stamp(row.created_at)||!digest(row.request_sha256))throw bad();previous=row.id;}
  if(v.next_cursor!==""&&(v.entries.length!==20||v.next_cursor!==previous))throw bad();
  return v as unknown as IntrusionRequests;
}
