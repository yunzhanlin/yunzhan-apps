import type {ApacheBodyEvent} from "./apacheBodyReport";
export interface ApacheLogArchive {id:string;captured_at:string;bytes:number;sha256:string;state:"copying"|"prepared"|"completed"|"retained"|"retained-incomplete"|"retained-missing"|"removing"}
export interface ApacheLogRecovery {archive:ApacheLogArchive;index_sha256:string;snapshot_sha256:string;snapshot_bytes:number;snapshot_missing:boolean}
export interface ApacheLogStage {id:string;bytes:number;sha256:string}
export interface ApacheLogInventory {archives:ApacheLogArchive[];recovery:ApacheLogRecovery[];index_stages:ApacheLogStage[];inventory_complete:true;maintenance_healthy:boolean;max_archives:8;max_archive_bytes:33554432;read_only:true;numeric_only:true;rotation_reloads_apache:false}
type NumericPage={events:ApacheBodyEvent[];available:boolean;partial:boolean;rejected_lines:number;log_bytes:number;max_bytes:number;capacity_near_limit:boolean;metadata_best_effort:true};
export interface ApacheLogExport {archive:ApacheLogArchive;metadata:NumericPage;export_contract:string;selected_snapshot_digest_verified?:true;inventory_not_claimed_complete?:true}
export const logObject=(v:unknown):v is Record<string,unknown>=>v!==null && typeof v==="object" && !Array.isArray(v);
export const logID=(v:unknown):v is string=>typeof v==="string" && /^[a-f0-9]{32}$/.test(v);
const sha=(v:unknown):v is string=>typeof v==="string" && /^[a-f0-9]{64}$/.test(v);
const integer=(v:unknown,min:number,max:number):v is number=>typeof v==="number" && Number.isSafeInteger(v) && v>=min && v<=max;
const utc=(v:unknown):v is string=>typeof v==="string" && /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?Z$/.test(v) && Number.isFinite(Date.parse(v));
const exact=(v:Record<string,unknown>,fields:string[])=>Object.keys(v).length===fields.length && fields.every(k=>Object.hasOwn(v,k));
const sameArchive=(a:ApacheLogArchive,b:ApacheLogArchive)=>a.id===b.id && a.captured_at===b.captured_at && a.bytes===b.bytes && a.sha256===b.sha256 && a.state===b.state;
export function apacheLogArchive(v:unknown):v is ApacheLogArchive {
 return logObject(v) && exact(v,["id","captured_at","bytes","sha256","state"]) && logID(v.id) && utc(v.captured_at) && integer(v.bytes,0,33554432) && sha(v.sha256) && typeof v.state==="string" && ["copying","prepared","completed","retained","retained-incomplete","retained-missing","removing"].includes(v.state) && (v.bytes>0 || ["retained-incomplete","removing"].includes(v.state));
}
export function apacheLogInventory(v:unknown):v is ApacheLogInventory {
 if(!logObject(v) || !exact(v,["archives","recovery","index_stages","inventory_complete","maintenance_healthy","max_archives","max_archive_bytes","read_only","numeric_only","rotation_reloads_apache"]) || v.inventory_complete!==true || v.read_only!==true || v.numeric_only!==true || v.rotation_reloads_apache!==false || v.max_archives!==8 || v.max_archive_bytes!==33554432 || typeof v.maintenance_healthy!=="boolean" || !Array.isArray(v.archives) || v.archives.length>8 || !v.archives.every(apacheLogArchive) || new Set(v.archives.map(x=>x.id)).size!==v.archives.length || !Array.isArray(v.recovery) || v.recovery.length>8 || !Array.isArray(v.index_stages) || v.index_stages.length>8)return false;
 const rows=v.archives as ApacheLogArchive[];
 if(!v.recovery.every(r=>logObject(r) && exact(r,["archive","index_sha256","snapshot_sha256","snapshot_bytes","snapshot_missing"]) && apacheLogArchive(r.archive) && ["copying","prepared","removing"].includes(r.archive.state) && rows.some(a=>sameArchive(a,r.archive as ApacheLogArchive)) && sha(r.index_sha256) && integer(r.snapshot_bytes,0,33554432) && typeof r.snapshot_missing==="boolean" && (r.snapshot_missing?r.snapshot_sha256==="" && r.snapshot_bytes===0:sha(r.snapshot_sha256))))return false;
 const recoveries=v.recovery as ApacheLogRecovery[];
 if(new Set(recoveries.map(x=>x.archive.id)).size!==recoveries.length || rows.filter(a=>["copying","prepared","removing"].includes(a.state)).length!==recoveries.length)return false;
 if(!v.index_stages.every(s=>logObject(s) && exact(s,["id","bytes","sha256"]) && logID(s.id) && integer(s.bytes,0,1024) && sha(s.sha256)) || new Set(v.index_stages.map(s=>s.id)).size!==v.index_stages.length)return false;
 return v.maintenance_healthy===(recoveries.length===0 && v.index_stages.length===0 && rows.every(a=>a.state==="completed"));
}
export function apacheLogExport(v:unknown,selected:ApacheLogArchive):v is ApacheLogExport {
 if(!logObject(v) || !apacheLogArchive(v.archive) || v.archive.id!==selected.id || v.archive.sha256!==selected.sha256 || v.archive.bytes!==selected.bytes || v.archive.state==="copying" || !logObject(v.metadata))return false;
 const outer=v.archive.state==="retained-missing"?["archive","metadata","export_contract"]:["archive","metadata","export_contract","selected_snapshot_digest_verified","inventory_not_claimed_complete"];
 if(!exact(v,outer))return false;
 const p=v.metadata;
 if(!exact(p,["events","available","partial","rejected_lines","log_bytes","max_bytes","capacity_near_limit","metadata_best_effort"]) || typeof p.available!=="boolean" || typeof p.partial!=="boolean" || typeof p.capacity_near_limit!=="boolean" || p.metadata_best_effort!==true || !integer(p.rejected_lines,0,4194304) || !integer(p.log_bytes,0,33554432) || !Array.isArray(p.events) || p.events.length>5000 || ![0,33554432].includes(p.max_bytes as number))return false;
 if(!p.events.every(e=>logObject(e) && exact(e,["time","engine_version","site_id","rule_id","phase","severity","mode","intercepted_mark"]) && utc(e.time) && e.engine_version==="2.9.15-yz5" && logID(e.site_id) && integer(e.rule_id,1,99999999) && integer(e.phase,1,5) && integer(e.severity,0,7) && ["observe","block"].includes(e.mode as string) && typeof e.intercepted_mark==="boolean" && (!e.intercepted_mark || e.mode==="block")))return false;
 if(v.archive.state==="retained-missing")return v.export_contract==="missing_snapshot_intent_only_no_rule_events_available" && !p.available && p.events.length===0 && p.log_bytes===0;
 return p.available===true && p.max_bytes===33554432 && p.log_bytes===selected.bytes && v.selected_snapshot_digest_verified===true && v.inventory_not_claimed_complete===true && v.export_contract==="numeric_only_recent_4MiB_5000_rules_not_full_raw_archive" && (p.partial===true || p.rejected_lines===0 && !p.capacity_near_limit);
}
export function apacheLogActionReceipt(v:unknown,kind:string,id?:string,digest?:string):boolean {
 if(!logObject(v))return false;
 if(kind==="rotate")return apacheLogArchive(v.archive) && v.archive.state==="completed" && v.same_inode_rotation===true && v.no_apache_reload===true;
 if(kind==="remove")return v.removed===true && v.archive_id===id && v.sha256===digest && v.current_log_untouched===true;
 if(kind==="retain")return v.retained_unknown===true && v.archive_id===id && v.current_log_untouched===true && v.original_rotation_not_repeated===true;
 return kind==="retain-stage" && logID(v.retained_id) && v.uncommitted_index_never_applied===true && v.current_log_untouched===true;
}
