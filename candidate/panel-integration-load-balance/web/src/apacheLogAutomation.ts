import {apacheLogArchive,logID,logObject,type ApacheLogArchive} from "./apacheNumericLogs";
export interface ApacheAutomationPolicy {enabled:boolean;rotate_mib:number;max_age_minutes:number}
export interface ApacheAutomationRecord {
 format:1;config_revision:number;policy:ApacheAutomationPolicy;id:string;
 state:"idle"|"rotating"|"completed"|"blocked"|"unknown"|"retained_unknown";
 window_started_at:string;checked_at:string;last_rotation_at?:string;policy_revision:number;
 log_bytes:number;archive_count:number;archive?:ApacheLogArchive;error_code?:string;
 history:{id:string;at:string;outcome:"completed"|"unknown_retained";archive?:ApacheLogArchive}[];
}
export interface ApacheAutomationStatus {
 configured:boolean;policy_revision:number;policy:ApacheAutomationPolicy;
 record:ApacheAutomationRecord|null;record_sha256:string;read_only:true;core_maintenance:true;
 check_interval_seconds:60;automatic_deletion:false;
}
export const apacheAutomationDefaults=():ApacheAutomationPolicy=>({enabled:false,rotate_mib:16,max_age_minutes:60});
const integer=(v:unknown,min:number,max:number):v is number=>typeof v==="number"&&Number.isSafeInteger(v)&&v>=min&&v<=max;
const utc=(v:unknown):v is string=>typeof v==="string"&&/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/.test(v)&&Number.isFinite(Date.parse(v));
const sha=(v:unknown):v is string=>typeof v==="string"&&/^[a-f0-9]{64}$/.test(v);
const keys=(v:Record<string,unknown>,required:string[],optional:string[]=[])=>required.every(k=>Object.hasOwn(v,k))&&Object.keys(v).every(k=>required.includes(k)||optional.includes(k));
export const sameApacheAutomationPolicy=(a:ApacheAutomationPolicy,b:ApacheAutomationPolicy)=>a.enabled===b.enabled&&a.rotate_mib===b.rotate_mib&&a.max_age_minutes===b.max_age_minutes;
export function apacheAutomationPolicy(v:unknown):v is ApacheAutomationPolicy {
 return logObject(v)&&keys(v,["enabled","rotate_mib","max_age_minutes"])&&typeof v.enabled==="boolean"&&integer(v.rotate_mib,1,28)&&integer(v.max_age_minutes,10,1440);
}
function record(v:unknown):v is ApacheAutomationRecord {
 if(!logObject(v)||!keys(v,["format","config_revision","policy","id","state","window_started_at","checked_at","policy_revision","log_bytes","archive_count","history"],["last_rotation_at","archive","error_code"])||v.format!==1||!integer(v.config_revision,1,1000000000)||!apacheAutomationPolicy(v.policy)||!logID(v.id)||typeof v.state!=="string"||!["idle","rotating","completed","blocked","unknown","retained_unknown"].includes(v.state)||!utc(v.window_started_at)||!utc(v.checked_at)||v.last_rotation_at!==undefined&&!utc(v.last_rotation_at)||!integer(v.policy_revision,0,Number.MAX_SAFE_INTEGER)||!integer(v.log_bytes,0,33554432)||!integer(v.archive_count,0,8)||v.error_code!==undefined&&!["archive_capacity","history_capacity","rotation_failed","verification_failed"].includes(v.error_code as string)||v.archive!==undefined&&(!apacheLogArchive(v.archive)||!["copying","prepared","completed"].includes(v.archive.state))||!Array.isArray(v.history)||v.history.length>16)return false;
 if(v.state==="completed"&&(!v.last_rotation_at||!apacheLogArchive(v.archive)||v.archive.state!=="completed"))return false;
 if(!v.history.every(h=>logObject(h)&&keys(h,["id","at","outcome"],["archive"])&&logID(h.id)&&utc(h.at)&&["completed","unknown_retained"].includes(h.outcome as string)&&(h.archive===undefined||apacheLogArchive(h.archive)&&["copying","prepared","completed"].includes(h.archive.state))&&(h.outcome!=="completed"||apacheLogArchive(h.archive)&&h.archive.state==="completed")))return false;
 return new Set(v.history.map(h=>h.id)).size===v.history.length;
}
export function apacheAutomationStatus(v:unknown):v is ApacheAutomationStatus {
 if(!logObject(v)||!keys(v,["configured","policy_revision","policy","record","record_sha256","read_only","core_maintenance","check_interval_seconds","automatic_deletion"])||typeof v.configured!=="boolean"||!integer(v.policy_revision,0,1000000000)||!apacheAutomationPolicy(v.policy)||v.read_only!==true||v.core_maintenance!==true||v.check_interval_seconds!==60||v.automatic_deletion!==false)return false;
 if(!v.configured)return v.policy_revision===0&&v.record===null&&v.record_sha256===""&&sameApacheAutomationPolicy(v.policy,apacheAutomationDefaults());
 return record(v.record)&&sha(v.record_sha256)&&v.record.config_revision===v.policy_revision&&sameApacheAutomationPolicy(v.record.policy,v.policy);
}
