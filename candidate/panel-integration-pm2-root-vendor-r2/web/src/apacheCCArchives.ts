import {browserSHA256} from "./browserSHA256.ts";
export interface CCArchiveRequest {request_id:string;expected_revision:number;allow_incomplete:boolean}
interface CCFile {device:string;inode:string;uid:number;gid:number;bytes:number;sha256:string}
interface CCIntent {format:2;id:string;at:string;request:CCArchiveRequest;source:CCFile;tail_incomplete:boolean}
interface CCPrepared {format:2;id:string;fresh:CCFile;archive:CCFile}
interface CCCompleted {format:2;id:string;at:string;archive:CCFile}
export interface CCSnapshot {format:2;id:string;files:Record<string,CCFile>;source_identity_only:true}
interface CCRetained {format:2;id:string;receipt_id:string;at:string;outcome:"unknown-retained";snapshot:CCSnapshot;snapshot_sha256:string;retention_intent:CCFile;archive?:CCFile;preserved_source?:CCFile;original_current_log:CCFile;no_replay:true;no_name_exchange:true;current_log_untouched:true;original_outcome_unknown:true}
export interface CCArchiveEntry {id:string;state:"unknown"|"completed"|"retained-unknown";record_sha256:Record<string,string>;intent?:CCIntent;prepared?:CCPrepared;completed?:CCCompleted;retained?:CCRetained;problem?:string;source_status?:"matches-witness"|"changed-after-copy"|"not-authoritative"}
export interface CCRecovery {record:CCArchiveEntry;snapshot:CCSnapshot;snapshot_sha256:string;read_only:true;automatic_replay_allowed:false}
export interface CCHistoryObservation {record:CCArchiveEntry;snapshot:CCSnapshot;snapshot_sha256:string;history:boolean;read_only:true;no_delete:true}
export interface CCRetentionTicket {id:string;sha256:string}
interface CCCurrent {available:boolean;bytes:number;max_bytes:33554432;tail_incomplete:boolean;capacity_near_limit:boolean;read_only:true}
export interface CCArchiveInventory {archives:CCArchiveEntry[];history:CCArchiveEntry[];max_history:32;current:CCCurrent;inventory_complete:true;maintenance_healthy:boolean;max_archives:8;max_archive_bytes:33554432;read_only:true;atomic_name_exchange:true;reloads_apache:false}
export interface CCArchiveClosed {format:1;state:"closed-before-archive";at:string;request:CCArchiveRequest}
export type CCRequestObservation = {kind:"archive";record:CCArchiveEntry;read_only:true}|{kind:"closed";record:CCArchiveClosed;sha256:string;read_only?:true;late_dispatch_refused?:true;current_log_untouched?:true}|{kind:"not-recorded";request_id:string;read_only:true;automatic_retry_allowed:false};
const object=(v:unknown):v is Record<string,unknown>=>!!v&&typeof v==="object"&&!Array.isArray(v);
const keys=(v:Record<string,unknown>,required:string[],optional:string[]=[])=>required.every(k=>Object.hasOwn(v,k))&&Object.keys(v).every(k=>required.includes(k)||optional.includes(k));
const integer=(v:unknown,min:number,max:number):v is number=>typeof v==="number"&&Number.isSafeInteger(v)&&v>=min&&v<=max;
const id=(v:unknown):v is string=>typeof v==="string"&&/^[a-f0-9]{32}$/.test(v);
const sha=(v:unknown):v is string=>typeof v==="string"&&/^[a-f0-9]{64}$/.test(v);
const decimal=(v:unknown):v is string=>typeof v==="string"&&/^[1-9][0-9]{0,19}$/.test(v)&&BigInt(v)<=18446744073709551615n;
const utc=(v:unknown):v is string=>typeof v==="string"&&/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/.test(v)&&Number.isFinite(Date.parse(v));
const emptySHA="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
export function ccArchiveRequest(v:unknown):v is CCArchiveRequest {
 return object(v)&&keys(v,["request_id","expected_revision","allow_incomplete"])&&id(v.request_id)&&integer(v.expected_revision,1,1000000000)&&typeof v.allow_incomplete==="boolean";
}
export const sameCCArchiveRequest=(a:CCArchiveRequest,b:CCArchiveRequest)=>a.request_id===b.request_id&&a.expected_revision===b.expected_revision&&a.allow_incomplete===b.allow_incomplete;
function file(v:unknown):v is CCFile {
 return object(v)&&keys(v,["device","inode","uid","gid","bytes","sha256"])&&decimal(v.device)&&decimal(v.inode)&&integer(v.uid,0,4294967295)&&integer(v.gid,0,4294967295)&&integer(v.bytes,0,33554432)&&sha(v.sha256);
}
// The service and native reader can use different Root groups. Preserve
// every recorded GID in hashes and exact file identities.
const sameFile=(a:CCFile,b:CCFile)=>a.device===b.device&&a.inode===b.inode&&a.uid===b.uid&&a.gid===b.gid&&a.bytes===b.bytes&&a.sha256===b.sha256;
const retentionName=(name:string)=>/^retain-(?:intent-)?[a-f0-9]{32}\.json$/.test(name);
function snapshot(v:unknown,wanted:string):v is CCSnapshot {
 if(!object(v)||!keys(v,["format","id","files","source_identity_only"])||v.format!==2||v.source_identity_only!==true||v.id!==wanted||!object(v.files)||Object.keys(v.files).length>21)return false;
 const attempts=new Set<string>();
 for(const [name,value] of Object.entries(v.files)){
  if(!file(value))return false;
  if(name==="data.log"){if(value.uid!==0)return false;continue;}
  if(name==="next.log"){if((value.uid!==0&&value.gid===0)||value.bytes!==0||value.sha256!==emptySHA)return false;continue;}
  if(retentionName(name))attempts.add(name.replace(/^retain-(?:intent-)?/,"").slice(0,-5));
  else if(!["intent.json","prepared.json","completed.json"].includes(name))return false;
  if(value.uid!==0||value.bytes>(retentionName(name)?16384:4096))return false;
 }
 return attempts.size<=8;
}
export function ccSnapshotSHA(v:CCSnapshot):string {
 const files:Record<string,CCFile>={};
 for(const name of Object.keys(v.files).sort()){const x=v.files[name]!;files[name]={device:x.device,inode:x.inode,uid:x.uid,gid:x.gid,bytes:x.bytes,sha256:x.sha256};}
 return browserSHA256(JSON.stringify({format:2,id:v.id,files,source_identity_only:true}));
}
export const ccRetentionTicket=(v:unknown):v is CCRetentionTicket=>object(v)&&keys(v,["id","sha256"])&&id(v.id)&&sha(v.sha256);
function retained(v:unknown,wanted:string):v is CCRetained {
 if(!object(v)||!keys(v,["format","id","receipt_id","at","outcome","snapshot","snapshot_sha256","retention_intent","original_current_log","no_replay","no_name_exchange","current_log_untouched","original_outcome_unknown"],["archive","preserved_source"])||v.format!==2||v.id!==wanted||!id(v.receipt_id)||!utc(v.at)||v.outcome!=="unknown-retained"||!snapshot(v.snapshot,wanted)||v.snapshot_sha256!==ccSnapshotSHA(v.snapshot)||v.no_replay!==true||v.no_name_exchange!==true||v.current_log_untouched!==true||v.original_outcome_unknown!==true||!file(v.retention_intent)||v.retention_intent.bytes===0||v.retention_intent.bytes>16384||v.retention_intent.uid!==0||!file(v.original_current_log)||v.original_current_log.uid===0||v.original_current_log.gid===0)return false;
 if(Object.keys(v.snapshot.files).length>19||Object.hasOwn(v.snapshot.files,"retain-"+v.receipt_id+".json")||Object.hasOwn(v.snapshot.files,"retain-intent-"+v.receipt_id+".json"))return false;
 const source=v.snapshot.files["next.log"];
 if(source){
  if(!file(v.preserved_source)||v.preserved_source.uid!==0)return false;
  if(source.uid!==0&&(source.uid!==v.original_current_log.uid||source.gid!==v.original_current_log.gid))return false;
  const projected={...source,uid:0,gid:source.uid===0?source.gid:v.preserved_source.gid};
  if(!sameFile(v.preserved_source,projected))return false;
 }else if(v.preserved_source!==undefined)return false;
 const data=v.snapshot.files["data.log"];
 return data?file(v.archive)&&v.archive.uid===0&&sameFile(v.archive,data):v.archive===undefined;
}
function intent(v:unknown,wanted:string):v is CCIntent {
 return object(v)&&keys(v,["format","id","at","request","source","tail_incomplete"])&&v.format===2&&v.id===wanted&&utc(v.at)&&ccArchiveRequest(v.request)&&v.request.request_id===wanted&&file(v.source)&&v.source.bytes>0&&v.source.uid>0&&v.source.gid>0&&typeof v.tail_incomplete==="boolean"&&(!v.tail_incomplete||v.request.allow_incomplete);
}
export function ccArchiveEntry(v:unknown,wanted?:string):v is CCArchiveEntry {
 if(!object(v)||!keys(v,["id","state","record_sha256"],["intent","prepared","completed","retained","problem","source_status"])||!id(v.id)||wanted!==undefined&&v.id!==wanted||!object(v.record_sha256)||Object.keys(v.record_sha256).some(k=>!["intent","prepared","completed","retained"].includes(k)||!sha((v.record_sha256 as Record<string,unknown>)[k]))||v.problem!==undefined&&(typeof v.problem!=="string"||v.problem.length>1024||v.problem.includes("\0")))return false;
 if(v.state==="retained-unknown")return retained(v.retained,v.id)&&(v.retained.preserved_source?v.source_status==="not-authoritative":v.source_status===undefined)&&typeof v.problem==="string"&&!!v.problem&&v.intent===undefined&&v.prepared===undefined&&v.completed===undefined&&Object.keys(v.record_sha256).length===1&&sha(v.record_sha256.retained);
 if(v.retained!==undefined||v.record_sha256.retained!==undefined)return false;
 if(v.intent!==undefined&&(!intent(v.intent,v.id)||!sha(v.record_sha256.intent)))return false;
 if(v.prepared!==undefined){
  if(!intent(v.intent,v.id)||!object(v.prepared)||!keys(v.prepared,["format","id","fresh","archive"])||v.prepared.format!==2||v.prepared.id!==v.id||!file(v.prepared.fresh)||v.prepared.fresh.bytes!==0||v.prepared.fresh.sha256!==emptySHA||v.prepared.fresh.device!==v.intent.source.device||v.prepared.fresh.inode===v.intent.source.inode||v.prepared.fresh.uid!==v.intent.source.uid||v.prepared.fresh.gid!==v.intent.source.gid||!sha(v.record_sha256.prepared)||!file(v.prepared.archive)||v.prepared.archive.uid!==0||v.prepared.archive.device!==v.intent.source.device||v.prepared.archive.inode===v.intent.source.inode||v.prepared.archive.inode===v.prepared.fresh.inode||v.prepared.archive.bytes!==v.intent.source.bytes||v.prepared.archive.sha256!==v.intent.source.sha256)return false;
 }
 if(v.state==="unknown")return v.source_status===undefined&&v.completed===undefined&&v.record_sha256.completed===undefined&&typeof v.problem==="string"&&!!v.problem;
 if(v.state!=="completed"||v.problem!==undefined||!intent(v.intent,v.id)||!object(v.prepared)||!object(v.completed)||!keys(v.completed,["format","id","at","archive"])||v.completed.format!==2||v.completed.id!==v.id||!utc(v.completed.at)||v.completed.at<v.intent.at||!file(v.completed.archive)||!sha(v.record_sha256.completed))return false;
 const a=v.completed.archive,b=v.prepared.archive as CCFile;
 return ["matches-witness","changed-after-copy"].includes(v.source_status as string)&&a.uid===0&&sameFile(a,b)&&Object.keys(v.record_sha256).length===3;
}
export function ccArchiveInventory(v:unknown):v is CCArchiveInventory {
 if(!object(v)||!keys(v,["archives","history","max_history","current","inventory_complete","maintenance_healthy","max_archives","max_archive_bytes","read_only","atomic_name_exchange","reloads_apache"])||v.inventory_complete!==true||v.read_only!==true||v.max_archives!==8||v.max_history!==32||v.max_archive_bytes!==33554432||v.atomic_name_exchange!==true||v.reloads_apache!==false||!Array.isArray(v.archives)||v.archives.length>8||!v.archives.every(row=>ccArchiveEntry(row))||!Array.isArray(v.history)||v.history.length>32||!v.history.every(row=>ccArchiveEntry(row)&&row.state!=="unknown"))return false;
 const c=v.current;
 if(!object(c)||!keys(c,["available","bytes","max_bytes","tail_incomplete","capacity_near_limit","read_only"])||typeof c.available!=="boolean"||!integer(c.bytes,0,33554432)||c.max_bytes!==33554432||c.read_only!==true||typeof c.tail_incomplete!=="boolean"||c.capacity_near_limit!==(c.bytes>=33550336)||!c.available&&(c.bytes!==0||c.tail_incomplete||c.capacity_near_limit)||c.bytes===0&&c.tail_incomplete)return false;
 const all=[...v.archives,...v.history] as CCArchiveEntry[];
 return new Set(all.map(row=>row.id)).size===all.length&&v.maintenance_healthy===all.every(row=>row.state!=="unknown");
}
export function ccRecovery(v:unknown,wanted:string):v is CCRecovery {
 return object(v)&&keys(v,["record","snapshot","snapshot_sha256","read_only","automatic_replay_allowed"])&&v.read_only===true&&v.automatic_replay_allowed===false&&ccArchiveEntry(v.record,wanted)&&v.record.state!=="completed"&&snapshot(v.snapshot,wanted)&&v.snapshot_sha256===ccSnapshotSHA(v.snapshot)&&(v.record.state!=="retained-unknown"||v.snapshot_sha256===v.record.retained?.snapshot_sha256);
}
export function ccHistoryObservation(v:unknown,wanted:string):v is CCHistoryObservation {
 return object(v)&&keys(v,["record","snapshot","snapshot_sha256","history","read_only","no_delete"])&&ccArchiveEntry(v.record,wanted)&&v.record.state!=="unknown"&&snapshot(v.snapshot,wanted)&&v.snapshot_sha256===ccSnapshotSHA(v.snapshot)&&typeof v.history==="boolean"&&v.read_only===true&&v.no_delete===true;
}
export function ccHistoryReceipt(v:unknown,wanted:string,digest:string):boolean {
 return object(v)&&keys(v,["record","snapshot_sha256","history","current_log_untouched","no_delete"])&&ccArchiveEntry(v.record,wanted)&&v.record.state!=="unknown"&&v.snapshot_sha256===digest&&v.history===true&&v.current_log_untouched===true&&v.no_delete===true;
}
export const ccArchiveData=(row:CCArchiveEntry):CCFile|undefined=>row.state==="completed"?row.completed?.archive:row.state==="retained-unknown"?row.retained?.archive:undefined;
export function ccRequestObservation(v:unknown,request:CCArchiveRequest,confirmedClose=false):v is CCRequestObservation {
 if(!object(v))return false;
 if(v.kind==="not-recorded")return !confirmedClose&&keys(v,["kind","request_id","read_only","automatic_retry_allowed"])&&v.request_id===request.request_id&&v.read_only===true&&v.automatic_retry_allowed===false;
 if(v.kind==="archive")return !confirmedClose&&keys(v,["kind","record","read_only"])&&v.read_only===true&&ccArchiveEntry(v.record,request.request_id)&&(v.record.intent===undefined||sameCCArchiveRequest(v.record.intent.request,request));
 if(v.kind!=="closed"||!keys(v,confirmedClose?["kind","record","sha256","late_dispatch_refused","current_log_untouched"]:["kind","record","sha256","read_only"])||!sha(v.sha256)||!object(v.record)||!keys(v.record,["format","state","at","request"])||v.record.format!==1||v.record.state!=="closed-before-archive"||!utc(v.record.at)||!ccArchiveRequest(v.record.request)||!sameCCArchiveRequest(v.record.request,request))return false;
 return confirmedClose?v.late_dispatch_refused===true&&v.current_log_untouched===true:v.read_only===true;
}
export function ccArchiveChunk(value:unknown,entry:CCArchiveEntry,part:number):Uint8Array {
 const original=ccArchiveData(entry);
 if(!original||!object(value)||!keys(value,["archive_id","part","offset","bytes","total_bytes","sha256","data_base64","raw_original_private_log","tail_incomplete","original_outcome_unknown"])||value.archive_id!==entry.id||value.part!==part||!integer(part,0,127)||value.offset!==part*262144||value.total_bytes!==original.bytes||value.bytes!==Math.min(262144,original.bytes-part*262144)||!integer(value.bytes,1,262144)||value.sha256!==original.sha256||value.raw_original_private_log!==true||value.original_outcome_unknown!==(entry.state==="retained-unknown")||value.tail_incomplete!==(entry.state==="retained-unknown"?null:entry.intent?.tail_incomplete)||typeof value.data_base64!=="string"||value.data_base64.length>349528||!/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(value.data_base64))throw Error("原归档分段身份、位置或大小不一致，未下载文件");
 const decoded=atob(value.data_base64);if(decoded.length!==value.bytes)throw Error("原归档分段内容不完整，未下载文件");
 return Uint8Array.from(decoded,c=>c.charCodeAt(0));
}
