export interface WafConfigBackup { id:string; created_at:string; files:number; bytes:number; sha256:string }
export interface WafConfigBackupInventory { available:boolean; entries:WafConfigBackup[]; bytes:number; count_max:100; scan_max_bytes:134217728; read_only:true; message:string }
const record=(v:unknown):v is Record<string,unknown>=>!!v&&typeof v==="object"&&!Array.isArray(v)&&[Object.prototype,null].includes(Object.getPrototypeOf(v));
const keys=(v:Record<string,unknown>,fields:string[])=>Object.keys(v).sort().join(",")===[...fields].sort().join(",");
const integer=(v:unknown,min:number,max:number):v is number=>typeof v==="number"&&Number.isSafeInteger(v)&&v>=min&&v<=max;

export function decodeWafConfigBackup(row:unknown):WafConfigBackup {
  if(!record(row)||!keys(row,["id","created_at","files","bytes","sha256"])||typeof row.id!=="string"||!/^[a-f0-9]{32}$/.test(row.id)||typeof row.created_at!=="string"||row.created_at.length>40||!/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?(?:Z|[+-]\d{2}:\d{2})$/.test(row.created_at)||!Number.isFinite(Date.parse(row.created_at))||!integer(row.files,5,4096)||!integer(row.bytes,1,9*1048576)||typeof row.sha256!=="string"||!/^[a-f0-9]{64}$/.test(row.sha256))throw new Error("原快照完整元数据不可核对；不接受私有配置正文、路径或部分内容。");
  return row as unknown as WafConfigBackup;
}

export function decodeWafConfigBackups(value:unknown):WafConfigBackupInventory {
  const bad=()=>new Error("配置备份库存尚未完整核验；未显示旧库存、部分列表或零份备份。");
  if(!record(value)||!keys(value,["available","entries","bytes","count_max","scan_max_bytes","read_only","message"])||typeof value.available!=="boolean"||value.read_only!==true||value.count_max!==100||value.scan_max_bytes!==134217728||!integer(value.bytes,0,134217728)||typeof value.message!=="string"||new TextEncoder().encode(value.message).length>1024||!Array.isArray(value.entries)||value.entries.length>100)throw bad();
  let bytes=0,previous="";
  for(const row of value.entries){
    const verified=decodeWafConfigBackup(row);if(verified.id<=previous)throw bad();
    bytes+=verified.bytes;previous=verified.id;
  }
  if(bytes!==value.bytes||!value.available&&(bytes!==0||value.entries.length!==0))throw bad();
  return value as unknown as WafConfigBackupInventory;
}

export interface WafConfigBackupSlots {available:boolean;ids:string[];count_max:100;read_only:true;contents_verified:false;message:string}
export interface WafConfigBackupArchiveInput {resource_id:string;expected_sha:string;confirm:string}
export interface WafConfigBackupArchiveResult {snapshot:WafConfigBackup;archived:true;replayed:boolean;records_retained:true;configuration_changed:false}
export interface WafConfigBackupArchivePending {resource_id:string;expected_sha:string;created_at:string}
export interface WafConfigBackupArchiveRecovery {pending:WafConfigBackupArchivePending|null;read_only:true}
type Read=(path:string)=>Promise<unknown>;
type Post=(path:string,method:string,body:unknown)=>Promise<unknown>;
const id=(value:string)=>/^[a-f0-9]{32}$/.test(value);
function decodeArchivePending(value:unknown):WafConfigBackupArchivePending {
  if(!record(value)||!keys(value,["resource_id","expected_sha","created_at"])||typeof value.resource_id!=="string"||!id(value.resource_id)||typeof value.expected_sha!=="string"||!/^[a-f0-9]{64}$/.test(value.expected_sha)||typeof value.created_at!=="string"||!/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/.test(value.created_at)||!Number.isFinite(Date.parse(value.created_at))||new Date(value.created_at).toISOString().replace(".000Z","Z")!==value.created_at)throw new Error("当前账户的原归档请求身份不可完整核对；不替换原标识或摘要。");
  return value as unknown as WafConfigBackupArchivePending;
}
export function decodeWafConfigBackupArchiveRecovery(value:unknown):WafConfigBackupArchiveRecovery {
  if(!record(value)||!keys(value,["pending","read_only"])||value.read_only!==true)throw new Error("当前账户的待核对请求未知；未执行或自动重试归档。");
  if(value.pending!==null)decodeArchivePending(value.pending);
  return value as unknown as WafConfigBackupArchiveRecovery;
}
export function wafConfigBackupArchiveRecoveredInput(value:WafConfigBackupArchivePending):WafConfigBackupArchiveInput {
  const pending=decodeArchivePending(value);
  return Object.freeze({resource_id:pending.resource_id,expected_sha:pending.expected_sha,confirm:"ARCHIVE NGINX CONFIG "+pending.resource_id});
}
export async function readWafConfigBackupArchiveRecovery(read:Read,current:()=>boolean):Promise<WafConfigBackupArchiveRecovery>{
  if(!current())throw new Error("原归档工作区已关闭，未恢复请求身份。");
  const value=await read("/software/nginx-waf/config-backup-archive-request");
  if(!current())throw new Error("原归档工作区已关闭，未恢复请求身份。");
  return decodeWafConfigBackupArchiveRecovery(value);
}
export function decodeWafConfigBackupSlots(value:unknown):WafConfigBackupSlots {
  if(!record(value)||!keys(value,["available","ids","count_max","read_only","contents_verified","message"])||typeof value.available!=="boolean"||value.count_max!==100||value.read_only!==true||value.contents_verified!==false||typeof value.message!=="string"||new TextEncoder().encode(value.message).length>1024||!Array.isArray(value.ids)||value.ids.length>100||!value.available&&value.ids.length>0)throw new Error("原快照目录标识不可核对；未宣称完整内容通过。");
  let previous="";for(const item of value.ids){if(typeof item!=="string"||!id(item)||item<=previous)throw new Error("原快照目录标识重复或无效。");previous=item;}
  return value as unknown as WafConfigBackupSlots;
}
export function wafConfigBackupArchiveInput(row:WafConfigBackup,confirm:string):WafConfigBackupArchiveInput {
  const original=decodeWafConfigBackup(row);
  if(confirm!=="ARCHIVE NGINX CONFIG "+original.id)throw new Error("请按所选原快照标识输入精确归档确认；不执行删除或回滚。");
  return Object.freeze({resource_id:original.id,expected_sha:original.sha256,confirm});
}
export function decodeWafConfigBackupArchiveResult(value:unknown,input:WafConfigBackupArchiveInput):WafConfigBackupArchiveResult {
  if(!id(input.resource_id)||!/^[a-f0-9]{64}$/.test(input.expected_sha)||input.confirm!=="ARCHIVE NGINX CONFIG "+input.resource_id||!record(value)||!keys(value,["snapshot","archived","replayed","records_retained","configuration_changed"])||value.archived!==true||typeof value.replayed!=="boolean"||value.records_retained!==true||value.configuration_changed!==false)throw new Error("原归档回执不可核对；保留同一标识和摘要，不自动重试或宣称未移动。");
  const row=decodeWafConfigBackup(value.snapshot);if(row.id!==input.resource_id||row.sha256!==input.expected_sha)throw new Error("原归档回执标识或完整摘要不匹配。");
  return value as unknown as WafConfigBackupArchiveResult;
}
export async function readWafConfigBackupSlots(read:Read,current:()=>boolean):Promise<WafConfigBackupSlots>{
  if(!current())throw new Error("原快照工作区已关闭，未读取目录标识。");
  const value=await read("/software/nginx-waf/config-backup-slots");if(!current())throw new Error("原快照工作区已关闭，未更新目录标识。");return decodeWafConfigBackupSlots(value);
}
export async function readWafConfigBackupSnapshot(read:Read,current:()=>boolean,snapshotID:string,archived=false):Promise<WafConfigBackup>{
  if(!id(snapshotID)||!current())throw new Error("原快照标识无效或工作区已关闭。");
  const value=await read("/software/nginx-waf/"+(archived?"config-backup-archive/":"config-backups/")+snapshotID);
  if(!current())throw new Error("原快照工作区已关闭，未更新元数据。");const row=decodeWafConfigBackup(value);if(row.id!==snapshotID)throw new Error("所选原快照标识不匹配。");return row;
}
export async function readWafConfigBackupArchive(read:Read,current:()=>boolean):Promise<WafConfigBackupInventory>{
  if(!current())throw new Error("原归档工作区已关闭，未读取库存。");const value=await read("/software/nginx-waf/config-backup-archive");if(!current())throw new Error("原归档工作区已关闭，未更新库存。");return decodeWafConfigBackups(value);
}
export async function archiveWafConfigBackup(post:Post,current:()=>boolean,input:WafConfigBackupArchiveInput):Promise<WafConfigBackupArchiveResult>{
  // Validate a closed immutable original ticket before its only explicit POST.
  if(!record(input)||!keys(input as unknown as Record<string,unknown>,["resource_id","expected_sha","confirm"])||typeof input.resource_id!=="string"||!id(input.resource_id)||typeof input.expected_sha!=="string"||!/^[a-f0-9]{64}$/.test(input.expected_sha)||input.confirm!=="ARCHIVE NGINX CONFIG "+input.resource_id||!current())throw new Error("原归档请求身份无效或工作区已关闭。");
  const value=await post("/software/nginx-waf/archive-config-backup","POST",input);
  if(!current())throw new Error("原工作区已关闭；归档回复未更新新工作区，原结果仍须核对。");return decodeWafConfigBackupArchiveResult(value,input);
}

export async function readWafConfigBackups(read:(path:string)=>Promise<unknown>,current:()=>boolean):Promise<WafConfigBackupInventory>{
  if(!current())throw new Error("原配置备份工作区已关闭，未读取库存。");
  const value=await read("/software/nginx-waf/config-backups");
  if(!current())throw new Error("原配置备份工作区已关闭，未更新库存。");
  return decodeWafConfigBackups(value);
}
