import { sha256 } from '@noble/hashes/sha2.js';
import { bytesToHex } from '@noble/hashes/utils.js';
import { menuPermissionIDs, validAccessPlan, type AccessPlan } from './menuPermissions';

export const independentBackupVersion='2.0.0', independentChunkBytes=256*1024, independentFileBytes=8*1024*1024;
export function independentBackupSupported(version:unknown){return version===independentBackupVersion||version==='2.0.1';}
const target=/^[a-z0-9][a-z0-9-]{2,63}$/, id=/^[a-f0-9]{32}$/, sha=/^[a-f0-9]{64}$/;
const matches=(pattern:RegExp,value:unknown)=>typeof value==='string'&&pattern.test(value);
const integer=(n:unknown,max:number)=>Number.isSafeInteger(n)&&Number(n)>=0&&Number(n)<=max;
const utc=(s:unknown)=>typeof s==='string'&&/^20\d\d-\d\d-\d\dT[\d:.]+Z$/.test(s)&&Number.isFinite(Date.parse(s));
const object=(v:unknown):v is Record<string,any>=>!!v&&typeof v==='object'&&!Array.isArray(v);
export type IndependentAPI=<T>(path:string,method?:string,body?:unknown,idempotencyKey?:string,signal?:AbortSignal)=>Promise<T>;
export type IndependentFile={name:'previous'|'staged';bytes:number;sha256:string};
export interface IndependentCopy {
 remote_target_id:string; backup_transaction_id:string; revision:number; source_snapshot_sha256:string;
 copy_intent_sha256:string; copy_state_sha256:string; independent_copy_state:'needs-review'|'committed'|'retained-incomplete';
 copy_bytes:number;retained_bytes:number;retained_attempts:number;created_at:string;completed_at:string;
 content_verified:boolean;pending_recovery:boolean;files:IndependentFile[];
}
export interface IndependentSource {
 remote_target_id:string;backup_transaction_id:string;revision:number;backup_snapshot_sha256:string;
 backup_archive_state:'committed';backup_bytes:number;content_verified:boolean;pending_recovery:false;
}
export interface IndependentPending {
 actor:string;target:string;revision:number;transaction:string;sha256:string;
 action:'copy-remote-backup'|'recover-remote-copy'|'retain-remote-copy';
}
export function independentFullAdministrator(access:AccessPlan|null|undefined) {
 return validAccessPlan(access)&&access.role==='admin'&&access.menu_ids.length===menuPermissionIDs.length;
}
export function independentCopyValid(value:unknown,chosen:string,revision:number):value is IndependentCopy {
 if(!object(value))return false;const v=value;
 if(!matches(target,chosen)||v.remote_target_id!==chosen||!matches(id,v.backup_transaction_id)||v.revision!==revision||!integer(revision,1e9)||revision<1||!matches(sha,v.source_snapshot_sha256)||!matches(sha,v.copy_intent_sha256)||!matches(sha,v.copy_state_sha256))return false;
 if(!['needs-review','committed','retained-incomplete'].includes(v.independent_copy_state)||!integer(v.copy_bytes,2*independentFileBytes)||!integer(v.retained_bytes,16*independentFileBytes)||!integer(v.retained_attempts,8)||!utc(v.created_at)||typeof v.content_verified!=='boolean'||v.pending_recovery!==(v.independent_copy_state==='needs-review'))return false;
 if(v.independent_copy_state==='needs-review'?v.completed_at!=='':!utc(v.completed_at)||Date.parse(v.completed_at)<Date.parse(v.created_at))return false;
 if(v.content_verified&&v.independent_copy_state!=='committed'||!Array.isArray(v.files)||v.files.length<1||v.files.length>2)return false;
 const names=new Set<string>();let total=0;
 for(const f of v.files){if(!object(f)||!['previous','staged'].includes(f.name)||names.has(f.name)||!integer(f.bytes,independentFileBytes)||!matches(sha,f.sha256))return false;names.add(f.name);total+=f.bytes}
 return total===v.copy_bytes&&v.retained_bytes<=v.copy_bytes*v.retained_attempts&&(v.independent_copy_state!=='committed'||v.retained_attempts>0&&v.retained_bytes>=v.copy_bytes);
}
export function independentSourceValid(value:unknown,chosen:string,revision:number):value is IndependentSource {
 if(!object(value))return false;const v=value;
 return matches(target,chosen)&&v.remote_target_id===chosen&&matches(id,v.backup_transaction_id)&&v.revision===revision&&integer(revision,1e9)&&revision>0&&matches(sha,v.backup_snapshot_sha256)&&v.backup_archive_state==='committed'&&integer(v.backup_bytes,2*independentFileBytes)&&typeof v.content_verified==='boolean'&&v.pending_recovery===false;
}
export function independentPendingValid(v:unknown,actor:string):v is IndependentPending {
 return object(v)&&matches(id,actor)&&v.actor===actor&&matches(target,v.target)&&integer(v.revision,1e9)&&v.revision>0&&matches(id,v.transaction)&&matches(sha,v.sha256)&&['copy-remote-backup','recover-remote-copy','retain-remote-copy'].includes(v.action);
}
export function independentMutationBody(action:IndependentPending['action'],row:IndependentCopy|IndependentSource,confirm:string) {
 if(!['copy-remote-backup','recover-remote-copy','retain-remote-copy'].includes(action))throw Error('独立备份不接受其他操作');
 const selected=row.backup_transaction_id,chosen=row.remote_target_id,revision=row.revision;
 let digest='',prefix='';
 if(action==='copy-remote-backup'){
  if(!independentSourceValid(row,chosen,revision)||!row.content_verified)throw Error('须先完整核对所选原远端归档');
  digest=row.backup_snapshot_sha256;prefix='COPY BACKUP ';
 }else{
  if(!independentCopyValid(row,chosen,revision)||row.independent_copy_state!=='needs-review')throw Error('须先核对仍待恢复的本机独立副本');
  digest=row.copy_state_sha256;prefix=action==='recover-remote-copy'?'RECOVER COPY ':'RETAIN COPY ';
 }
 if(confirm!==prefix+selected)throw Error('请填写所选原事务的精确确认');
 return {remote_target_id:chosen,expected_revision:revision,resource_id:selected,expected_sha:digest,confirm};
}
export function independentReplyCopy(value:unknown,chosen:string,revision:number,transaction?:string):IndependentCopy {
 if(!object(value)||value.remote_files_changed!==false||!independentCopyValid(value.independent_backup,chosen,revision)||transaction&&value.independent_backup.backup_transaction_id!==transaction)throw Error('独立备份回执身份、状态或摘要不符，请刷新原库存核对');
 return value.independent_backup;
}
export async function independentDownload(api:IndependentAPI,row:IndependentCopy,file:IndependentFile,signal:AbortSignal,current:()=>boolean):Promise<Uint8Array> {
 if(!independentCopyValid(row,row.remote_target_id,row.revision)||row.independent_copy_state!=='committed'||!row.content_verified||!row.files.some(f=>f.name===file.name&&f.bytes===file.bytes&&f.sha256===file.sha256))throw Error('先完整核验当前副本，再下载所选文件');
 const bytes=new Uint8Array(file.bytes),parts=Math.max(1,Math.ceil(file.bytes/independentChunkBytes));
 for(let part=0;part<parts;part++){
  if(signal.aborted||!current())throw Error('会话、权限或所选副本变化，未生成文件');
  const v=await api<unknown>(`/app-modules/files-sync/independent-backups/${row.remote_target_id}/${row.backup_transaction_id}/${file.name}/chunks/${part}?sha=${row.copy_intent_sha256}`,'GET',undefined,undefined,signal);
  if(signal.aborted||!current())throw Error('会话、权限或所选副本变化，已丢弃分段');
  const count=Math.min(independentChunkBytes,file.bytes-part*independentChunkBytes);
  if(!object(v)||v.remote_target_id!==row.remote_target_id||v.backup_transaction_id!==row.backup_transaction_id||v.name!==file.name||v.part!==part||v.intent_sha256!==row.copy_intent_sha256||v.file_sha256!==file.sha256||v.file_bytes!==file.bytes||v.files_changed!==false||typeof v.data!=='string'||v.data.length!==4*Math.ceil(count/3)||!/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(v.data))throw Error('下载分段的原文件身份或容量改变，未生成文件');
  const decoded=Uint8Array.from(atob(v.data),c=>c.charCodeAt(0));
  if(decoded.length!==count||bytesToHex(sha256(decoded))!==v.chunk_sha256)throw Error('下载分段摘要不符，未生成文件');
  bytes.set(decoded,part*independentChunkBytes);
 }
 if(signal.aborted||!current()||bytesToHex(sha256(bytes))!==file.sha256)throw Error('下载完整文件摘要未通过，未生成文件');
 return bytes;
}
export const independentStateLabels:Record<IndependentCopy['independent_copy_state'],string>={'needs-review':'未完成 · 待核对恢复',committed:'已保存 · 内容待独立核验','retained-incomplete':'仅保留未完成片段'};
