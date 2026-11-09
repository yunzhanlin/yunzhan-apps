export const unpublishedRetentionVersion='2.0.1',unpublishedPartLimit=32*1024,unpublishedPartCount=8;
const id=/^[a-f0-9]{32}$/,target=/^[a-z0-9][a-z0-9-]{2,63}$/,sha=/^[a-f0-9]{64}$/;
const object=(v:unknown):v is Record<string,any>=>!!v&&typeof v==='object'&&!Array.isArray(v);
const integer=(v:unknown,max:number)=>Number.isSafeInteger(v)&&Number(v)>=0&&Number(v)<=max;
const matches=(r:RegExp,v:unknown)=>typeof v==='string'&&r.test(v);
const utc=(v:unknown)=>typeof v==='string'&&/^20\d\d-\d\d-\d\dT[\d:.]+Z$/.test(v)&&Number.isFinite(Date.parse(v));
export type UnpublishedFragment={name:string;bytes:number;sha256:string};
export interface UnpublishedCopy {
 remote_target_id:string;backup_transaction_id:string;revision:number;
 fragment_state:'unpublished-needs-review'|'unpublished-retained';snapshot_sha256:string;retained_at:string;retained_bytes:number;
 fragments:UnpublishedFragment[];root_private:true;backup_complete:false;source_authority:false;downloadable:false;
}
export interface UnpublishedPending {
 actor:string;target:string;revision:number;transaction:string;sha256:string;action:'retain-remote-copy-fragments';
}
export function unpublishedCopyValid(value:unknown,chosen:string,revision:number):value is UnpublishedCopy {
 if(!object(value)||!matches(target,chosen)||value.remote_target_id!==chosen||value.revision!==revision||!integer(revision,1e9)||revision<1||!matches(id,value.backup_transaction_id)||!matches(sha,value.snapshot_sha256))return false;
 if(value.root_private!==true||value.backup_complete!==false||value.source_authority!==false||value.downloadable!==false||!['unpublished-needs-review','unpublished-retained'].includes(value.fragment_state))return false;
 if(!Array.isArray(value.fragments)||value.fragments.length>unpublishedPartCount||!integer(value.retained_bytes,(unpublishedPartCount+1)*unpublishedPartLimit))return false;
 let sum=0,prior='';
 for(const f of value.fragments){if(!object(f)||!/^record-[a-f0-9]{32}\.part$/.test(f.name)||f.name<=prior||!integer(f.bytes,unpublishedPartLimit)||!matches(sha,f.sha256))return false;prior=f.name;sum+=f.bytes;}
 return value.fragment_state==='unpublished-needs-review'?value.retained_at===''&&value.retained_bytes===sum:utc(value.retained_at)&&value.retained_bytes>sum&&value.retained_bytes<=sum+unpublishedPartLimit;
}
export function unpublishedInventory(value:unknown,chosen:string,revision:number,offset:number){
 if(!integer(offset,128)||!object(value)||value.remote_files_changed!==false||!Array.isArray(value.unpublished_records)||value.unpublished_records.length>16||!integer(value.total,128)||!integer(value.global_copies,128)||value.global_copies<value.total||!integer(value.retained_bytes,1024**3)||!integer(value.unpublished_bytes,128*9*unpublishedPartLimit)||value.offset!==offset||value.limit!==16||value.unpublished_records.length!==Math.max(0,Math.min(16,value.total-offset)))throw Error('未发布原片段库存不完整，未显示为保留成功');
 const seen=new Set<string>();
 for(const row of value.unpublished_records){if(!unpublishedCopyValid(row,chosen,revision)||seen.has(row.backup_transaction_id))throw Error('原片段身份、权限、状态或完整摘要不能核对');seen.add(row.backup_transaction_id);}
 return {rows:value.unpublished_records as UnpublishedCopy[],total:value.total as number,globalCount:value.global_copies as number,globalBytes:value.retained_bytes as number};
}
export function unpublishedMutationBody(row:UnpublishedCopy,confirm:string){
 if(!unpublishedCopyValid(row,row.remote_target_id,row.revision)||row.fragment_state!=='unpublished-needs-review'||row.fragments.length>=unpublishedPartCount||confirm!==`RETAIN FRAGMENTS ${row.backup_transaction_id}`)throw Error('须核对仍未发布的原片段及容量余量，并填写精确确认');
 return {remote_target_id:row.remote_target_id,expected_revision:row.revision,resource_id:row.backup_transaction_id,expected_sha:row.snapshot_sha256,confirm};
}
export function unpublishedPendingValid(value:unknown,actor:string):value is UnpublishedPending {
 return object(value)&&matches(id,actor)&&value.actor===actor&&matches(target,value.target)&&integer(value.revision,1e9)&&value.revision>0&&matches(id,value.transaction)&&matches(sha,value.sha256)&&value.action==='retain-remote-copy-fragments';
}
export function unpublishedReply(value:unknown,chosen:string,revision:number,transaction:string,snapshot:string):UnpublishedCopy {
 if(!object(value)||value.original_fragments_preserved!==true||value.remote_files_changed!==false||value.backup_complete!==false||!unpublishedCopyValid(value.unpublished_record,chosen,revision)||value.unpublished_record.backup_transaction_id!==transaction||value.unpublished_record.snapshot_sha256!==snapshot||value.unpublished_record.fragment_state!=='unpublished-retained')throw Error('原片段保留结果尚未完整核对；保留原条件请求，不自动重发');
 return value.unpublished_record;
}
