const targetID=/^[a-z0-9][a-z0-9-]{2,63}$/;
const transactionID=/^[0-9a-f]{32}$/;
export function remoteBackupFields(row:unknown):Record<string,unknown>|undefined {
  if(!row || typeof row!=="object" || Array.isArray(row))return;
  const v=row as Record<string,any>;
  if(!transactionID.test(v.backup_transaction_id) || typeof v.remote_target_id!=="string" || !targetID.test(v.remote_target_id) || !Number.isSafeInteger(v.revision) || v.revision<1 || typeof v.pending_recovery!=="boolean" || !Array.isArray(v.backup_files) || v.backup_files.length>2)return;
  const names=new Set();let bytes=0;
  for(const f of v.backup_files){if(!f || !["staged","previous"].includes(f.name) || names.has(f.name) || !Number.isSafeInteger(f.bytes) || f.bytes<0 || f.bytes>8*1024*1024 || !Number.isSafeInteger(f.mode) || f.mode<0 || f.mode>0o777)return;names.add(f.name);bytes+=f.bytes;}
  if(v.backup_bytes!==bytes)return;
  return {remote_target_id:v.remote_target_id,expected_revision:v.revision,limit:16,offset:0};
}
export function remoteBackupBody(form:Record<string,any>,revision:unknown):Record<string,unknown>{
  if(typeof form.remote_target_id!=="string" || !targetID.test(form.remote_target_id) || !Number.isSafeInteger(revision) || Number(revision)<1)throw Error("请先选择当前远端连接和有效修订号");
  const limit=form.limit === undefined ? 16 : form.limit,offset=form.offset === undefined ? 0 : form.offset;
  if(!Number.isInteger(limit) || limit<1 || limit>32 || !Number.isInteger(offset) || offset<0 || offset>512)throw Error("备份容量每页为 1–32 条，分页起点为 0–512");
  return {remote_target_id:form.remote_target_id,expected_revision:revision,limit,offset};
}
