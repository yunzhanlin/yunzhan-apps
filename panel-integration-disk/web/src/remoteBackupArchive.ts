const target=/^[a-z0-9][a-z0-9-]{2,63}$/;
const id=/^[0-9a-f]{32}$/;
const sha=/^[0-9a-f]{64}$/;
export const remoteBackupArchiveActions=['remote-backup-preview','remote-backup-archive','archive-remote-backup','recover-remote-backup'];
export function remoteBackupArchiveFields(row:unknown):Record<string,any>|undefined {
  if(!row||typeof row!=='object'||Array.isArray(row))return;
  const r=row as Record<string,any>;
  if(typeof r.remote_target_id!=='string'||!target.test(r.remote_target_id)||typeof r.backup_transaction_id!=='string'||!id.test(r.backup_transaction_id)||!Number.isSafeInteger(r.revision)||r.revision<1||typeof r.backup_snapshot_sha256!=='string'||!sha.test(r.backup_snapshot_sha256)||!['reviewed','prepared','reserved','committed'].includes(r.backup_archive_state)||!Number.isSafeInteger(r.backup_bytes)||r.backup_bytes<0||r.backup_bytes>16*1024*1024||typeof r.content_verified!=='boolean'||typeof r.pending_recovery!=='boolean')return;
  if(r.pending_recovery!==['prepared','reserved'].includes(r.backup_archive_state)||r.backup_archive_state==='reviewed'&&!r.content_verified)return;
  return {remote_target_id:r.remote_target_id,expected_revision:r.revision,resource_id:r.backup_transaction_id,expected_sha:r.backup_snapshot_sha256,confirm:'',backup_archive_state:r.backup_archive_state};
}
export function remoteBackupArchiveBody(action:string,form:Record<string,any>,revision:unknown):Record<string,unknown> {
  if(!remoteBackupArchiveActions.includes(action)||typeof form.remote_target_id!=='string'||!target.test(form.remote_target_id)||!Number.isSafeInteger(revision)||Number(revision)<1)throw Error('请先选择当前连接和有效修订号');
  const body:Record<string,unknown>={remote_target_id:form.remote_target_id,expected_revision:revision};
  if(action==='remote-backup-archive') {
    const limit=form.limit===undefined?16:form.limit,offset=form.offset===undefined?0:form.offset;
    if(!Number.isInteger(limit)||limit<1||limit>32||!Number.isInteger(offset)||offset<0||offset>512)throw Error('远端备份归档每页为 1–32 条，起点为 0–512');
    return {...body,limit,offset};
  }
  if(typeof form.resource_id!=='string'||!id.test(form.resource_id))throw Error('请先从实际库存选择原备份事务');
  body.resource_id=form.resource_id;
  if(action==='remote-backup-preview')return body;
  const recovery=action==='recover-remote-backup';
  if(typeof form.expected_sha!=='string'||!sha.test(form.expected_sha)||form.confirm!==`${recovery?'RECOVER':'ARCHIVE'} BACKUP ${form.resource_id}`||!(recovery?['prepared','reserved','committed']:['reviewed','committed']).includes(form.backup_archive_state))throw Error('先核对原事务摘要与阶段，再填写精确确认；不自动确认或重新提交');
  return {...body,expected_sha:form.expected_sha,confirm:form.confirm};
}
