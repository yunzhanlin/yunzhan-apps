import {menuPermissionIDs,validAccessPlan,type AccessPlan} from './menuPermissions';
import {pm2ConfigurationRecord} from './pm2Configuration';
export const pm2ArchiveVersion='7.0.4-compat12';
const id=/^[a-f0-9]{32}$/,sha=/^[a-f0-9]{64}$/;
const object=(v:unknown):v is Record<string,any>=>!!v&&typeof v==='object'&&!Array.isArray(v)&&Object.getPrototypeOf(v)===Object.prototype;
const integer=(v:unknown,max:number)=>Number.isSafeInteger(v)&&Number(v)>=0&&Number(v)<=max;
export type ArchiveAction='archive-configurations'|'recover-configuration-archive'|'restore-configuration-archive';
export type ArchiveRow={pm2_operation_id:string;state:'not_started'|'needs_attention'|'archived'|'not_moved'|'restored_for_review';created_at:string;record_count:number;expected_sha:string;inventory_sha256:string;retained_fragments:number;restore_requested:boolean;automatic_replay:false;services_changed:false};
export type ArchivePage={configuration_archives:ArchiveRow[];archive_inventory_complete:true;total:number;limit:number;offset:number;next_offset:number;page_complete:boolean;max_retained_requests:512;automatic_replay:false;services_changed:false;history_or_report_written:false;active_inventory_known:boolean;active_record_count?:number;active_pending_count?:number;active_max_retained_records?:512;inventory_sha256?:string;archive_eligible?:boolean;active_error?:string};
export type ArchivePending={actor:string;installation:string;action:ArchiveAction;id:string;sha256:string};
export const archiveFullAdmin=(access:AccessPlan|null|undefined)=>validAccessPlan(access)&&access.role==='admin'&&access.menu_ids.length===menuPermissionIDs.length;
export function archiveRow(v:unknown):ArchiveRow|undefined{
 if(!object(v)||!id.test(v.pm2_operation_id)||!['not_started','needs_attention','archived','not_moved','restored_for_review'].includes(v.state)||!integer(v.record_count,512)||!integer(v.retained_fragments,64)||typeof v.restore_requested!=='boolean'||v.automatic_replay!==false||v.services_changed!==false)return;
 if(v.state==='not_started'){if(v.record_count!==0||v.expected_sha!==''||v.inventory_sha256!==''||v.created_at!==''||v.restore_requested)return}
 else if(!sha.test(v.expected_sha)||!sha.test(v.inventory_sha256)||v.record_count<1||typeof v.created_at!=='string'||!Number.isFinite(Date.parse(v.created_at)))return;
 if(v.state==='archived'&&v.restore_requested)return;
 if(['before','after','environment_cipher','environment_patch','password','token','inventory'].some(k=>k in v))return;
 return v as ArchiveRow;
}
export function archivePage(value:unknown):ArchivePage{
 if(!object(value)||value.archive_inventory_complete!==true||value.automatic_replay!==false||value.services_changed!==false||value.history_or_report_written!==false||value.max_retained_requests!==512||!integer(value.total,512)||!integer(value.limit,32)||value.limit<1||!integer(value.offset,512)||!integer(value.next_offset,512)||typeof value.page_complete!=='boolean'||typeof value.active_inventory_known!=='boolean'||!Array.isArray(value.configuration_archives)||value.configuration_archives.length>32)throw Error('配置封存清单的身份或完整性无法核对');
 const rows=value.configuration_archives.map(archiveRow);if(rows.some(v=>!v)||new Set(rows.map(v=>v!.pm2_operation_id)).size!==rows.length||value.offset>value.total||value.next_offset!==value.offset+rows.length||value.next_offset>value.total||value.page_complete!==(value.next_offset===value.total)||rows.length>value.limit)throw Error('配置封存分页或原记录不完整');
 if(value.active_inventory_known){if(!integer(value.active_record_count,512)||!integer(value.active_pending_count,512)||value.active_pending_count>value.active_record_count||value.active_max_retained_records!==512||!sha.test(value.inventory_sha256)||typeof value.archive_eligible!=='boolean')throw Error('活动配置清单尚未完整核对')}
 else if(value.archive_eligible===true)throw Error('未知活动记录不能封存');
 return value as ArchivePage;
}
export function archivePending(value:unknown,actor:string,installation:string):value is ArchivePending{
 return object(value)&&id.test(actor)&&id.test(installation)&&value.actor===actor&&value.installation===installation&&id.test(value.id)&&sha.test(value.sha256)&&['archive-configurations','recover-configuration-archive','restore-configuration-archive'].includes(value.action)&&Object.keys(value).length===5;
}
export function archiveBody(p:ArchivePending){
 if(!archivePending(p,p.actor,p.installation))throw Error('原配置封存请求身份无法核对');
 return {pm2_installation_id:p.installation,pm2_operation_id:p.id,expected_sha:p.sha256,confirm:p.action==='archive-configurations'?'ARCHIVE PM2 CONFIGURATIONS '+p.sha256:p.action==='recover-configuration-archive'?'RECOVER PM2 CONFIG ARCHIVE '+p.id:'RESTORE PM2 CONFIG ARCHIVE '+p.id};
}
export function archiveOriginalRecords(value:unknown,selected:ArchiveRow){
 if(!object(value)||value.archived_original!==true||value.archive_operation_id!==selected.pm2_operation_id||value.archive_expected_sha!==selected.expected_sha||value.configuration_inventory_complete!==true||value.automatic_replay!==false||value.history_or_report_written!==false||!integer(value.total,512)||!integer(value.limit,128)||value.limit<1||!integer(value.offset,512)||!integer(value.next_offset,512)||!Array.isArray(value.configuration_transactions)||value.configuration_transactions.length>128)throw Error('所选封存记录身份或分页不完整');
 const rows=value.configuration_transactions.map(pm2ConfigurationRecord);if(rows.some(v=>!v||v.state==='needs_attention')||new Set(rows.map(v=>v!.pm2_operation_id)).size!==rows.length||value.offset>value.total||value.next_offset!==value.offset+rows.length||value.next_offset>value.total||value.page_complete!==(value.next_offset===value.total)||rows.length>value.limit)throw Error('封存配置原记录不能核对');
 return {rows:rows as NonNullable<ReturnType<typeof pm2ConfigurationRecord>>[],total:value.total as number,offset:value.offset as number,next:value.next_offset as number};
}
export const archiveLabels:Record<ArchiveRow['state'],string>={not_started:'原请求未被接受 · 标识已保留',needs_attention:'封存中断 · 待核对',archived:'封存完成',not_moved:'已保留原活动目录',restored_for_review:'原目录已恢复 · 待核对'};

export const configurationResultLabels={needs_attention:'待核对',committed:'已提交',rolled_back:'已回退',recovered_stopped:'已恢复旧配置并停止',cancelled_before_publication:'原请求已取消'};
export function archiveDisplayTime(value:string){return value&&Number.isFinite(Date.parse(value))?new Date(value).toLocaleString('zh-CN',{hour12:false}):'尚未接受'}
