export type PM2ConfigurationObservation={appID:string;operationID:string};
export function newPM2ConfigurationID():string { const bytes=crypto.getRandomValues(new Uint8Array(16));return Array.from(bytes,value=>value.toString(16).padStart(2,'0')).join(''); }
type PublicRecord={resource_id:string;site_id?:string;pm2_operation_id:string;expected_sha:string;state:'needs_attention'|'committed'|'rolled_back'|'recovered_stopped'|'cancelled_before_publication';previous_revision?:number;next_revision?:number;created_at:string;previous_running?:boolean;previous_boot_enabled?:boolean;automatic_replay:false};
const own=(v:unknown):v is Record<string,unknown>=>v!==null&&typeof v==='object'&&!Array.isArray(v)&&Object.getPrototypeOf(v)===Object.prototype;
export function pm2ConfigurationRecord(value:unknown):PublicRecord|undefined{
 if(!own(value))return;
 const row=value as unknown as PublicRecord;
 if(typeof row.resource_id!=='string'||typeof row.pm2_operation_id!=='string'||typeof row.expected_sha!=='string'||!/^[a-z][a-z0-9-]{2,31}$/.test(row.resource_id)||!/^[a-f0-9]{32}$/.test(row.pm2_operation_id)||!/^[a-f0-9]{64}$/.test(row.expected_sha)||typeof row.created_at!=='string'||!Number.isFinite(Date.parse(row.created_at))||row.automatic_replay!==false)return;
 if(['before','after','environment_cipher','environment_patch','password','token'].some(key=>key in value))return;
 if(row.state==='cancelled_before_publication'){
  if(['site_id','previous_revision','next_revision','previous_running','previous_boot_enabled'].some(key=>key in value))return;
  return row;
 }
 if(typeof row.site_id!=='string'||!/^[a-f0-9]{32}$/.test(row.site_id)||!['needs_attention','committed','rolled_back','recovered_stopped'].includes(row.state)||!Number.isSafeInteger(row.previous_revision)||!Number.isSafeInteger(row.next_revision)||row.previous_revision!<1||row.next_revision!==row.previous_revision!+1||typeof row.previous_running!=='boolean'||typeof row.previous_boot_enabled!=='boolean')return;
 return row;
}
export function pm2ConfigurationFields(value:unknown){
 const row=pm2ConfigurationRecord(value);if(!row)return;
 return {resource_id:row.resource_id,pm2_operation_id:row.pm2_operation_id,expected_sha:row.expected_sha,confirm:''};
}
export function pm2ConfigurationReplyMatches(ticket:PM2ConfigurationObservation,value:unknown):boolean{
 if(!own(value)||value.ok!==true)return false;
 const record=pm2ConfigurationRecord(value.configuration_transaction);
 return !!record&&record.resource_id===ticket.appID&&record.pm2_operation_id===ticket.operationID&&record.state==='committed';
}
export function pm2ConfigurationReadConfirms(ticket:PM2ConfigurationObservation,value:unknown):boolean{
 if(!own(value)||value.configuration_inventory_complete!==true||!Array.isArray(value.configuration_transactions)||value.configuration_transactions.length>128)return false;
 const records=value.configuration_transactions.map(pm2ConfigurationRecord);if(records.some(row=>!row))return false;
 const ids=records.map(row=>row!.pm2_operation_id);if(new Set(ids).size!==ids.length)return false;
 const original=records.find(row=>row!.pm2_operation_id===ticket.operationID);
 return !!original&&original.resource_id===ticket.appID&&original.state!=='needs_attention';
}
// Absence never unblocks a save: an explicit durable cancellation consumes
// this exact nonce before the user can submit another configuration.
export function pm2ConfigurationAbsentMatches(ticket:PM2ConfigurationObservation,value:unknown):boolean{
 return own(value)&&value.configuration_inventory_complete===true&&value.selected_operation_absent===true&&value.automatic_replay===false&&value.resource_id===ticket.appID&&value.pm2_operation_id===ticket.operationID&&Array.isArray(value.configuration_transactions)&&value.configuration_transactions.length===0;
}

