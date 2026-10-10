export interface ApacheTransactionRow {
  transaction_id:string;transaction_state:"applying"|"committed"|"recovered";
  created_at:string;transaction_format:2;transaction_files:3;transaction_sha256:string;
  transaction_bytes:number;transaction_archived:boolean;transaction_archivable:boolean;
}
export interface ApacheTransactionInventory {
  apache_transactions:ApacheTransactionRow[];limit:number;offset:number;total:number;
  transaction_active_count:number;transaction_archive_count:number;transaction_active_bytes:number;
  transaction_archive_bytes:number;transaction_slots_available:number;pending:boolean;
  records_retained:true;configuration_changed:false;transaction_archive_ready:boolean;
  transaction_replay_ready:boolean;transaction_archive_blocked:string;scope:string;
}
export interface ApacheArchiveReceipt {
  apache_transactions:[ApacheTransactionRow];archived:1;replayed:boolean;
  records_retained:true;configuration_changed:false;scope:string;
}
const id=/^[a-f0-9]{32}$/,sha=/^[a-f0-9]{64}$/;
const object=(v:unknown):v is Record<string,unknown>=>!!v&&typeof v==="object"&&!Array.isArray(v);
const bounded=(v:unknown,max:number,min=0):v is number=>Number.isSafeInteger(v)&&Number(v)>=min&&Number(v)<=max;
const date=(v:unknown)=>typeof v==="string"&&v.length<=64&&Number.isFinite(Date.parse(v));
export function apacheTransactionRow(v:unknown):v is ApacheTransactionRow {
  if(!object(v))return false;
  return typeof v.transaction_id==="string"&&id.test(v.transaction_id)&&typeof v.transaction_sha256==="string"&&sha.test(v.transaction_sha256)&&
    ["applying","committed","recovered"].includes(String(v.transaction_state))&&date(v.created_at)&&v.transaction_format===2&&v.transaction_files===3&&
    bounded(v.transaction_bytes,16*1048576,1)&&typeof v.transaction_archived==="boolean"&&typeof v.transaction_archivable==="boolean"&&
    !(v.transaction_archived&&v.transaction_state==="applying")&&!(v.transaction_archivable&&(v.transaction_archived||v.transaction_state==="applying"));
}
export function apacheTransactionQuery(limit=16,offset=0) {
  if(!bounded(limit,32,1)||!bounded(offset,612))throw new Error("事务清单每页 1–32 条，起点最多 612");
  return `?limit=${limit}&offset=${offset}`;
}
export function apacheTransactionInventory(v:unknown,limit:number,offset:number):v is ApacheTransactionInventory {
  if(!object(v)||!Array.isArray(v.apache_transactions)||v.limit!==limit||v.offset!==offset||!bounded(limit,32,1)||!bounded(offset,612)||
    !bounded(v.total,612)||!bounded(v.transaction_active_count,100)||!bounded(v.transaction_archive_count,512)||
    v.total!==v.transaction_active_count+v.transaction_archive_count||v.transaction_slots_available!==100-v.transaction_active_count||
    !bounded(v.transaction_active_bytes,128*1048576)||!bounded(v.transaction_archive_bytes,256*1048576)||typeof v.pending!=="boolean"||
    typeof v.transaction_archive_ready!=="boolean"||typeof v.transaction_replay_ready!=="boolean"||typeof v.transaction_archive_blocked!=="string"||
    v.transaction_archive_blocked.length>1024||typeof v.scope!=="string"||v.scope.length>4096||v.records_retained!==true||v.configuration_changed!==false)return false;
  if(v.apache_transactions.length!==Math.min(limit,Math.max(0,v.total-offset)))return false;
  if(v.pending&&(v.transaction_archive_ready||v.transaction_replay_ready))return false;
  if(v.transaction_archive_ready&&!v.transaction_replay_ready)return false;
  const seen=new Set<string>();
  return v.apache_transactions.every(row=>apacheTransactionRow(row)&&!seen.has(row.transaction_id)&&
    (seen.add(row.transaction_id),true)&&!(row.transaction_archivable&&!v.transaction_archive_ready)&&!(v.pending&&row.transaction_archivable));
}
export function apacheArchiveBody(row:ApacheTransactionRow,confirm:string) {
  if(!apacheTransactionRow(row)||row.transaction_state==="applying"||(!row.transaction_archived&&!row.transaction_archivable)||confirm!==`ARCHIVE APACHE TRANSACTION ${row.transaction_id}`)throw new Error("先选择已结束事务并精确填写原标识确认");
  return {resource_id:row.transaction_id,expected_sha:row.transaction_sha256,confirm};
}
export function apacheArchiveReceipt(v:unknown,row:ApacheTransactionRow):v is ApacheArchiveReceipt {
  if(!object(v)||v.archived!==1||typeof v.replayed!=="boolean"||v.replayed!==row.transaction_archived||v.records_retained!==true||v.configuration_changed!==false||
    typeof v.scope!=="string"||v.scope.length>4096||!Array.isArray(v.apache_transactions)||v.apache_transactions.length!==1)return false;
  const item=v.apache_transactions[0];
  return apacheTransactionRow(item)&&item.transaction_archived&&!item.transaction_archivable&&
    item.transaction_id===row.transaction_id&&item.transaction_sha256===row.transaction_sha256&&item.transaction_bytes===row.transaction_bytes&&
    item.created_at===row.created_at&&item.transaction_state===row.transaction_state;
}
