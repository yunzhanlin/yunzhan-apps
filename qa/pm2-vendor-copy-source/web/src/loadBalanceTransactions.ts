type Form = Record<string,unknown>;
const id=/^[a-f0-9]{32}$/,sha=/^[a-f0-9]{64}$/;
export const loadBalanceTransactionActions=['transactions','archive-transaction'];
// The server's last report belongs to its actual operation, not every tab.
// Never put cached entry status in the transaction inventory or an inventory
// into a completed archive receipt, including after an asynchronous tab change.
export function loadBalanceReportForSection(section:string,value:Form|undefined):Form|undefined {
  if(!value||Array.isArray(value)||typeof value!=='object')return;
  if(section==='reports')return value;
  const rows=value.load_transactions;
  if(section==='transactions'||section==='transaction-archive') {
    if(!Array.isArray(rows)||rows.length>32||value.records_retained!==true||value.configuration_changed!==false||rows.some(row=>!row||typeof row!=='object'||!loadBalanceTransactionFields(row)))return;
    if(section==='transaction-archive') {
      if(rows.length!==1||value.archived!==1||typeof value.replayed!=='boolean'||rows[0].transaction_archived!==true||rows[0].transaction_archivable!==false)return;
    } else {
      const bounded=(key:string,max:number,min=0)=>Number.isSafeInteger(value[key])&&Number(value[key])>=min&&Number(value[key])<=max;
      if(!bounded('limit',32,1)||!bounded('offset',2560)||!bounded('total',2560)||!bounded('transaction_active_count',512)||!bounded('transaction_archive_count',2048)||Number(value.transaction_active_count)+Number(value.transaction_archive_count)!==value.total||rows.length>Number(value.limit)||rows.length>Number(value.total))return;
    }
    return value;
  }
  if(['entries','entry','health','recovery'].includes(section)&&rows===undefined)return value;
}
export function loadBalanceTransactionQueryMatches(value:Form|undefined,form:Form):boolean {
  return !!loadBalanceReportForSection('transactions',value)&&value?.limit===(form.limit??16)&&value?.offset===(form.offset??0);
}
export function loadBalanceTransactionFields(row:Form):Form|undefined {
  if(typeof row.transaction_id!=='string'||!id.test(row.transaction_id)||typeof row.transaction_sha256!=='string'||!sha.test(row.transaction_sha256)||
    !['committed','recovered','applying','restored'].includes(String(row.transaction_state))||typeof row.transaction_archived!=='boolean'||typeof row.transaction_archivable!=='boolean'||
    !Number.isSafeInteger(row.transaction_bytes)||Number(row.transaction_bytes)<1||Number(row.transaction_bytes)>256*1024)return;
  const terminal=['committed','recovered'].includes(String(row.transaction_state));
  if(row.transaction_archived&&(!terminal||row.transaction_archivable)||row.transaction_archivable&&!terminal)return;
  return {resource_id:row.transaction_id,expected_sha:row.transaction_sha256,confirm:''};
}
export function loadBalanceTransactionBody(action:string,form:Form):Form {
  if(action==='transactions') {
    const limit=form.limit??16,offset=form.offset??0;
    if(!Number.isSafeInteger(limit)||Number(limit)<1||Number(limit)>32||!Number.isSafeInteger(offset)||Number(offset)<0||Number(offset)>2560)throw Error('事务清单每页 1–32 条，起点 0–2560');
    return {limit,offset};
  }
  if(action!=='archive-transaction'||typeof form.resource_id!=='string'||!id.test(form.resource_id)||typeof form.expected_sha!=='string'||!sha.test(form.expected_sha)||form.confirm!==`ARCHIVE LOAD TRANSACTION ${form.resource_id}`)throw Error('请从完整库存选择事务、核对摘要并填写 ARCHIVE LOAD TRANSACTION 原事务标识');
  return {resource_id:form.resource_id,expected_sha:form.expected_sha,confirm:form.confirm};
}
