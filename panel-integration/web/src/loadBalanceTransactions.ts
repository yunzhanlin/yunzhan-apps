type Form = Record<string,unknown>;
const id=/^[a-f0-9]{32}$/,sha=/^[a-f0-9]{64}$/;
export const loadBalanceTransactionActions=['transactions','archive-transaction'];
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
