type Report = Record<string, unknown>;
const hexID = /^[a-f0-9]{32}$/, hexSHA = /^[a-f0-9]{64}$/;
const actions = ['run','save','probe','check-http','remove','recover','transactions','archive-transaction','history'];
const sections:Record<string,string[]> = {
  entries:['run','save','remove'], entry:['run','save','remove'],
  health:['run','probe','check-http','remove'], recovery:['run','recover'],
  transactions:['transactions'], 'transaction-archive':['archive-transaction'],
  history:['history'], reports:actions,
};
// Only current workspace data carries a same-origin authenticated attachment
// receipt. A cached result from another tab cannot turn into a download URL.
export function loadBalanceReportExportHref(section:string, report:Report|undefined, now:number):string|undefined {
  if(!report || Array.isArray(report) || !Number.isFinite(now) || report.token!==undefined)return;
  const value=report.report_export;
  if(!value || typeof value!=='object' || Array.isArray(value))return;
  const receipt=value as Report;
  const keys=['format','module','action','id','sha256','bytes','expires_at'];
  if(Object.keys(receipt).length!==keys.length || keys.some(key=>!Object.prototype.hasOwnProperty.call(receipt,key)) ||
     receipt.format!==1 || receipt.module!=='load-balance' || typeof receipt.action!=='string' || !sections[section]?.includes(receipt.action) ||
     typeof receipt.id!=='string' || !hexID.test(receipt.id) || typeof receipt.sha256!=='string' || !hexSHA.test(receipt.sha256) ||
     !Number.isSafeInteger(receipt.bytes) || Number(receipt.bytes)<1 || Number(receipt.bytes)>1048576 ||
     typeof receipt.expires_at!=='string' || !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{1,9})?Z$/.test(receipt.expires_at))return;
  const expires=Date.parse(receipt.expires_at);
  if(!Number.isFinite(expires) || expires<=now)return;
  return `/api/app-modules/load-balance/report-export/${receipt.id}?sha256=${receipt.sha256}`;
}
