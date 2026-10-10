const planID=/^[a-z0-9][a-z0-9-]{2,63}$/, siteID=/^[a-f0-9]{32}$/;
const revision=(n:unknown):n is number=>Number.isSafeInteger(n) && Number(n)>0;
export const remotePlanActions=['remote-plans','schedule-remote-plan','pause-remote-plan','resume-remote-plan','remove-remote-plan'];
export function remotePlanFields(value:unknown):Record<string,unknown>|undefined {
  if(!value || typeof value!=='object' || Array.isArray(value))return;
  const v=value as Record<string,any>;
  if(!planID.test(v.id) || !planID.test(v.remote_target_id) || !siteID.test(v.site_id) || !revision(v.revision) || !revision(v.remote_target_revision) || typeof v.enabled!=='boolean' || !Number.isInteger(v.interval) || v.interval<60 || v.interval>86400 || !Array.isArray(v.excludes) || v.excludes.length>64 || v.excludes.some((p:unknown)=>typeof p!=='string' || p.length<1 || p.length>512) || !['pending','queueing','queued','succeeded','paused','paused-error','removed'].includes(v.last_state))return;
  return {resource_id:v.id,remote_target_id:v.remote_target_id,site_id:v.site_id,expected_revision:v.revision,remote_target_revision:v.remote_target_revision,interval:v.interval,enabled:v.enabled,excludes:[...v.excludes]};
}
// No credentials, manual task identity, realtime flag or unrelated form data
// can escape into these actions. Connection and plan revisions are independent.
export function remotePlanBody(action:string,form:Record<string,any>,expectedRevision:unknown):Record<string,unknown> {
  if(!remotePlanActions.includes(action))throw Error('远端计划动作无效');
  if(action==='remote-plans')return {};
  if(!planID.test(form.resource_id) || !Number.isSafeInteger(expectedRevision) || Number(expectedRevision)<0)throw Error('请填写计划标识并选择当前计划修订号');
  const body:Record<string,unknown>={resource_id:form.resource_id,expected_revision:expectedRevision};
  if(action==='schedule-remote-plan' || action==='resume-remote-plan'){
    if(!revision(form.remote_target_revision))throw Error('先选择并核对已启用远端连接的修订号');
    body.remote_target_revision=form.remote_target_revision;
  }
  if(action==='schedule-remote-plan'){
    if(!planID.test(form.remote_target_id) || !siteID.test(form.site_id) || !Number.isInteger(form.interval) || form.interval<60 || form.interval>86400 || typeof form.enabled!=='boolean')throw Error('远端计划来源、目标、启用选择或间隔无效');
    const excludes=typeof form.excludes==='string'?JSON.parse(form.excludes||'[]'):form.excludes??[];
    if(!Array.isArray(excludes) || excludes.length>64 || excludes.some((p:unknown)=>typeof p!=='string' || !p.length || p.length>512))throw Error('最多 64 个有效排除路径');
    Object.assign(body,{remote_target_id:form.remote_target_id,site_id:form.site_id,interval:form.interval,enabled:form.enabled,excludes:[...excludes].sort()});
  }
  return body;
}
