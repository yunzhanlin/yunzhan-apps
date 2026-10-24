export function loadBalanceRoutingSaveBody(body:Record<string,unknown>):Record<string,unknown> {
  const health=body.health_check;
  if(health===undefined||health===null)return body;
  if(typeof health!=='object'||Array.isArray(health))throw Error('应用检查策略必须为完整对象');
  const policy=health as Record<string,unknown>;
  if(policy.auto_traffic!==undefined&&typeof policy.auto_traffic!=='boolean')throw Error('自动流量必须明确开启或关闭，不接受字符串或数字');
  if(policy.auto_traffic===true) {
    if(typeof body.domain!=='string'||!/^[a-z0-9][a-z0-9.-]*[a-z0-9]$/.test(body.domain)||body.confirm!==`ENABLE HEALTH ROUTING ${body.domain}`)throw Error('自动摘除与恢复须先核对当前入口，再填写 ENABLE HEALTH ROUTING 入口域名');
  }
  return body;
}
