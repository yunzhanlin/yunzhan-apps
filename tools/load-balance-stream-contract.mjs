export const loadBalanceStreamFeature = 'load-balance-stream-controller-v1';
const equalSet = (a,b) => Array.isArray(a) && a.length === b.length && [...a].sort().every((v,i) => v === [...b].sort()[i]);
function newStreamVersion(value) {
  if(typeof value !== 'string' || !/^[0-9]+(?:\.[0-9]+){0,3}(?:-[A-Za-z0-9]+(?:[.-][A-Za-z0-9]+)*)?$/.test(value)) return false;
  const numbers=value.split('-')[0].split('.').map(BigInt),floor=[1n,9n,0n];
  for(let i=0;i<3;i++){const n=numbers[i]??0n;if(n!==floor[i])return n>floor[i];}
  return true;
}
export function loadBalanceStreamErrors(app) {
  const req=app?.required_panel_features,claimed=Array.isArray(req)&&req.includes(loadBalanceStreamFeature);
  if(!claimed && !(app?.id==='load-balance'&&newStreamVersion(app.version)) && !(app?.delivery?.target==='load-balance'&&app.id!=='load-balance')) return null;
  const errors=[],d=app?.delivery;
  if(app?.schema_version!==1||app.id!=='load-balance'||app.version!=='1.9.0'||app.category!=='professional'||app.stage!=='ready'||app.risk!=='privileged')errors.push('stream delivery requires exact load-balance1.9.0 identity');
  if(!d||d.provider!=='panel-module'||d.target!=='load-balance'||d.manage_route!=='app-modules'||Object.keys(d).sort().join(',')!=='manage_route,provider,target')errors.push('stream delivery cannot borrow a foreign target, image or installer');
  if(!Array.isArray(req)||req.length!==1||req[0]!==loadBalanceStreamFeature)errors.push('stream delivery requires its exact independently compiled handler');
  if(!equalSet(app?.compatibility?.os,['debian-12','debian-13','ubuntu-22.04','ubuntu-24.04','ubuntu-26.04'])||!equalSet(app?.compatibility?.architectures,['amd64','arm64']))errors.push('stream delivery requires the closed native OS and architecture set');
  if(!app?.health||app.health.probe!=='panel-api'||app.health.target!=='/api/app-modules/load-balance'||Object.keys(app.health).sort().join(',')!=='probe,target')errors.push('stream delivery requires its original panel API health route');
  if(!app?.uninstall||app.uninstall.preserve_data!==true||app.uninstall.reference_check!==true||Object.keys(app.uninstall).sort().join(',')!=='preserve_data,reference_check')errors.push('stream data and original references must be preserved');
  if(app.rule_data_channel!=null||app.geo_data_channel!=null||app.rule_feeds!=null&&(!Array.isArray(app.rule_feeds)||app.rule_feeds.length))errors.push('stream delivery cannot borrow another application data channel');
  return errors;
}
