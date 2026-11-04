// Publisher authority for the independent Apache native request-body handler.
// Keep every published metadata-only identity readable; new labels require review.
export const apacheNativeBodyFeature='apache-native-body-site-transactions-v1';
export const apacheNativeBodyVersion='2.4.0';
export const apacheNativeCCFeature='apache-native-cc-site-transactions-v1';
export const apacheNativeCCVersion='2.5.0';
export const apacheCCArchiveFeature='apache-cc-log-archive-v1';
export const apacheCCArchiveVersion='2.5.1';
export const apacheLegacyVersions=Object.freeze(['1.0','1.0-compat1','1.1.0','2.0.0','2.1.0','2.2.0','2.3.0']);

export function apacheNativeBodyErrors(app){
  const requirements=app?.required_panel_features;
  const feature=Array.isArray(requirements)&&requirements.some(f=>f===apacheNativeBodyFeature||f===apacheNativeCCFeature||f===apacheCCArchiveFeature);
  if(app?.id!=='apache-waf'&&app?.delivery?.target!=='apache-waf'&&!feature)return null;
  const delivery=app?.delivery;
  if(app?.id!=='apache-waf'||delivery?.provider!=='panel-module'||delivery?.target!=='apache-waf'||delivery?.manage_route!=='app-modules'||Object.keys(delivery??{}).sort().join(',')!=='manage_route,provider,target')return ['Apache requires its exact application identity and fixed independent panel-module delivery'];
  if(apacheLegacyVersions.includes(app.version))return Object.hasOwn(app,'required_panel_features')?['Historical Apache metadata versions cannot borrow a new compiled handler']:[];
  if(app.version===apacheCCArchiveVersion)return Array.isArray(requirements)&&requirements.length===3&&requirements[0]===apacheNativeBodyFeature&&requirements[1]===apacheNativeCCFeature&&requirements[2]===apacheCCArchiveFeature?[]:['Apache CC archive requires exact2.5.1 and all three ordered independent body, CC and archive handlers'];
  if(app.version===apacheNativeCCVersion)return Array.isArray(requirements)&&requirements.length===2&&requirements[0]===apacheNativeBodyFeature&&requirements[1]===apacheNativeCCFeature?[]:['Apache native CC requires exact2.5.0 and both ordered independent body and CC site-transaction handlers'];
  if(app.version!==apacheNativeBodyVersion||!Array.isArray(requirements)||requirements.length!==1||requirements[0]!==apacheNativeBodyFeature)return ['Apache native request-body protection requires exact2.4.0 and its single compiled site-transaction handler; aliases and future labels need independent review'];
  return [];
}
