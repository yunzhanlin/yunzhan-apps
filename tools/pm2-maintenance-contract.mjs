export const pm2MaintenanceFeature='pm2-evidence-preserving-stop-v1';
export const pm2MaintenanceVersion='7.0.4-compat10';
export const pm2LegacyVersions=['6','7.0.4',...Array.from({length:9},(_,i)=>'7.0.4-compat'+(i+1))];
export function pm2LegacyVersion(version){
 if(pm2LegacyVersions.includes(version))return true;
 if(typeof version!=='string'||version.length>80||!/^[0-9]+(?:\.[0-9]+){0,3}(?:-[A-Za-z0-9]+(?:[.-][A-Za-z0-9]+)*)?$/.test(version))return false;
 const parts=version.split('-')[0].split('.').map(BigInt),floor=[7n,0n,4n];
 if(parts.some(v=>v>18446744073709551615n))return false;
 for(let i=0;i<Math.max(parts.length,floor.length);i++){if((parts[i]??0n)!==(floor[i]??0n))return (parts[i]??0n)<(floor[i]??0n);}
 return false;
}
export function pm2MaintenanceErrors(app){
 const features=app.required_panel_features,mentions=Array.isArray(features)&&features.includes(pm2MaintenanceFeature);
 if(!mentions&&app.id!=='pm2-manager'&&app.delivery?.target!=='pm2-manager')return null;
 if(!mentions&&app.id==='pm2-manager'&&pm2LegacyVersion(app.version))return [];
 if(app.id!=='pm2-manager'||app.version!==pm2MaintenanceVersion||app.delivery?.provider!=='panel-module'||app.delivery?.target!=='pm2-manager'||app.delivery?.manage_route!=='app-modules'||!Array.isArray(features)||features.length!==1||features[0]!==pm2MaintenanceFeature)return ['PM2 preserving stop requires exact compat10, its fixed identity and independent compiled handler'];
 return [];
}
export const pm2MaintenanceScope={properties:{id:{const:'pm2-manager'},version:{const:pm2MaintenanceVersion},delivery:{required:['provider','target','manage_route'],properties:{provider:{const:'panel-module'},target:{const:'pm2-manager'},manage_route:{const:'app-modules'}}},required_panel_features:{minItems:1,maxItems:1,items:{const:pm2MaintenanceFeature}}}};
const olderNumeric='^(?:0*[0-6](?:\\.[0-9]+){0,3}|0*7(?:\\.0+(?:\\.0*[0-3](?:\\.[0-9]+)?)?)?)(?:-[A-Za-z0-9]+(?:[.-][A-Za-z0-9]+)*)?$';
export const pm2MaintenanceGuard={if:{anyOf:[
 {required:['required_panel_features'],properties:{required_panel_features:{contains:{const:pm2MaintenanceFeature}}}},
 {required:['id','version'],properties:{id:{const:'pm2-manager'},version:{not:{anyOf:[{enum:pm2LegacyVersions},{pattern:olderNumeric}]}}}},
 {required:['delivery'],properties:{delivery:{required:['target'],properties:{target:{const:'pm2-manager'}}}},not:{required:['id'],properties:{id:{const:'pm2-manager'}}}}
]},then:{required:['required_panel_features'],...pm2MaintenanceScope}};

