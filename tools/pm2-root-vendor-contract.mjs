import {pm2MaintenanceGuard} from './pm2-maintenance-contract.mjs';

export const pm2RootVendorFeature='pm2-root-vendor-v1';
export const pm2RootVendorVersion='7.0.4-compat11';
const pm2ID='pm2-manager';
export function pm2RootVendorErrors(app){
 const f=app.required_panel_features,mentions=Array.isArray(f)&&f.includes(pm2RootVendorFeature);
 if(!mentions&&!(app.version===pm2RootVendorVersion&&(app.id===pm2ID||app.delivery?.target===pm2ID)))return null;
 if(app.id!==pm2ID||app.version!==pm2RootVendorVersion||app.delivery?.provider!=='panel-module'||app.delivery?.target!==pm2ID||app.delivery?.manage_route!=='app-modules'||!Array.isArray(f)||f.length!==1||f[0]!==pm2RootVendorFeature)return ['PM2 Root vendor requires exact compat11 and its independent compiled handler'];
 return [];
}

const identity={required:['id'],properties:{id:{const:pm2ID}}};
const target={required:['delivery'],properties:{delivery:{required:['target'],properties:{target:{const:pm2ID}}}}};
export const pm2RootVendorScope={properties:{id:{const:pm2ID},version:{const:pm2RootVendorVersion},delivery:{required:['provider','target','manage_route'],properties:{provider:{const:'panel-module'},target:{const:pm2ID},manage_route:{const:'app-modules'}}},required_panel_features:{minItems:1,maxItems:1,items:{const:pm2RootVendorFeature}}}};
export const pm2RootVendorGuard={if:{anyOf:[
 {required:['required_panel_features'],properties:{required_panel_features:{contains:{const:pm2RootVendorFeature}}}},
 {required:['version'],properties:{version:{const:pm2RootVendorVersion}},anyOf:[identity,target]}
]},then:{required:['required_panel_features'],...pm2RootVendorScope}};

// Only the exact new independent scope may bypass the old stop guard. The
// original guard remains authoritative for all historical manifests.
export const pm2LegacyMaintenanceWithRootVendor={
 if:{allOf:[pm2MaintenanceGuard.if,{not:{required:['required_panel_features'],...pm2RootVendorScope}}]},
 then:pm2MaintenanceGuard.then,
};
