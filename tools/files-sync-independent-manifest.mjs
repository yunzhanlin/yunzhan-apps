export const filesSyncIndependentFeature='files-sync-root-independent-backup-v1';
export function filesSyncIndependentErrors(app){
 const features=app.required_panel_features,mentions=Array.isArray(features)&&features.includes(filesSyncIndependentFeature);
 if(app.id!=='files-sync')return mentions?['independent backup handler belongs only to files-sync2.0.0']:null;
 if(typeof app.version!=='string')return ['files-sync version must be a string'];
 const base=app.version.split('-')[0];
 if(!/^(?:0|[1-9][0-9]*)(?:\.(?:0|[1-9][0-9]*)){0,3}$/.test(base))return ['files-sync version is not canonical'];
 if(!mentions&&BigInt(base.split('.')[0])<2n)return null;
 if(app.version!=='2.0.0'||app.delivery?.provider!=='panel-module'||app.delivery?.target!==app.id||app.delivery?.manage_route!=='app-modules'||!Array.isArray(features)||features.length!==1||features[0]!==filesSyncIndependentFeature)return ['independent copies require exact files-sync2.0.0, fixed module identity and the complete Root-private copy/recovery/download handler'];
 return [];
}
