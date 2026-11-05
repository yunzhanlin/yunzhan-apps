export const filesSyncUnpublishedFeature='files-sync-unpublished-retention-v1';
export function filesSyncUnpublishedErrors(app){
 const features=app.required_panel_features,mentions=Array.isArray(features)&&features.includes(filesSyncUnpublishedFeature);
 if(!mentions&&!(app.id==='files-sync'&&app.version==='2.0.1'))return null;
 const wanted=['files-sync-root-independent-backup-v1',filesSyncUnpublishedFeature];
 if(app.id!=='files-sync'||app.version!=='2.0.1'||app.delivery?.provider!=='panel-module'||app.delivery?.target!=='files-sync'||app.delivery?.manage_route!=='app-modules'||!Array.isArray(features)||features.length!==2||new Set(features).size!==2||!wanted.every(v=>features.includes(v)))return ['unpublished fragment retention requires exact files-sync2.0.1, its fixed module identity, independent backup and bounded retention handlers'];
 return [];
}
