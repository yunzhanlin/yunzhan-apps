import fs from 'node:fs';
import {filesSyncUnpublishedFeature as feature}from './files-sync-unpublished-manifest.mjs';
export function filesSyncUnpublishedCases(root){
 const old=JSON.parse(fs.readFileSync(root+'/candidate/dist/apps/files-sync/2.0.0/manifest.json'));
 const current=()=>({...structuredClone(old),version:'2.0.1',required_panel_features:['files-sync-root-independent-backup-v1',feature]});
 const reversed=current();reversed.required_panel_features.reverse();
 const cases=[{name:'exact201',valid:true,manifest:current()},{name:'exact201-distinct-order',valid:true,manifest:reversed},{name:'original200',valid:true,manifest:old}];
 for(const[name,edit]of[
  ['missing',m=>delete m.required_panel_features],['null',m=>m.required_panel_features=null],['old-only',m=>m.required_panel_features.pop()],['new-only',m=>m.required_panel_features.shift()],['empty',m=>m.required_panel_features=[]],['duplicate',m=>m.required_panel_features[1]=m.required_panel_features[0]],['extra',m=>m.required_panel_features.push('analytics-navigation-order-v1')],['unknown',m=>m.required_panel_features[1]='files-sync-unpublished-retention-v2'],
  ...['1.9.0','2.0.0','2.0.1-compat1','2.0.1+build','2.0.2','2.1','3.0.0','02.00.01'].map(v=>['version-'+v,m=>m.version=v]),
  ['foreign-app',m=>{m.id='daily-report';m.delivery.target=m.id}],['wrong-provider',m=>m.delivery.provider='runtime'],['wrong-target',m=>m.delivery.target='file-monitor'],['wrong-route',m=>m.delivery.manage_route='security'],
 ]){const manifest=current();edit(manifest);cases.push({name,valid:false,manifest})}
 const actual=JSON.parse(fs.readFileSync(root+'/registry/candidate-apps.json')).apps.find(m=>m.id==='files-sync');
 if(!actual||actual.version!=='2.0.1')throw Error('actual candidate files-sync201 missing');
 cases.push({name:'actual-candidate201',valid:true,manifest:actual});return cases;
}
