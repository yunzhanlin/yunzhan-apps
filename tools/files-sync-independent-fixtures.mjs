import fs from 'node:fs';
import {filesSyncIndependentFeature}from './files-sync-independent-manifest.mjs';
export function filesSyncIndependentCases(root){
 const previous=JSON.parse(fs.readFileSync(root+'/dist/apps/files-sync/1.9.0/manifest.json'));
 const current=()=>({...structuredClone(previous),version:'2.0.0',required_panel_features:[filesSyncIndependentFeature]});
 const cases=[{name:'exact200',valid:true,manifest:current()},{name:'original190',valid:true,manifest:previous}];
 for(const[name,edit]of[
  ['missing-feature',m=>delete m.required_panel_features],['null',m=>m.required_panel_features=null],['empty',m=>m.required_panel_features=[]],['string',m=>m.required_panel_features=filesSyncIndependentFeature],['duplicate',m=>m.required_panel_features.push(filesSyncIndependentFeature)],['foreign-feature',m=>m.required_panel_features=['integrity-kernel-inode-journal-v1']],['unimplemented-feature',m=>m.required_panel_features=['files-sync-root-independent-backup-v2']],
  ['old-with-feature',m=>m.version='1.9.0'],['future',m=>m.version='2.0.1'],['future-without-feature',m=>{m.version='2.0.1';delete m.required_panel_features}],['future-major',m=>{m.version='3.0.0';delete m.required_panel_features}],['short',m=>m.version='2.0'],['alias',m=>m.version='2.0.0-compat1'],['build',m=>m.version='2.0.0+build'],['leading-zero',m=>m.version='02.00.00'],['leading-zero-without-feature',m=>{m.version='02.00.00';delete m.required_panel_features}],
  ['foreign-app',m=>{m.id='daily-report';m.delivery.target=m.id}],['wrong-provider',m=>m.delivery.provider='runtime'],['wrong-target',m=>m.delivery.target='file-monitor'],['wrong-route',m=>m.delivery.manage_route='security'],
 ]){const manifest=current();edit(manifest);cases.push({name,valid:false,manifest})}
 const actual=JSON.parse(fs.readFileSync(root+'/registry/candidate-apps.json')).apps.find(app=>app.id==='files-sync');
 if(!actual)throw Error('actual candidate files-sync is missing');cases.push({name:'actual-candidate',valid:true,manifest:actual});
 return cases;
}
