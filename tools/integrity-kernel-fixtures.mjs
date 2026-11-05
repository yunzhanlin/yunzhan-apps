import fs from'node:fs';
import{integrityKernelFeature}from'./integrity-kernel-manifest.mjs';
export function integrityKernelCases(root){
 const base=JSON.parse(fs.readFileSync(root+'/dist/apps/website-tamper-proof/1.4.1/manifest.json'));
 const current=()=>({...structuredClone(base),version:'1.5.0',required_panel_features:[integrityKernelFeature]});
 const cases=[{name:'exact150',valid:true,manifest:current()},{name:'original141',valid:true,manifest:structuredClone(base)}];
 for(const[name,change]of[
  ['missing',m=>delete m.required_panel_features],['null',m=>m.required_panel_features=null],['empty',m=>m.required_panel_features=[]],['string',m=>m.required_panel_features=integrityKernelFeature],['duplicate',m=>m.required_panel_features.push(integrityKernelFeature)],['foreign-feature',m=>m.required_panel_features=['hardening-reversible-journal-v1']],['unknown-feature',m=>m.required_panel_features=['integrity-kernel-inode-journal-v2']],
  ['old-with-feature',m=>m.version='1.4.1'],['future',m=>m.version='1.5.1'],['future-without-feature',m=>{m.version='1.5.1';delete m.required_panel_features}],['future-major-without-feature',m=>{m.version='2.0.0';delete m.required_panel_features}],['short',m=>m.version='1.5'],['alias',m=>m.version='1.5.0-compat1'],['build',m=>m.version='1.5.0+build'],['leading-zero',m=>m.version='01.05.00'],['leading-zero-without-feature',m=>{m.version='01.05.00';delete m.required_panel_features}],
  ['foreign-app',m=>{m.id='enterprise-tamper-proof';m.delivery.target=m.id}],['wrong-provider',m=>m.delivery.provider='runtime'],['wrong-target',m=>m.delivery.target='file-monitor'],['wrong-route',m=>m.delivery.manage_route='security'],
 ]){const manifest=current();change(manifest);cases.push({name,valid:false,manifest});}
 cases.push({name:'actual-candidate150',valid:true,manifest:JSON.parse(fs.readFileSync(root+'/registry/candidate-apps.json')).apps.find(app=>app.id==='website-tamper-proof')});
 return cases;
}
