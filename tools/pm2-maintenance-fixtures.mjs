import fs from 'node:fs';
import path from 'node:path';
import {candidateSource} from './candidate-source.mjs';
export function pm2MaintenanceCases(root){
 const stable=JSON.parse(fs.readFileSync(path.join(root,'registry/apps.json'))),overrides=JSON.parse(fs.readFileSync(path.join(root,'registry/candidate-apps.json')));
 const current=overrides.apps.find(a=>a.id==='pm2-manager'),cases=[{name:'exact10',manifest:structuredClone(current),valid:true}];
 for(const name of fs.readdirSync(path.join(root,'candidate/dist/apps/pm2-manager')).sort()){
  if(name==='7.0.4-compat10')continue;
  const manifest=JSON.parse(fs.readFileSync(path.join(root,'candidate/dist/apps/pm2-manager',name,'manifest.json')));
  cases.push({name:'actual-original-PM2:'+name,manifest,valid:true});
 }
 const mutations=[
 ['missing',a=>delete a.required_panel_features],['empty',a=>a.required_panel_features=[]],
 ['duplicate',a=>a.required_panel_features.push(a.required_panel_features[0])],['mixed',a=>a.required_panel_features.push('mobile-native-delivery-v133')],
 ['foreign-feature',a=>a.required_panel_features=['mobile-native-delivery-v133']],['foreign-id',a=>a.id='daily-report'],
 ['foreign-target',a=>a.delivery.target='daily-report'],['foreign-id-no-feature',a=>{a.id='daily-report';delete a.required_panel_features;}],
 ['foreign-provider-runtime',a=>a.delivery.provider='runtime'],['foreign-provider-compose',a=>a.delivery.provider='compose'],
 ['missing-route',a=>delete a.delivery.manage_route],['foreign-route',a=>a.delivery.manage_route='security']
 ];
 for(const version of ['6','7.0.4','7.0.4-compat9','7.0.4-compat10.0','7.0.4-compat10-alias','7.0.4-compat11','7.0.5','99.0.0',10])mutations.push(['wrong-version-with-feature:'+version,a=>a.version=version]);
 for(const [name,mutate]of mutations){const manifest=structuredClone(current);mutate(manifest);cases.push({name,manifest,valid:false});}
 for(const version of ['7.0.4.0','7.0.4-compat9.0','7.0.4-compat11','7.0.5','99.0.0']){const manifest=structuredClone(current);manifest.version=version;delete manifest.required_panel_features;cases.push({name:'unbound-new-version:'+version,manifest,valid:false});}
 for(const a of stable.apps)cases.push({name:'stable50:'+a.id,manifest:a,valid:true});
 for(const a of candidateSource(stable,overrides).apps)cases.push({name:'candidate50:'+a.id,manifest:a,valid:true});
 return cases;
}

