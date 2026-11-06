import fs from 'node:fs';
import path from 'node:path';
import {candidateSource} from './candidate-source.mjs';
export function nativeMobile133Cases(root){
 const stable=JSON.parse(fs.readFileSync(path.join(root,'registry/apps.json'))),overrides=JSON.parse(fs.readFileSync(path.join(root,'registry/candidate-apps.json')));
 const current=overrides.apps.find(a=>a.id==='mobile'),cases=[{name:'exact133',manifest:structuredClone(current),valid:true}];
 const old=JSON.parse(fs.readFileSync(path.join(root,'candidate/dist/apps/mobile/1.3.2/manifest.json')));
 cases.push({name:'original132',manifest:old,valid:true});
 const mutations=[
  ['missing-feature',a=>delete a.required_panel_features],['empty-feature',a=>a.required_panel_features=[]],['wrong-feature',a=>a.required_panel_features=['mobile-native-delivery-v132']],
  ['duplicate',a=>a.required_panel_features=['mobile-native-delivery-v133','mobile-native-delivery-v133']],['mixed',a=>a.required_panel_features=['mobile-native-delivery-v132','mobile-native-delivery-v133']],
  ['foreign-id',a=>a.id='daily-report'],['foreign-target',a=>a.delivery.target='daily-report'],['foreign-scope',a=>{a.id='daily-report';a.delivery.target='daily-report';}],
  ['runtime',a=>a.delivery.provider='runtime'],['compose',a=>a.delivery.provider='compose'],['missing-route',a=>delete a.delivery.manage_route],['wrong-route',a=>a.delivery.manage_route='security']
 ];
 for(const version of ['1.0','1.0-compat1','1.1.0','1.2.0','1.3.0','1.3.1','1.3.2','1.3.3-compat1','01.3.3','1.3.4','1.4.0','unknown',133])mutations.push(['wrong-version:'+version,a=>a.version=version]);
 for(const[name,mutate]of mutations){const app=structuredClone(current);mutate(app);cases.push({name,manifest:app,valid:false});}
 for(const a of stable.apps)cases.push({name:'stable50:'+a.id,manifest:a,valid:true});
 for(const a of candidateSource(stable,overrides).apps)cases.push({name:'candidate50:'+a.id,manifest:a,valid:true});
 return cases;
}
