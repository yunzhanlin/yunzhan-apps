import fs from 'node:fs';
import path from 'node:path';
import {pm2MaintenanceCases} from './pm2-maintenance-fixtures.mjs';

export function pm2RootVendorCases(root){
 const source=JSON.parse(fs.readFileSync(path.join(root,'registry/candidate-apps.json')));
 const current=source.apps.find(app=>app.id==='pm2-manager');
 const cases=[...pm2MaintenanceCases(root),{name:'exact-PM2-root-vendor-11',manifest:current,valid:true}];
 const mutations=[
  ['missing-feature',a=>delete a.required_panel_features],
  ['empty',a=>a.required_panel_features=[]],
  ['old-stop-feature',a=>a.required_panel_features=['pm2-evidence-preserving-stop-v1']],
  ['duplicate',a=>a.required_panel_features.push(a.required_panel_features[0])],
  ['extra',a=>a.required_panel_features.push('pm2-evidence-preserving-stop-v1')],
  ['different-app',a=>a.id='daily-report'],
  ['different-target',a=>a.delivery.target='daily-report'],
  ['different-route',a=>a.delivery.manage_route='security'],
  ['missing-route',a=>delete a.delivery.manage_route],
  ['runtime',a=>a.delivery.provider='runtime'],
  ['compose',a=>a.delivery.provider='compose'],
  ['alias',a=>a.version='7.0.4-compat11.0'],
  ['future',a=>a.version='7.0.4-compat12'],
  ['legacy',a=>a.version='7.0.4-compat10'],
 ];
 for(const [name,mutate]of mutations){const manifest=structuredClone(current);mutate(manifest);cases.push({name:'root-vendor:'+name,manifest,valid:false});}
 return cases;
}
