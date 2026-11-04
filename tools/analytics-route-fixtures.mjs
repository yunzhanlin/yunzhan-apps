import fs from 'node:fs';
import {analyticsClientCases} from './analytics-client-fixtures.mjs';
export function analyticsRouteCases(root){
 const cases=analyticsClientCases(root),legacy=JSON.parse(fs.readFileSync(root+'/dist/apps/website-analytics/2.3.1/manifest.json'));
 const features=['analytics-session-lifecycle-v1','analytics-managed-client-address-v1','analytics-route-readiness-v1'];
 const current=()=>({...structuredClone(legacy),version:'2.4.0',required_panel_features:[...features]});
 cases.push({name:'exact240',valid:true,manifest:current()},{name:'reordered240',valid:true,manifest:{...current(),required_panel_features:[...features].reverse()}});
 for(const[name,change]of[
  ['missing',m=>delete m.required_panel_features],['empty',m=>m.required_panel_features=[]],['null',m=>m.required_panel_features=null],['string',m=>m.required_panel_features=features[2]],
  ['two-only',m=>m.required_panel_features=features.slice(0,2)],['route-only',m=>m.required_panel_features=[features[2]]],['duplicate',m=>m.required_panel_features=[features[0],features[2],features[2]]],['extra',m=>m.required_panel_features.push('statistics-geodata-v2')],
  ['old',m=>m.version='2.3.2'],['future',m=>m.version='2.4.1'],['future-without-features',m=>{m.version='2.4.1';delete m.required_panel_features}],['future-major-without-features',m=>{m.version='3.0.0';delete m.required_panel_features}],
  ['short',m=>m.version='2.4'],['alias',m=>m.version='2.4.0-compat1'],['build-alias',m=>m.version='2.4.0+build'],['leading-zero',m=>m.version='02.4.0'],['leading-zero-without-features',m=>{m.version='02.04.00';delete m.required_panel_features}],
  ['other-app',m=>{m.id='daily-report';m.delivery.target='daily-report'}],['target',m=>m.delivery.target='website-statistics-v2'],['manage-route',m=>m.delivery.manage_route='security'],['runtime',m=>m.delivery.provider='runtime'],['unknown-handler',m=>m.required_panel_features[2]='analytics-route-readiness-v2'],
 ]){const manifest=current();change(manifest);cases.push({name:'route240:'+name,valid:false,manifest});}
 return cases;
}
