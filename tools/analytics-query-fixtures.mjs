import fs from 'node:fs';
export const analyticsQueryFeatures=['analytics-session-lifecycle-v1','analytics-managed-client-address-v1','analytics-route-readiness-v1','analytics-navigation-order-v1','website-analytics-query-context-v1'];
export function analyticsQueryCases(root){
 const base=JSON.parse(fs.readFileSync(root+'/candidate/dist/apps/website-analytics/2.4.1/manifest.json'));
 const current=()=>({...structuredClone(base),version:'2.4.2',required_panel_features:[...analyticsQueryFeatures]});
 const cases=[{name:'exact242',valid:true,manifest:current()},{name:'reordered242',valid:true,manifest:{...current(),required_panel_features:[...analyticsQueryFeatures].reverse()}},{name:'original241',valid:true,manifest:base}];
 for(const [name,change]of[
  ['missing',m=>delete m.required_panel_features],['null',m=>m.required_panel_features=null],['empty',m=>m.required_panel_features=[]],['scalar',m=>m.required_panel_features=analyticsQueryFeatures[4]],
  ['four-only',m=>m.required_panel_features.pop()],['query-only',m=>m.required_panel_features=analyticsQueryFeatures.slice(4)],['duplicate',m=>m.required_panel_features[0]=analyticsQueryFeatures[4]],['extra',m=>m.required_panel_features.push('statistics-geodata-v2')],
  ['old',m=>m.version='2.4.1'],['future',m=>m.version='2.4.3'],['future-no-features',m=>{m.version='2.4.3';delete m.required_panel_features}],['short',m=>m.version='2.4'],
  ['alias',m=>m.version='2.4.2-compat1'],['build',m=>m.version='2.4.2+build'],['leading-zero',m=>m.version='02.4.2'],['leading-zero-no-features',m=>{m.version='02.4.2';delete m.required_panel_features}],
  ['foreign-app',m=>{m.id='daily-report';m.delivery.target='daily-report'}],['provider',m=>m.delivery.provider='runtime'],['target',m=>m.delivery.target='website-statistics-v2'],['route',m=>m.delivery.manage_route='security'],['foreign-feature',m=>m.required_panel_features[4]='website-analytics-query-context-v2']
 ]){const manifest=current();change(manifest);cases.push({name,valid:false,manifest});}
 cases.push({name:'actual-candidate',valid:true,manifest:JSON.parse(fs.readFileSync(root+'/registry/candidate-apps.json')).apps.find(a=>a.id==='website-analytics')});
 return cases;
}
