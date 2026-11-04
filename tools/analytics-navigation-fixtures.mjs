import fs from 'node:fs';
export function analyticsNavigationCases(root){
 const base=JSON.parse(fs.readFileSync(root+'/dist/apps/website-analytics/2.3.1/manifest.json'));
 const features=['analytics-session-lifecycle-v1','analytics-managed-client-address-v1','analytics-route-readiness-v1','analytics-navigation-order-v1'];
 const current=()=>({...structuredClone(base),version:'2.4.1',required_panel_features:[...features]});
 const cases=[{name:'exact241',valid:true,manifest:current()},{name:'reordered241',valid:true,manifest:{...current(),required_panel_features:[...features].reverse()}}];
 for(const[name,change]of[
  ['missing',m=>delete m.required_panel_features],['empty',m=>m.required_panel_features=[]],['null',m=>m.required_panel_features=null],['string',m=>m.required_panel_features=features[3]],
  ['three-only',m=>m.required_panel_features=features.slice(0,3)],['order-only',m=>m.required_panel_features=[features[3]]],['duplicate',m=>m.required_panel_features=[features[0],features[1],features[3],features[3]]],['extra',m=>m.required_panel_features.push('statistics-geodata-v2')],
  ['old',m=>m.version='2.4.0'],['future',m=>m.version='2.4.2'],['future-without-features',m=>{m.version='2.4.2';delete m.required_panel_features}],['future-major-without-features',m=>{m.version='3.0.0';delete m.required_panel_features}],
  ['short',m=>m.version='2.4'],['alias',m=>m.version='2.4.1-compat1'],['build',m=>m.version='2.4.1+build'],['leading-zero',m=>m.version='02.04.01'],['leading-zero-without-features',m=>{m.version='02.04.01';delete m.required_panel_features}],
  ['foreign-app',m=>{m.id='daily-report';m.delivery.target='daily-report'}],['target',m=>m.delivery.target='website-statistics-v2'],['route',m=>m.delivery.manage_route='security'],['runtime',m=>m.delivery.provider='runtime'],['unknown',m=>m.required_panel_features[3]='analytics-navigation-order-v2']
 ]){const manifest=current();change(manifest);cases.push({name,valid:false,manifest});}
 cases.push({name:'actual-candidate',valid:true,manifest:JSON.parse(fs.readFileSync(root+'/registry/candidate-apps.json')).apps.find(app=>app.id==='website-analytics')});
 return cases;
}
