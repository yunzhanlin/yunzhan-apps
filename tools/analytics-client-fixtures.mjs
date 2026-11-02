import fs from'node:fs';import path from'node:path';
export function analyticsClientCases(root){
 const read=p=>JSON.parse(fs.readFileSync(path.join(root,p))),clone=v=>structuredClone(v);
 const old=read('dist/apps/website-analytics/2.3.1/manifest.json'),session='analytics-session-lifecycle-v1',address='analytics-managed-client-address-v1';
 const current=()=>({...clone(old),version:'2.3.2',required_panel_features:[session,address]});
 const cases=read('registry/apps.json').apps.map(m=>({name:'retained:'+m.id,valid:true,manifest:clone(m.id==='website-analytics'?old:m)}));
 cases.push({name:'exact232',valid:true,manifest:current()},{name:'reordered232',valid:true,manifest:{...current(),required_panel_features:[address,session]}});
 const mutations=[
  ['missing',m=>delete m.required_panel_features],['empty',m=>m.required_panel_features=[]],
  ['null',m=>m.required_panel_features=null],['string',m=>m.required_panel_features=address],
  ['duplicate',m=>m.required_panel_features=[address,address]],['extra',m=>m.required_panel_features.push('statistics-geodata-v2')],
  ['session-only',m=>m.required_panel_features=[session]],['address-only',m=>m.required_panel_features=[address]],
  ['alias',m=>m.version='2.3.2-compat1'],['build-alias',m=>m.version='2.3.2+build'],
  ['future',m=>m.version='2.3.3'],['leading-zero',m=>m.version='02.3.2'],
  ['legacy-new-feature',m=>m.version='2.3.1'],
  ['foreign',m=>{m.id='daily-report';m.delivery.target=m.id;}],
  ['target',m=>m.delivery.target='website-statistics-v2'],['route',m=>m.delivery.manage_route='security'],
  ['runtime',m=>m.delivery.provider='runtime'],['compose',m=>m.delivery.provider='compose']
 ];
 for(const[name,mutate]of mutations){const manifest=current();mutate(manifest);cases.push({name,valid:false,manifest});}
 return cases;
}
