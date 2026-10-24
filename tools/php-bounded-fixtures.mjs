import {phpSecurityCases} from './php-security-fixtures.mjs';
import {phpSecurityBindings,phpSecurityFeature} from './php-security-contract.mjs';
import {phpBoundedFeature} from './php-bounded-contract.mjs';

export function phpBoundedCases(root){
 const result=phpSecurityCases(root);
 for(const[id,b]of Object.entries(phpSecurityBindings)){
  const base=structuredClone(result.find(c=>c.name===id+':exact').manifest);
  base.version=b.patched+'-compat2';base.required_panel_features=[phpSecurityFeature,phpBoundedFeature];
  result.push({name:id+':bounded-exact',valid:true,manifest:structuredClone(base)});
  const reverse=structuredClone(base);reverse.required_panel_features.reverse();result.push({name:id+':bounded-reversed',valid:true,manifest:reverse});
  const mutations=[
   ['missing',m=>delete m.required_panel_features],['empty',m=>m.required_panel_features=[]],['null',m=>m.required_panel_features=null],['string',m=>m.required_panel_features=phpBoundedFeature],
   ['security-only',m=>m.required_panel_features=[phpSecurityFeature]],['bounded-only',m=>m.required_panel_features=[phpBoundedFeature]],
   ['duplicate-security',m=>m.required_panel_features=[phpSecurityFeature,phpSecurityFeature]],['duplicate-bounded',m=>m.required_panel_features=[phpBoundedFeature,phpBoundedFeature]],
   ['extra',m=>m.required_panel_features.push('runtime-package-version-v1')],['future-feature',m=>m.required_panel_features[1]='php-bounded-native-build-v2'],
   ['foreign-id',m=>m.id='daily-report'],['foreign-scope',m=>{m.id='daily-report';m.delivery.target='daily-report';}],['foreign-without-feature',m=>{m.id='daily-report';delete m.required_panel_features;}],
   ['foreign-target',m=>m.delivery.target='nginx-1.30.6'],['other-branch',m=>m.delivery.target='php-'+(id==='php-85'?'8.2.35':'8.5.12')],['old-target',m=>m.delivery.target='php-'+b.previous],
   ['route',m=>m.delivery.manage_route='security'],['missing-route',m=>delete m.delivery.manage_route],['module',m=>m.delivery.provider='panel-module'],['compose',m=>{m.delivery.provider='compose';m.delivery.image='php:latest';}],
   ['old-label',m=>m.version=b.previous+'-compat1'],['compat1-label',m=>m.version=b.patched+'-compat1'],['bare-label',m=>m.version=b.patched],['future-label',m=>m.version=b.patched+'-compat3'],['noncanonical-label',m=>m.version=b.patched+'-compat02'],
  ];
  for(const[name,mutate]of mutations){const manifest=structuredClone(base);mutate(manifest);result.push({name:id+':bounded:'+name,valid:false,manifest});}
 }
 return result;
}
