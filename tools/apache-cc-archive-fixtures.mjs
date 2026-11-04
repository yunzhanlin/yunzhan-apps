// Closed publisher fixtures; a feature declaration does not enable protection.
export function apacheCCArchiveCases(base){
 const current=structuredClone(base);current.version='2.5.1';current.required_panel_features=['apache-native-body-site-transactions-v1','apache-native-cc-site-transactions-v1','apache-cc-log-archive-v1'];
 const cases=[{name:'exact251-all-three-ordered-handlers',valid:true,manifest:current}];
 for(const[name,change]of[
  ['missing',m=>delete m.required_panel_features],['empty',m=>m.required_panel_features=[]],['null',m=>m.required_panel_features=null],['string',m=>m.required_panel_features='apache-cc-log-archive-v1'],
  ['body-and-CC-only',m=>m.required_panel_features.pop()],['CC-and-archive-only',m=>m.required_panel_features.shift()],['archive-only',m=>m.required_panel_features=m.required_panel_features.slice(2)],['reversed',m=>m.required_panel_features.reverse()],['duplicate',m=>m.required_panel_features[2]=m.required_panel_features[1]],['extra-reviewed-feature',m=>m.required_panel_features.push('waf-bound-health-v1')],['unknown-feature',m=>m.required_panel_features[2]='apache-cc-log-archive-v2'],
  ['old250',m=>m.version='2.5.0'],['old240',m=>m.version='2.4.0'],['metadata230',m=>m.version='2.3.0'],['future252',m=>m.version='2.5.2'],['future-no-features',m=>{m.version='2.6.0';delete m.required_panel_features;}],['alias',m=>m.version='2.5.1-compat1'],['extra-component',m=>m.version='2.5.1.0'],['foreign-id',m=>m.id='file-monitor'],['foreign-target',m=>m.delivery.target='nginx-waf'],['foreign-both',m=>{m.id='file-monitor';m.delivery.target='file-monitor';}],['wrong-provider',m=>m.delivery.provider='runtime'],['wrong-route',m=>m.delivery.manage_route='security'],['extra-delivery',m=>m.delivery.command='/bin/sh'],['coerced-version',m=>m.version=251]
 ]){const manifest=structuredClone(current);change(manifest);cases.push({name,valid:false,manifest});}
 return cases;
}
