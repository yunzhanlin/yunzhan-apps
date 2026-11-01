import {apacheNativeBodyFeature} from './apache-native-body-contract.mjs';
export function apacheNativeBodyCases(base){
  const current=structuredClone(base);current.version='2.4.0';current.required_panel_features=[apacheNativeBodyFeature];
  const cases=[{name:'exact-native-2.4.0',valid:true,manifest:current}];
  for(const[name,change]of[
    ['missing-handler',m=>delete m.required_panel_features],['empty-handler',m=>m.required_panel_features=[]],['null-handler',m=>m.required_panel_features=null],['string-handler',m=>m.required_panel_features=apacheNativeBodyFeature],
    ['duplicate-handler',m=>m.required_panel_features.push(apacheNativeBodyFeature)],['borrowed-handler',m=>m.required_panel_features=['waf-bound-health-v1']],['extra-handler',m=>m.required_panel_features.push('waf-bound-health-v1')],['future-handler',m=>m.required_panel_features=['apache-native-body-site-transactions-v2']],
    ['foreign-id',m=>m.id='file-monitor'],['foreign-target',m=>m.delivery.target='nginx-waf'],['foreign-route',m=>m.delivery.manage_route='security'],['runtime-provider',m=>m.delivery.provider='runtime'],['compose-provider',m=>m.delivery.provider='compose'],['foreign-envelope',m=>m.delivery.image='unreviewed:latest'],
    ['native-handler-on-old-version',m=>m.version='2.3.0'],['alias',m=>m.version='2.4.0-compat1'],['prerelease-alias',m=>m.version='2.4.0-rc1'],['future-version',m=>m.version='2.4.1'],['future-without-handler',m=>{m.version='2.5.0';delete m.required_panel_features;}],['shortened-version',m=>m.version='2.4'],['leading-zero',m=>m.version='02.4.0'],['oversized-version',m=>m.version='18446744073709551616.0.0']
  ]){const manifest=structuredClone(current);change(manifest);cases.push({name,valid:false,manifest});}
  return cases;
}
