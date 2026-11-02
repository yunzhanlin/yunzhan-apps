// Publication inputs only; these fixtures do not grant native service authority.
export function apacheNativeCCCases(base){
 const current=structuredClone(base);current.version='2.5.0';current.required_panel_features=['apache-native-body-site-transactions-v1','apache-native-cc-site-transactions-v1'];
 const cases=[{name:'exact-CC250-complete-ordered-authority',valid:true,manifest:current}];
 for(const[name,change]of[
  ['missing',m=>delete m.required_panel_features],['empty',m=>m.required_panel_features=[]],['null',m=>m.required_panel_features=null],['string',m=>m.required_panel_features='apache-native-cc-site-transactions-v1'],
  ['body-only',m=>m.required_panel_features.pop()],['CC-only',m=>m.required_panel_features.shift()],['reversed',m=>m.required_panel_features.reverse()],['duplicate-body',m=>m.required_panel_features[1]=m.required_panel_features[0]],['duplicate-CC',m=>m.required_panel_features[0]=m.required_panel_features[1]],
  ['extra-approved-feature',m=>m.required_panel_features.push('waf-bound-health-v1')],['extra-unknown-feature',m=>m.required_panel_features.push('apache-native-cc-site-transactions-v2')],
  ['foreign-id',m=>m.id='file-monitor'],['foreign-target',m=>m.delivery.target='nginx-waf'],['foreign-both',m=>{m.id='file-monitor';m.delivery.target='file-monitor';}],['foreign-route',m=>m.delivery.manage_route='security'],['runtime',m=>m.delivery.provider='runtime'],['compose',m=>m.delivery.provider='compose'],['extra-delivery',m=>m.delivery.image='unreviewed:latest'],
  ['metadata-version',m=>m.version='2.3.0'],['body-version',m=>m.version='2.4.0'],['alias',m=>m.version='2.5.0-compat1'],['prerelease',m=>m.version='2.5.0-rc1'],['future',m=>m.version='2.5.1'],['future-without-features',m=>{m.version='2.6.0';delete m.required_panel_features;}],['shortened',m=>m.version='2.5'],['leading-zero',m=>m.version='02.5.0'],['oversized',m=>m.version='18446744073709551616.0.0']
 ]){const manifest=structuredClone(current);change(manifest);cases.push({name,valid:false,manifest});}
 return cases;
}
