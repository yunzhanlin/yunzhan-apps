import fs from'node:fs';import path from'node:path';import assert from'node:assert/strict';import{createHash}from'node:crypto';
export const mobileFeature='mobile-native-delivery-v132';
export const legacyMobileHashes={'1.0':'c68e5f899f9e00a28f1f67d67c334fb367d476c20f78dc9c3f591757a30b6dd4','1.0-compat1':'99d20ea2e6227a12ffb253d66f6680b37768f165e6123bbc2c7192b8bb3b48f5','1.1.0':'a57aeedfd0d444abfc25d44d32e1f084373a5051414790b63e2593d3ea6ece25','1.2.0':'4b8739ded0767e70b04578c712067c8eee1c31d4e4e84303e482497b1039c893','1.3.0':'d99c73e9118c0f80294d3c5140ae51d7243a5d7e8fc8d55d2e5a722a571e5657'};
export function nativeMobileCases(root){
 const result=[],legacy={};for(const[v,hash]of Object.entries(legacyMobileHashes)){const raw=fs.readFileSync(path.join(root,'dist/apps/mobile',v,'manifest.json'));assert.equal(createHash('sha256').update(raw).digest('hex'),hash,v);legacy[v]=JSON.parse(raw);result.push({name:'legacy:'+v,valid:true,manifest:legacy[v]});}
 const exact={...structuredClone(legacy['1.3.0']),version:'1.3.2',required_panel_features:[mobileFeature]};result.push({name:'exact132',valid:true,manifest:exact});
 const mutations=[
 ['missing',m=>delete m.required_panel_features],['empty',m=>m.required_panel_features=[]],['null',m=>m.required_panel_features=null],['string',m=>m.required_panel_features=mobileFeature],['duplicate',m=>m.required_panel_features=[mobileFeature,mobileFeature]],['extra',m=>m.required_panel_features=[mobileFeature,'analytics-session-lifecycle-v1']],['wrong',m=>m.required_panel_features=['analytics-session-lifecycle-v1']],['unreviewed-feature',m=>m.required_panel_features=['mobile-native-delivery-v133']],
 ['foreign-id',m=>m.id='daily-report'],['foreign-without-feature',m=>{m.id='daily-report';delete m.required_panel_features;}],['foreign-scope',m=>{m.id='daily-report';m.delivery.target='daily-report';}],['target',m=>m.delivery.target='website-analytics'],['route',m=>m.delivery.manage_route='security'],['missing-route',m=>delete m.delivery.manage_route],['runtime',m=>m.delivery.provider='runtime'],['compose',m=>m.delivery.provider='compose'],['legacy-with-feature',m=>m.version='1.3.0']
 ];
 for(const version of ['1.0.0','1.0-compat2','1.2.1','01.3.0','1.3.1','1.3.2-compat1','1.3.3','1.4.0','18446744073709551616.0.0','unknown'])for(const withFeature of [true,false])mutations.push(['unreviewed:'+version+':'+withFeature,m=>{m.version=version;if(!withFeature)delete m.required_panel_features;}]);
 for(const[name,mutate]of mutations){const manifest=structuredClone(exact);mutate(manifest);result.push({name,valid:false,manifest});}
 const current=JSON.parse(fs.readFileSync(path.join(root,'registry/apps.json')));assert.equal(current.apps.length,50);for(const m of current.apps)result.push({name:'current50:'+m.id,valid:true,manifest:m});
 return result;
}
