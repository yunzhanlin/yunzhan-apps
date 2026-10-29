import test from'node:test';import assert from'node:assert/strict';import fs from'node:fs';import{validateManifest}from'../tools/lib.mjs';
const old=JSON.parse(fs.readFileSync(new URL('../dist/apps/nginx-waf/2.5.2/manifest.json',import.meta.url))),feature='waf-country-signed-data-v1';
const candidate=()=>({...structuredClone(old),version:'2.6.0',required_panel_features:[feature],country_data_channel:{id:'dbip-country-lite-v1',format:1}});
test('country application preserves historical252 and requires exact independent260 handler',()=>{
 assert.deepEqual(validateManifest(old),[]);assert.deepEqual(validateManifest(candidate()),[]);
 const changes=[{version:'2.5.2'},{version:'2.6.0-preview'},{version:'2.6.0.0'},{version:'2.6.1'},{version:'2.7.0'},{id:'apache-waf'},{required_panel_features:[]},{required_panel_features:null},{required_panel_features:[feature,feature]},{required_panel_features:[feature,'waf-bound-health-v1']},{required_panel_features:['waf-bound-health-v1']},{delivery:{provider:'runtime',target:'nginx-waf',manage_route:'security'}},{delivery:{provider:'panel-module',target:'apache-waf',manage_route:'security'}},{delivery:{provider:'panel-module',target:'nginx-waf',manage_route:'app-modules'}},{country_data_channel:null},{country_data_channel:{id:'dbip-city-lite-v1',format:1}},{country_data_channel:{id:'dbip-country-lite-v1',format:2}},{geo_data_channel:{id:'dbip-city-lite-v1',format:1}}];
 for(const change of changes)assert(validateManifest({...candidate(),...change}).length,JSON.stringify(change));
 for(const key of['required_panel_features','country_data_channel']){const app=candidate();delete app[key];assert(validateManifest(app).length,key);}
 for(const extra of['url','public_key','script','download_url','path','fallback']){const app=candidate();app.country_data_channel[extra]='caller override';assert(validateManifest(app).length,extra);}
 for(const extra of['image','isolation']){const app=candidate();app.delivery[extra]='caller override';assert(validateManifest(app).length,extra);}
});
test('country schema binds mandatory feature channel and target without changing health252',()=>{
 const s=JSON.parse(fs.readFileSync(new URL('../schema/app.schema.json',import.meta.url))),branches=s.allOf[0].then.oneOf;
 assert(s.properties.required_panel_features.items.enum.includes(feature));assert.equal(s.properties.country_data_channel.additionalProperties,false);
 const country=branches.find(v=>v.properties.id.const==='nginx-waf'&&v.properties.version.const==='2.6.0');assert(country.required.includes('country_data_channel'));assert.equal(country.properties.required_panel_features.items.const,feature);assert.equal(country.properties.delivery.properties.manage_route.const,'security');assert(country.not.required.includes('geo_data_channel'));
 const legacy=branches.find(v=>v.properties.id.const==='nginx-waf'&&v.properties.version.const==='2.5.2');assert.equal(legacy.properties.required_panel_features.items.const,'waf-bound-health-v1');
});
