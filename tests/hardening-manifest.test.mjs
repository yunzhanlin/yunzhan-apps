import test from'node:test';import assert from'node:assert/strict';import fs from'node:fs';import{validateManifest}from'../tools/lib.mjs';
const old=JSON.parse(fs.readFileSync(new URL('../dist/apps/system-hardening/1.0-compat1/manifest.json',import.meta.url))),feature='hardening-reversible-journal-v1';
const candidate=()=>({...structuredClone(old),version:'1.1.0',required_panel_features:[feature]});
test('fixed hardening package requires exact reviewed compiled identity, never a marketing version',()=>{
 assert.deepEqual(validateManifest(candidate()),[]);
 for(const patch of [{version:'1.1.0-compat1'},{version:'01.1.0'},{version:'1.1.1'},{version:'1.2.0'},{version:'18446744073709551616.0.0'},{version:'1.0-compat1'},{id:'daily-report'},{required_panel_features:[]},{required_panel_features:[feature,feature]},{required_panel_features:[feature,'statistics-geodata-v2']},{required_panel_features:['hardening-reversible-journal-v2']},{required_panel_features:null},{delivery:{provider:'runtime',target:'system-hardening',manage_route:'security'}},{delivery:{provider:'panel-module',target:'daily-report',manage_route:'security'}},{delivery:{provider:'panel-module',target:'system-hardening',manage_route:'app-modules'}}])assert(validateManifest({...candidate(),...patch}).length,JSON.stringify(patch));
 const missing=candidate();delete missing.required_panel_features;assert(validateManifest(missing).length);
 assert.deepEqual(validateManifest(old),[]);assert(!Object.hasOwn(old,'required_panel_features'));
});
test('schema independently binds feature to full version, target, provider and security workspace',()=>{
 const schema=JSON.parse(fs.readFileSync(new URL('../schema/app.schema.json',import.meta.url)));assert(schema.properties.required_panel_features.items.enum.includes(feature));
 const scope=schema.allOf[0].then.oneOf.find(v=>v.properties.id.const==='system-hardening').properties;assert.equal(scope.version.const,'1.1.0');for(const[k,v]of Object.entries({provider:'panel-module',target:'system-hardening',manage_route:'security'}))assert.equal(scope.delivery.properties[k].const,v);assert.deepEqual(scope.required_panel_features,{minItems:1,maxItems:1,items:{const:feature}});
 const guard=schema.allOf.find(v=>v.if?.properties?.id?.const==='system-hardening');assert.deepEqual(guard.then.required,['required_panel_features']);assert.deepEqual(guard.then.properties.required_panel_features,scope.required_panel_features);
});
