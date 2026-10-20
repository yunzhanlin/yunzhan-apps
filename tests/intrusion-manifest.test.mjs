import test from 'node:test';import assert from 'node:assert/strict';import fs from 'node:fs';import {validateManifest} from '../tools/lib.mjs';
const old=JSON.parse(fs.readFileSync(new URL('../dist/apps/anti-intrusion/1.0-compat1/manifest.json',import.meta.url))),feature='intrusion-preserving-journal-v2';
const candidate=()=>({...structuredClone(old),version:'1.1.0',required_panel_features:[feature]});
test('intrusion package requires exact final process-lifetime handler and preserves legacy bytes',()=>{
 assert.deepEqual(validateManifest(candidate()),[]);assert.deepEqual(validateManifest(old),[]);assert(!Object.hasOwn(old,'required_panel_features'));
 const variants=[{version:'1.1.0-compat1'},{version:'01.1.0'},{version:'1.1.1'},{version:'1.2.0'},{version:'18446744073709551616.0.0'},{version:'1.0-compat1'},{id:'system-hardening'},{id:'intrusion-prevention'},{required_panel_features:[]},{required_panel_features:[feature,feature]},{required_panel_features:[feature,'hardening-reversible-journal-v1']},{required_panel_features:['intrusion-preserving-journal-v1']},{required_panel_features:null},{delivery:{provider:'runtime',target:'intrusion-prevention',manage_route:'security'}},{delivery:{provider:'panel-module',target:'anti-intrusion',manage_route:'security'}},{delivery:{provider:'panel-module',target:'intrusion-prevention',manage_route:'app-modules'}}];
 for(const p of variants)assert(validateManifest({...candidate(),...p}).length,JSON.stringify(p));const missing=candidate();delete missing.required_panel_features;assert(validateManifest(missing).length);
});
test('schema independently restricts final feature to exact app version target and management workspace',()=>{
 const s=JSON.parse(fs.readFileSync(new URL('../schema/app.schema.json',import.meta.url)));assert(s.properties.required_panel_features.items.enum.includes(feature));assert(!s.properties.required_panel_features.items.enum.includes('intrusion-preserving-journal-v1'));
 const p=s.allOf[0].then.oneOf.find(v=>v.properties.id.const==='anti-intrusion').properties;assert.equal(p.version.const,'1.1.0');assert.deepEqual(p.delivery.properties,{provider:{const:'panel-module'},target:{const:'intrusion-prevention'},manage_route:{const:'security'}});assert.deepEqual(p.required_panel_features,{minItems:1,maxItems:1,items:{const:feature}});
 const g=s.allOf.find(v=>v.if?.properties?.id?.const==='anti-intrusion');assert.deepEqual(g.then.required,['required_panel_features']);assert.deepEqual(g.then.properties.required_panel_features,p.required_panel_features);
});
