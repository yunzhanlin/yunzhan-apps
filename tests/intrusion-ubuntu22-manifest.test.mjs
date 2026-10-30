import test from 'node:test';import assert from 'node:assert/strict';import fs from 'node:fs';import {validateManifest} from '../tools/lib.mjs';
import{schemaBeforeIntrusionUbuntu22}from'./helpers/intrusion-ubuntu22-schema.mjs';
import{intrusionUbuntu22Cases}from'../tools/intrusion-ubuntu22-fixtures.mjs';import{fileURLToPath}from'node:url';
const old=JSON.parse(fs.readFileSync(new URL('../dist/apps/anti-intrusion/1.1.0/manifest.json',import.meta.url))),journal='intrusion-preserving-journal-v2',compat='intrusion-upstream0112-v1';
const candidate=()=>({...structuredClone(old),version:'1.1.1',required_panel_features:[journal,compat]});
test('111 requires both exact fixed handlers and preserves the original110 declaration',()=>{
 assert.deepEqual(validateManifest(old),[]);assert.deepEqual(validateManifest(candidate()),[]);
 for(const change of [{version:'1.1.0'},{version:'1.1.1-alias'},{version:'1.1.2'},{version:'01.1.1'},{id:'system-hardening'},{id:'intrusion-prevention'},{required_panel_features:[]},{required_panel_features:[journal]},{required_panel_features:[compat]},{required_panel_features:[compat,journal]},{required_panel_features:[journal,compat,compat]},{required_panel_features:[journal,compat,'hardening-reversible-journal-v1']},{delivery:{provider:'runtime',target:'intrusion-prevention',manage_route:'security'}},{delivery:{provider:'panel-module',target:'anti-intrusion',manage_route:'security'}},{delivery:{provider:'panel-module',target:'intrusion-prevention',manage_route:'app-modules'}}])assert(validateManifest({...candidate(),...change}).length,JSON.stringify(change));
 const missing=candidate();delete missing.required_panel_features;assert(validateManifest(missing).length);
});
test('actual signed candidate fifty and all exact negative111 cases agree with the publisher',()=>{
 const cases=intrusionUbuntu22Cases(fileURLToPath(new URL('../',import.meta.url)));assert.equal(cases.length,80);assert.equal(cases.filter(c=>!c.valid).length,29);
 for(const c of cases)assert.equal(validateManifest(c.manifest).length===0,c.valid,c.name);
});
test('schema independently fixes ordered111 handlers without weakening the old110 branch',()=>{
 const s=JSON.parse(fs.readFileSync(new URL('../schema/app.schema.json',import.meta.url)));
 assert(s.properties.required_panel_features.items.enum.includes(compat));
 const branches=s.allOf[0].then.oneOf.filter(v=>v.properties.id.const==='anti-intrusion');assert.equal(branches.length,2);
 const p=branches.find(v=>v.properties.version.const==='1.1.1').properties;
 assert.deepEqual(p.delivery,branches.find(v=>v.properties.version.const==='1.1.0').properties.delivery);
 assert.deepEqual(p.required_panel_features,{minItems:2,maxItems:2,prefixItems:[{const:journal},{const:compat}],items:false});
 const g=s.allOf.find(v=>v.if?.properties?.id?.const==='anti-intrusion'&&v.if.properties.version.const==='1.1.1');assert.deepEqual(g.then.required,['required_panel_features']);assert.deepEqual(g.then.properties.required_panel_features,p.required_panel_features);
});
test('historical projection rejects a weakened111 extension and any unrelated schema change',()=>{
 const raw=JSON.parse(fs.readFileSync(new URL('../schema/app.schema.json',import.meta.url))),original=structuredClone(raw);
 schemaBeforeIntrusionUbuntu22(raw);assert.deepEqual(raw,original);
 for(const change of [s=>s.additionalProperties=true,s=>s.properties.required_panel_features.uniqueItems=false,s=>s.allOf.pop(),s=>s.allOf.push(s.allOf.at(-1)),s=>s.allOf[0].then.oneOf.at(-1).properties.delivery.properties.target.const='daily-report',s=>s.allOf[0].then.oneOf.at(-1).properties.required_panel_features.items=true,s=>s.allOf.at(-1).then.required=[],s=>s.properties.required_panel_features.items.enum.push('unknown-handler')]){
  const bad=structuredClone(raw);change(bad);assert.throws(()=>schemaBeforeIntrusionUbuntu22(bad));
 }
});
