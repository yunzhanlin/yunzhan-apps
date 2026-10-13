import assert from 'node:assert/strict';
import {readFile}from'node:fs/promises';
import {test}from'node:test';
import {validateManifest}from'../tools/lib.mjs';

const registry=JSON.parse(await readFile(new URL('../registry/apps.json',import.meta.url),'utf8'));
const original=registry.apps.find(app=>app.id==='website-statistics-v2');
const feature='statistics-cursor-retirement-v1';
const candidate=()=>({...structuredClone(original),version:'2.4.1',required_panel_features:[feature]});

test('old packages remain compatible and new statistics versions require implementation',()=>{
 const legacy=structuredClone(original);legacy.version='2.4.0';delete legacy.required_panel_features;
 assert.deepEqual(validateManifest(legacy),[]);
 assert.deepEqual(validateManifest(candidate()),[]);
 for(const version of ['2.4.1','2.4.1-compat1','2.4.2','2.5.0','3.0','18446744073709551616.0']){
  const app=candidate();app.version=version;delete app.required_panel_features;
  assert.ok(validateManifest(app).length,version);
 }
});

test('requirements are bounded typed unique identifiers without runtime/compose scope',()=>{
 for(const value of [null,true,{},[],[''],['../handler'],[feature,feature],Array(9).fill(feature),['unsupported-only-v1'],[feature,'unsupported-extra-v1']]){
  const app=candidate();app.required_panel_features=value;assert.ok(validateManifest(app).length,JSON.stringify(value));
 }
 for(const provider of ['runtime','compose']){const app=candidate();app.delivery.provider=provider;assert.ok(validateManifest(app).length,provider);}
 for(const change of [{id:'daily-report'},{delivery:{provider:'panel-module',target:'daily-report'}}])assert.ok(validateManifest({...candidate(),...change}).length);
});

test('schema preserves strict legacy rejection while defining the new bounded field',async()=>{
 const schema=JSON.parse(await readFile(new URL('../schema/app.schema.json',import.meta.url),'utf8'));
 assert.equal(schema.additionalProperties,false);
 const field=schema.properties.required_panel_features;
 assert.equal(field.type,'array');assert.equal(field.minItems,1);assert.equal(field.maxItems,8);assert.equal(field.uniqueItems,true);
});

test('statistics2.5 requires both exact reviewed handlers and rejects version aliases',()=>{
 const identity='statistics-request-identity-v1';
 const app=candidate();app.version='2.5.0';
 assert(validateManifest(app).length>0);
 app.required_panel_features=[feature,identity];
 assert.deepEqual(validateManifest(app),[]);
 for(const version of ['2.5','2.5.0-compat1','2.5.1','2.6.0']){const alias={...app,version};assert(validateManifest(alias).length>0,version);}
 for(const requirements of [[identity],[identity,identity],[feature,identity,'unreviewed-v1']])assert(validateManifest({...app,required_panel_features:requirements}).length>0);
 assert(validateManifest({...app,id:'daily-report',delivery:{provider:'panel-module',target:'daily-report'}}).length>0);
});
