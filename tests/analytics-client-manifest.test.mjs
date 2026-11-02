import test from'node:test';
import assert from'node:assert/strict';
import{readFileSync}from'node:fs';
import{validateManifest}from'../tools/lib.mjs';

const previous=()=>JSON.parse(readFileSync(new URL('../dist/apps/website-analytics/2.3.1/manifest.json',import.meta.url)));
const session='analytics-session-lifecycle-v1',address='analytics-managed-client-address-v1';
const candidate=()=>({...previous(),version:'2.3.2',required_panel_features:[session,address]});

test('analytics232 publisher keeps exact legacy session packages and requires both current handlers',()=>{
 assert.deepEqual(validateManifest(previous()),[]);
 const legacy={...previous(),version:'2.3.0'};delete legacy.required_panel_features;assert.deepEqual(validateManifest(legacy),[]);
 assert.deepEqual(validateManifest(candidate()),[]);
 assert.deepEqual(validateManifest({...candidate(),required_panel_features:[address,session]}),[]);
 for(const scenario of['missing','empty','duplicate','extra','session-only','address-only','alias','build-alias','future','foreign','target','route','provider']){
  const m=candidate();
  if(scenario==='missing')delete m.required_panel_features;
  else if(scenario==='empty')m.required_panel_features=[];
  else if(scenario==='duplicate')m.required_panel_features=[address,address];
  else if(scenario==='extra')m.required_panel_features.push('statistics-geodata-v2');
  else if(scenario==='session-only')m.required_panel_features=[session];
  else if(scenario==='address-only')m.required_panel_features=[address];
  else if(scenario==='alias')m.version='2.3.2-compat1';
  else if(scenario==='build-alias')m.version='2.3.2+build';
  else if(scenario==='future')m.version='2.3.3';
  else if(scenario==='foreign'){m.id='daily-report';m.delivery={...m.delivery,target:m.id};}
  else if(scenario==='target')m.delivery={...m.delivery,target:'website-statistics-v2'};
  else if(scenario==='route')m.delivery={...m.delivery,manage_route:'security'};
  else if(scenario==='provider')m.delivery={...m.delivery,provider:'runtime'};
  assert(validateManifest(m).length,scenario);
 }
});

test('analytics232 JSON schema preserves231 and declares exact two-feature scope',()=>{
 const schema=JSON.parse(readFileSync(new URL('../schema/app.schema.json',import.meta.url)));
 assert(schema.properties.required_panel_features.items.enum.includes(address));
 const alternatives=schema.allOf[0].then.oneOf.filter(v=>v.properties?.id?.const==='website-analytics');
 assert.equal(alternatives.length,2);
 const old=alternatives.find(v=>v.properties.version.const==='2.3.1').properties;
 assert.deepEqual(old.required_panel_features,{minItems:1,maxItems:1,items:{const:session}});
 const current=alternatives.find(v=>v.properties.version.const==='2.3.2').properties;
 assert.deepEqual(current.required_panel_features,{minItems:2,maxItems:2,items:{enum:[session,address]}});
 const exact=schema.allOf.find(v=>v.if?.properties?.id?.const==='website-analytics'&&v.if.properties.version?.const==='2.3.2');
 assert.deepEqual(exact.then.required,['required_panel_features']);
 assert.deepEqual(exact.then.properties.required_panel_features,current.required_panel_features);
 assert.equal(schema.properties.required_panel_features.uniqueItems,true);
});
