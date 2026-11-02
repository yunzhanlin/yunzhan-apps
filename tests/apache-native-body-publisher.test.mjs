import test from 'node:test';
import assert from 'node:assert/strict';
import {readFile,readdir} from 'node:fs/promises';
import {validateManifest} from '../tools/lib.mjs';
import {apacheNativeBodyErrors,apacheNativeBodyFeature,apacheLegacyVersions} from '../tools/apache-native-body-contract.mjs';
import {apacheNativeBodyCases} from '../tools/apache-native-body-fixtures.mjs';
const root=new URL('../',import.meta.url),read=async n=>JSON.parse(await readFile(new URL(n,root),'utf8'));
test('Apache native publication requires one exact independent handler and rejects identity/version borrowing',async()=>{
  const base=(await read('registry/apps.json')).apps.find(a=>a.id==='apache-waf');
  for(const c of apacheNativeBodyCases(base))assert.equal(validateManifest(c.manifest).length===0,c.valid,c.name);
  assert.equal(apacheNativeBodyErrors({id:'ordinary',version:'2.4.0',delivery:{target:'ordinary'}}),null);
});
test('Apache published historical packages remain readable without silently acquiring body capability',async()=>{
  const versions=(await readdir(new URL('dist/apps/apache-waf/',root))).sort();assert.deepEqual(versions,[...apacheLegacyVersions].sort());
  for(const version of versions){const app=await read(`dist/apps/apache-waf/${version}/manifest.json`);assert.deepEqual(validateManifest(app),[],version);assert(!Object.hasOwn(app,'required_panel_features'));}
});
test('Both publication schemas bind Apache legacy/native identities and the fixed compiled capability',async()=>{
  for(const file of ['schema/app.schema.json','candidate/schema/app.schema.json']){
    const schema=await read(file);assert(schema.properties.required_panel_features.items.enum.includes(apacheNativeBodyFeature));
    const guard=schema.allOf.find(c=>c.if?.anyOf?.some(x=>x.properties?.required_panel_features?.contains?.const===apacheNativeBodyFeature));assert(guard,file);assert.equal(guard.then.oneOf.length,3);
    const [legacy,native]=guard.then.oneOf;assert.deepEqual(legacy.properties.version.enum,apacheLegacyVersions);assert.equal(native.properties.version.const,'2.4.0');assert.deepEqual(native.properties.required_panel_features,{minItems:1,maxItems:1,items:{const:apacheNativeBodyFeature}});
    assert(schema.allOf.some(c=>c.if?.required?.includes('required_panel_features')&&c.then?.oneOf?.some(branch=>JSON.stringify(branch)===JSON.stringify(native))),'native capability must also be registered in the shared required-feature admission guard');
    for(const branch of [legacy,native]){assert.equal(branch.properties.id.const,'apache-waf');assert.equal(branch.properties.delivery.additionalProperties,false);assert.deepEqual(branch.properties.delivery.required,['provider','target','manage_route']);}
  }
});
