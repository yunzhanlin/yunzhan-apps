import{historicalMemcachedUnixSchemaURL}from'./reviewed-memcached-unix-inputs.mjs';
import test from'node:test';import assert from'node:assert/strict';import{readFile}from'node:fs/promises';import{validateManifest}from'../tools/lib.mjs';
const original=JSON.parse(await readFile(new URL('../dist/apps/memcached/1.6.45-compat1/manifest.json',import.meta.url),'utf8'));
const feature='compose-memcached-digest-v1',image='memcached:1.6.45-alpine@sha256:9e4de012dc607573052061c0bcb38abc775e1dd59b24e7ac38d1892842094aaf';
const candidate=()=>({...structuredClone(original),version:'1.6.45-compat2',required_panel_features:[feature],delivery:{...original.delivery,image}});
test('only original compat1 and exact pinned compat2 retain the reviewed Compose ABI',()=>{
 assert.deepEqual(validateManifest(original),[]);assert.deepEqual(validateManifest(candidate()),[]);
 for(const version of ['1.6.45','1.6.45-compat02','1.6.45-compat2.0','1.6.45-compat3','1.6.46-compat1','2.0'])assert(validateManifest({...candidate(),version}).length,version);
});
test('a feature or provider alias never widens the pinned Memcached exemption',()=>{
 for(const change of [{id:'redis'},{version:'1.6.45-compat1'},{delivery:{...candidate().delivery,provider:'runtime'}},{delivery:{...candidate().delivery,provider:'panel-module'}},{delivery:{...candidate().delivery,target:'mongodb'}},{delivery:{...candidate().delivery,manage_route:'terminal'}},{delivery:{...candidate().delivery,isolation:'legacy-container'}},{delivery:{...candidate().delivery,image:'memcached:latest'}},{delivery:{...candidate().delivery,image:image.replace(/.$/,'0')}},{required_panel_features:undefined},{required_panel_features:[feature,feature]},{required_panel_features:[feature,'disk-host-jobs-v1']}])assert(validateManifest({...candidate(),...change}).length,JSON.stringify(change));
 const missing=candidate();delete missing.required_panel_features;assert(validateManifest(missing).length);
});
test('schema keeps the exact Memcached branch separate from every module and generic Compose app',async()=>{
 const schema=JSON.parse(await readFile(historicalMemcachedUnixSchemaURL(import.meta.url),'utf8'));assert.equal(schema.additionalProperties,false);
 const branches=schema.allOf[0].then.oneOf.filter(x=>x.properties.id.const==='memcached');assert.equal(branches.length,1);const p=branches[0].properties;assert.equal(p.version.const,'1.6.45-compat2');assert.equal(p.delivery.properties.provider.const,'compose');assert.equal(p.delivery.properties.image.const,image);assert.equal(p.required_panel_features.maxItems,1);assert(schema.allOf.some(x=>x.if?.properties?.id?.const==='memcached'&&x.then.required.includes('required_panel_features')));
});
