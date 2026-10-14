import test from 'node:test';
import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import {createHash} from 'node:crypto';
import {validateManifest} from '../tools/lib.mjs';
const read=p=>readFile(new URL('../'+p,import.meta.url),'utf8');
const original=JSON.parse(await read('registry/candidates/platform-ops-1.3.0.json'));
test('maintenance candidate keeps independent handler requirement out of official signed catalogue',async()=>{
 assert.deepEqual(validateManifest(original),[]);assert.equal(original.stage,'integration');assert.deepEqual(original.required_panel_features,['platform-maintenance-v1']);
 const catalogue=JSON.parse(await read('dist/catalog-v1.json'));const app=catalogue.apps.find(x=>x.id==='platform-ops');assert.equal(app.version,'1.2.0');
 assert.equal(createHash('sha256').update(await read('dist/apps/platform-ops/1.2.0/manifest.json')).digest('hex'),app.sha256);
});
test('new maintenance manifests cannot omit, borrow, alias or widen handler authority',()=>{
 const missing=structuredClone(original);delete missing.required_panel_features;assert(validateManifest(missing).length);
 for(const patch of [{version:'1.3'},{version:'1.3.0-compat1'},{version:'1.4.0'},{version:'01.3.0'},{version:'1.2.0'},{id:'daily-report'},{delivery:{provider:'runtime',target:'platform-ops'}},{delivery:{provider:'panel-module',target:'daily-report'}},{required_panel_features:['statistics-request-identity-v1']},{required_panel_features:['platform-maintenance-v1','platform-maintenance-v1']},{required_panel_features:['platform-maintenance-v1','statistics-request-identity-v1']},{required_panel_features:['platform-maintenance-v2']}])assert(validateManifest({...structuredClone(original),...patch}).length,JSON.stringify(patch));
 const legacy={...structuredClone(original),version:'1.2.0'};delete legacy.required_panel_features;assert.deepEqual(validateManifest(legacy),[]);
});
test('schema has separate closed statistics and maintenance scopes rather than globally trusting a feature label',async()=>{
 const schema=JSON.parse(await read('schema/app.schema.json'));assert.equal(schema.additionalProperties,false);
 const scope=schema.allOf.find(x=>x.if?.required?.includes('required_panel_features')).then.oneOf;assert.equal(scope.length,2);
 const stats=scope.find(x=>x.properties.id.const==='website-statistics-v2'),maintenance=scope.find(x=>x.properties.id.const==='platform-ops');
 assert(!stats.properties.required_panel_features.items.enum.includes('platform-maintenance-v1'));assert.equal(maintenance.properties.version.const,'1.3.0');assert.equal(maintenance.properties.required_panel_features.maxItems,1);assert.equal(maintenance.properties.required_panel_features.items.const,'platform-maintenance-v1');assert.equal(maintenance.properties.delivery.properties.target.const,'platform-ops');
});
