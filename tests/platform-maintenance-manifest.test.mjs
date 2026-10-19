import test from 'node:test';
import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import {createHash} from 'node:crypto';
import {validateManifest} from '../tools/lib.mjs';
const read=p=>readFile(new URL('../'+p,import.meta.url),'utf8');
const original=JSON.parse(await read('registry/candidates/platform-ops-1.3.0.json'));
test('original maintenance candidate and historical signed1.2 package stay immutable after independent1.3 publication',async()=>{
 assert.deepEqual(validateManifest(original),[]);assert.equal(original.stage,'integration');assert.deepEqual(original.required_panel_features,['platform-maintenance-v1']);
 const catalogue=JSON.parse(await read('registry/reviewed-catalogs/20261013-201440/catalog-v1.json'));const app=catalogue.apps.find(x=>x.id==='platform-ops');assert.equal(app.version,'1.2.0');
 assert.equal(createHash('sha256').update(await read('dist/apps/platform-ops/1.2.0/manifest.json')).digest('hex'),app.sha256);
});
test('new maintenance manifests cannot omit, borrow, alias or widen handler authority',()=>{
 const missing=structuredClone(original);delete missing.required_panel_features;assert(validateManifest(missing).length);
 for(const patch of [{version:'1.3'},{version:'1.3.0-compat1'},{version:'1.4.0'},{version:'01.3.0'},{version:'1.2.0'},{id:'daily-report'},{delivery:{provider:'runtime',target:'platform-ops'}},{delivery:{provider:'panel-module',target:'daily-report'}},{required_panel_features:['statistics-request-identity-v1']},{required_panel_features:['platform-maintenance-v1','platform-maintenance-v1']},{required_panel_features:['platform-maintenance-v1','statistics-request-identity-v1']},{required_panel_features:['platform-maintenance-v2']}])assert(validateManifest({...structuredClone(original),...patch}).length,JSON.stringify(patch));
 const legacy={...structuredClone(original),version:'1.2.0'};delete legacy.required_panel_features;assert.deepEqual(validateManifest(legacy),[]);
});
test('schema keeps original module scopes and one separate exact pinned Memcached scope',async()=>{
 const schema=JSON.parse(await read('schema/app.schema.json'));assert.equal(schema.additionalProperties,false);
 const allScopes=schema.allOf.find(x=>x.if?.required?.includes('required_panel_features')).then.oneOf;
 const sessionScopes=allScopes.filter(x=>x.properties.id.const==='website-analytics');assert.equal(sessionScopes.length,1);
 const session=sessionScopes[0].properties;assert.equal(session.version.const,'2.3.1');assert.equal(session.delivery.properties.provider.const,'panel-module');assert.equal(session.delivery.properties.target.const,'website-analytics');assert.equal(session.delivery.properties.manage_route.const,'app-modules');assert.deepEqual(session.required_panel_features,{minItems:1,maxItems:1,items:{const:'analytics-session-lifecycle-v1'}});
 // Preserve all five original authority scopes and their exact assertions.
 const scope=allScopes.filter(x=>!['website-analytics','system-hardening'].includes(x.properties.id.const));assert.equal(scope.length,5);assert.equal(allScopes.length,7);
 assert.equal(allScopes.filter(x=>x.properties.id.const==='system-hardening').length,1);
 assert.deepEqual(scope.filter(x=>x.properties.id.const!=='memcached').map(x=>x.properties.id.const).sort(),['disk-analysis','disk-analysis','platform-ops','website-statistics-v2']);
 const mc=scope.find(x=>x.properties.id.const==='memcached').properties;assert.equal(mc.version.const,'1.6.45-compat2');assert.equal(mc.delivery.properties.provider.const,'compose');assert.equal(mc.delivery.properties.target.const,'memcached-cache');assert.equal(mc.required_panel_features.maxItems,1);assert.equal(mc.required_panel_features.items.const,'compose-memcached-digest-v1');
 const stats=scope.find(x=>x.properties.id.const==='website-statistics-v2'),maintenance=scope.find(x=>x.properties.id.const==='platform-ops');
 assert(!stats.properties.required_panel_features.items.enum.includes('platform-maintenance-v1'));assert.equal(maintenance.properties.version.const,'1.3.0');assert.equal(maintenance.properties.required_panel_features.maxItems,1);assert.equal(maintenance.properties.required_panel_features.items.const,'platform-maintenance-v1');assert.equal(maintenance.properties.delivery.properties.target.const,'platform-ops');
 const disk=scope.find(x=>x.properties.id.const==='disk-analysis');assert.equal(disk.properties.version.const,'1.3.0');assert.equal(disk.properties.required_panel_features.maxItems,1);assert.equal(disk.properties.required_panel_features.items.const,'disk-inode-usage-v1');assert.equal(disk.properties.delivery.properties.target.const,'disk-analysis');assert.equal(disk.properties.delivery.properties.manage_route.const,'app-modules');assert(!stats.properties.required_panel_features.items.enum.includes('disk-inode-usage-v1'));
 const host=scope.find(x=>x.properties.id.const==='disk-analysis'&&x.properties.version.const==='1.4.0').properties;assert.equal(host.required_panel_features.minItems,2);assert.equal(host.required_panel_features.maxItems,2);assert.deepEqual(host.required_panel_features.items.enum,['disk-inode-usage-v1','disk-host-jobs-v1']);assert.deepEqual(host.required_panel_features.allOf.map(x=>x.contains.const),host.required_panel_features.items.enum);assert.equal(host.delivery.properties.provider.const,'panel-module');assert.equal(host.delivery.properties.target.const,'disk-analysis');assert.equal(host.delivery.properties.manage_route.const,'app-modules');assert(!stats.properties.required_panel_features.items.enum.includes('disk-host-jobs-v1'));assert.equal(maintenance.properties.required_panel_features.items.const,'platform-maintenance-v1');
});
