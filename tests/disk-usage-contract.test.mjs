// Candidate validation only. No app version or runtime acceptance is invented.
import test from 'node:test';
import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import {validateManifest} from '../tools/lib.mjs';
const read=p=>readFile(new URL('../'+p,import.meta.url),'utf8');
test('inode usage candidate requires exact new handler while old published1.2 remains unchanged',async()=>{
 const m=JSON.parse(await read('registry/candidates/disk-analysis-1.3.0.json'));assert.equal(m.stage,'integration');assert.deepEqual(validateManifest(m),[]);
 for(const change of [{required_panel_features:undefined},{required_panel_features:[]},{required_panel_features:['disk-inode-usage-v1','disk-inode-usage-v1']},{required_panel_features:['platform-maintenance-v1']},{version:'1.3.0-compat1'},{version:'1.4.0'},{version:'1.2.0'},{id:'daily-report'},{delivery:{...m.delivery,target:'daily-report'}},{delivery:{...m.delivery,provider:'runtime'}},{delivery:{...m.delivery,manage_route:'software'}}]){
  const bad={...m,...change};if(Object.hasOwn(change,'required_panel_features')&&change.required_panel_features===undefined)delete bad.required_panel_features;assert(validateManifest(bad).length,JSON.stringify(change));
 }
 const old=JSON.parse(await read('dist/apps/disk-analysis/1.2.0/manifest.json'));assert.deepEqual(validateManifest(old),[]);
 const published=JSON.parse(await read('dist/apps/disk-analysis/1.3.0/manifest.json'));assert.equal(published.stage,'ready');assert.deepEqual(validateManifest(published),[]);assert.deepEqual(published.required_panel_features,['disk-inode-usage-v1']);assert.match(published.summary,/不含全盘分析/);assert.match(published.summary,/商用.*仍在验收/);assert.equal(JSON.parse(await read('dist/catalog-v1.json')).apps.find(a=>a.id==='disk-analysis').version,'1.3.0');
 const schema=JSON.parse(await read('schema/app.schema.json'));assert(schema.properties.required_panel_features.items.enum.includes('disk-inode-usage-v1'));
 const gate=schema.allOf.find(c=>c.if?.properties?.id?.const==='disk-analysis');assert.deepEqual(gate.then.required,['required_panel_features']);assert.equal(gate.then.properties.required_panel_features.items.const,'disk-inode-usage-v1');
});
