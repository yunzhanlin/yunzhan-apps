import test from 'node:test';
import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import {validateManifest,sha256} from '../tools/lib.mjs';
import {schemaBeforeDiskCancel} from './helpers/disk-cancel-schema.mjs';
const read=p=>readFile(new URL('../'+p,import.meta.url));
const json=async p=>JSON.parse(await read(p));
const features=['disk-inode-usage-v1','disk-host-jobs-v1','disk-host-cancel-seal-v1'];
const candidate=async()=>(await json('registry/candidate-apps.json')).apps.find(a=>a.id==='disk-analysis');

test('confirmed cancel update has a separate exact contract and preserves signed historical packages',async()=>{
 const app=await candidate();assert.equal(app.version,'1.4.1');assert.equal(app.capabilities.length,12);assert.deepEqual(app.required_panel_features,features);assert.deepEqual(validateManifest(app),[]);
 const stable=await json('dist/catalog-v1.json');assert.equal(stable.apps.length,50);assert.equal(stable.apps.find(a=>a.id==='disk-analysis').version,'1.4.0');
 assert.equal(sha256(await read('dist/apps/disk-analysis/1.4.0/manifest.json')),'0378158248d4be3a9920680131853250419bf0823336c481aa6b04bfe2293950');
 for(const version of ['1.3.0','1.4.0'])assert.deepEqual(validateManifest(await json('dist/apps/disk-analysis/'+version+'/manifest.json')),[]);
 const schema=await json('schema/app.schema.json'),scope=schema.allOf[0].then.oneOf.find(x=>x.properties.id.const==='disk-analysis'&&x.properties.version.const==='1.4.1').properties;
 const gate=schema.allOf.find(x=>x.if?.properties?.id?.const==='disk-analysis'&&x.if.properties.version.const==='1.4.1').then;
 assert.deepEqual(gate.required,['required_panel_features']);assert.deepEqual(gate.properties.required_panel_features,scope.required_panel_features);
 assert.equal(scope.required_panel_features.minItems,3);assert.equal(scope.required_panel_features.maxItems,3);assert.deepEqual(scope.required_panel_features.items.enum,features);assert.deepEqual(scope.required_panel_features.allOf.map(x=>x.contains.const),features);
 for(const name of ['provider','target','manage_route'])assert.equal(scope.delivery.properties[name].const,app.delivery[name]);
});

test('old capability sets, version aliases, borrowed targets and extra handlers cannot advertise the cancel update',async()=>{
 const app=await candidate();const changes=[
  x=>delete x.required_panel_features,
  ...features.map(feature=>x=>x.required_panel_features=x.required_panel_features.filter(f=>f!==feature)),
  x=>x.required_panel_features=[...features,features[0]],
  x=>x.required_panel_features.push('platform-maintenance-v1'),
  ...['1.4','1.4.0','1.4.01','1.4.1.0','1.4.1-rc1','1.4.2','1.5.0'].map(version=>x=>x.version=version),
  x=>{x.id='daily-report';x.delivery.target=x.id;},
  x=>x.delivery.target='daily-report',x=>x.delivery.manage_route='software',
  ...['runtime','compose'].map(provider=>x=>x.delivery.provider=provider),
  x=>x.capabilities.push('unreviewed extra capability')
 ];
 for(const change of changes){const bad=structuredClone(app);change(bad);assert(validateManifest(bad).length,JSON.stringify(bad));}
 const legacy=await json('dist/apps/disk-analysis/1.4.0/manifest.json');legacy.version='1.4.1';assert(validateManifest(legacy).length,'changing only the label must not grant the new handler');
});

test('historical schema verification refuses unrelated edits, weakened new scopes and missing or duplicate guards',async()=>{
 const raw=await read('schema/app.schema.json');assert.equal(schemaBeforeDiskCancel(raw).properties.required_panel_features.items.enum.includes('disk-host-cancel-seal-v1'),false);
 const changes=[x=>x.additionalProperties=true,x=>x.properties.required_panel_features.uniqueItems=false,x=>x.properties.required_panel_features.items.enum.push('borrowed-handler'),x=>x.allOf.pop(),x=>x.allOf.push(x.allOf.find(g=>g.if?.properties?.version?.const==='1.4.1')),x=>{x.allOf[0].then.oneOf.find(g=>g.properties?.version?.const==='1.4.1').properties.delivery.properties.target.const='daily-report';},x=>{x.allOf.find(g=>g.if?.properties?.version?.const==='1.4.1').then.required=[];}];
 for(const change of changes){const bad=JSON.parse(raw);change(bad);assert.throws(()=>schemaBeforeDiskCancel(JSON.stringify(bad)));}
});
