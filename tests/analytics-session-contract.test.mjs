import test from 'node:test';
import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import {createHash} from 'node:crypto';
import {validateManifest} from '../tools/lib.mjs';
const read=p=>readFile(new URL('../'+p,import.meta.url));
const feature='analytics-session-lifecycle-v1';
async function fixture(){
 const raw=await read('dist/apps/website-analytics/2.3.0/manifest.json');
 assert.equal(createHash('sha256').update(raw).digest('hex'),'4953ee9526b5e5b189f59eed5731d2ca40f3b76c715319e215b0f3fe3a9f1ec8');
 return {...JSON.parse(raw),version:'2.3.1',required_panel_features:[feature]};
}
test('the exact analytics session revision requires its actual independently compiled handler',async()=>{
 const m=await fixture();assert.deepEqual(validateManifest(m),[]);
 for(const change of [
  x=>delete x.required_panel_features,x=>x.required_panel_features=[],
  x=>x.required_panel_features=[feature,feature],x=>x.required_panel_features=[feature,'statistics-geodata-v2'],
  x=>x.required_panel_features=['statistics-geodata-v2'],x=>x.version='2.3.1-compat1',
  x=>x.version='02.3.1',x=>x.version='2.3.2',x=>x.version='2.4.0',x=>x.version='2.3.0',
  x=>x.id='daily-report',x=>x.delivery.provider='runtime',x=>x.delivery.provider='compose',
  x=>x.delivery.target='website-statistics-v2',x=>x.delivery.manage_route='security'
 ]){const bad=structuredClone(m);change(bad);assert(validateManifest(bad).length,JSON.stringify(bad));}
 for(const version of ['2.3.2','2.4.0','18446744073709551616.0.0']){const bad=structuredClone(m);bad.version=version;delete bad.required_panel_features;assert(validateManifest(bad).length,version);}
});
test('the actual immutable2.3.0 manifest remains compatible without claiming the new handler',async()=>{
 const old=JSON.parse(await read('dist/apps/website-analytics/2.3.0/manifest.json'));
 assert.equal(old.version,'2.3.0');assert(!Object.hasOwn(old,'required_panel_features'));assert.deepEqual(validateManifest(old),[]);
});
test('schema independently closes the new session feature scope and requires it for2.3.1',async()=>{
 const s=JSON.parse(await read('schema/app.schema.json'));
 assert(s.properties.required_panel_features.items.enum.includes(feature));
 const scope=s.allOf[0].then.oneOf.find(x=>x.properties.id.const==='website-analytics').properties;
 assert.equal(scope.version.const,'2.3.1');
 for(const [name,value]of Object.entries({provider:'panel-module',target:'website-analytics',manage_route:'app-modules'}))assert.equal(scope.delivery.properties[name].const,value);
 assert.deepEqual(scope.required_panel_features,{minItems:1,maxItems:1,items:{const:feature}});
 const guard=s.allOf.find(x=>x.if?.properties?.id?.const==='website-analytics'&&x.if.properties.version.const==='2.3.1').then;
 assert.deepEqual(guard.required,['required_panel_features']);assert.deepEqual(guard.properties.required_panel_features,scope.required_panel_features);
});
