import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import {validateManifest} from '../tools/lib.mjs';
import {schemaBeforeMobileNative133}from './helpers/mobile-native133-schema.mjs';
import {schemaBeforePM2Maintenance}from './helpers/pm2-maintenance-schema.mjs';
const root=new URL('../',import.meta.url);
const apps=JSON.parse(fs.readFileSync(new URL('registry/candidate-apps.json',root))).apps;
const current=apps.find(a=>a.id==='mobile');
test('only the exact native133 handler can describe current133 while original132 and legacy manifests remain valid',()=>{
 assert.equal(current.version,'1.3.3');assert.deepEqual(current.required_panel_features,['mobile-native-delivery-v133']);assert.deepEqual(validateManifest(current),[]);
 const old=JSON.parse(fs.readFileSync(new URL('candidate/dist/apps/mobile/1.3.2/manifest.json',root)));
 assert.deepEqual(validateManifest(old),[]);assert.deepEqual(old.required_panel_features,['mobile-native-delivery-v132']);
 for(const [version,feature]of [['1.3.2','mobile-native-delivery-v133'],['1.3.3','mobile-native-delivery-v132'],['1.3.4','mobile-native-delivery-v133'],['1.3.3-compat1','mobile-native-delivery-v133'],['01.3.3','mobile-native-delivery-v133']]){
  const app=structuredClone(current);app.version=version;app.required_panel_features=[feature];assert(validateManifest(app).length>0,version+':'+feature);
 }
 for(const mutate of [a=>delete a.required_panel_features,a=>a.required_panel_features=[],a=>a.required_panel_features=['mobile-native-delivery-v133','mobile-native-delivery-v133'],a=>a.required_panel_features=['mobile-native-delivery-v132','mobile-native-delivery-v133'],a=>a.id='daily-report',a=>a.delivery.target='daily-report',a=>a.delivery.provider='runtime',a=>a.delivery.manage_route='security',a=>delete a.delivery.manage_route]){
  const app=structuredClone(current);mutate(app);assert(validateManifest(app).length>0);
 }
});
test('schema preserves every original132 guard and adds only its separate exact133 branch',()=>{
 const schema=schemaBeforePM2Maintenance(JSON.parse(fs.readFileSync(new URL('schema/app.schema.json',root)))),old=JSON.parse(fs.readFileSync(new URL('registry/reviewed-catalogs/before-mobile-native133-c68r3/schema/app.schema.json',root)));
 const guard=schema.allOf[1],previous=old.allOf[1];assert.deepEqual(guard.then.oneOf.slice(0,2),previous.then.oneOf);assert.deepEqual(guard.if.anyOf.slice(0,3),previous.if.anyOf);
 assert.equal(guard.then.oneOf.length,3);assert.equal(guard.if.anyOf.length,4);assert.equal(guard.then.oneOf[2].properties.version.const,'1.3.3');assert.equal(guard.then.oneOf[2].properties.required_panel_features.items.const,'mobile-native-delivery-v133');
 const original=schema.allOf[0].then.oneOf.filter(v=>v.properties.id.const==='mobile');assert.equal(original.length,2);assert.deepEqual(original[0],old.allOf[0].then.oneOf.find(v=>v.properties.id.const==='mobile'));
 assert.deepEqual(schema.properties.required_panel_features.items.enum.filter(s=>s!=='mobile-native-delivery-v133'),old.properties.required_panel_features.items.enum);
});

test('mobile133 historical projection preserves complete original schema and immutable input',()=>{
 const current=JSON.parse(fs.readFileSync(new URL('schema/app.schema.json',root))),before=JSON.stringify(current),old=JSON.parse(fs.readFileSync(new URL('registry/reviewed-catalogs/before-mobile-native133-c68r3/schema/app.schema.json',root)));
 assert.deepEqual(schemaBeforeMobileNative133(current),old);assert.equal(JSON.stringify(current),before);assert.deepEqual(schemaBeforeMobileNative133(old),old);
});
for(const kind of ['missing-feature','duplicate-feature','wrong-position','missing-branch','changed-branch','missing-guard-condition','missing-guard-branch','weakened-132-guard','unrelated'])test('mobile133 projection refuses '+kind,()=>{
 const s=JSON.parse(fs.readFileSync(new URL('schema/app.schema.json',root))),flags=s.properties.required_panel_features.items.enum;
 if(kind==='missing-feature')flags.splice(14,1);if(kind==='duplicate-feature')flags.push('mobile-native-delivery-v133');if(kind==='wrong-position'){flags.splice(14,1);flags.push('mobile-native-delivery-v133');}
 if(kind==='missing-branch')s.allOf[0].then.oneOf.splice(11,1);if(kind==='changed-branch')s.allOf[0].then.oneOf[11].properties.version.const='1.3.4';if(kind==='missing-guard-condition')s.allOf[1].if.anyOf.pop();if(kind==='missing-guard-branch')s.allOf[1].then.oneOf.pop();if(kind==='weakened-132-guard')s.allOf[1].then.oneOf[1].required.pop();if(kind==='unrelated')s.title='unreviewed';
 assert.throws(()=>schemaBeforeMobileNative133(s));
});
