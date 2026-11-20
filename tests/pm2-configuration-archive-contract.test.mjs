import fs from 'node:fs';import path from 'node:path';import assert from 'node:assert/strict';import test from 'node:test';
import {canonical,sha256,validateManifest}from'../tools/lib.mjs';import{schemaBeforePM2ConfigurationArchive}from'./helpers/pm2-configuration-archive-schema.mjs';
const root=path.resolve(import.meta.dirname,'..'),source=JSON.parse(fs.readFileSync(path.join(root,'registry/candidate-apps.json'))),good=source.apps.find(a=>a.id==='pm2-manager');
test('instance-bound PM2 configuration archive has exact compat12 authority and preserves previous app manifests',()=>{
 assert.equal(good.version,'7.0.4-compat12');assert.deepEqual(validateManifest(good),[]);
 const changes=[v=>v.version='7.0.4-compat11',v=>v.version='7.0.4-compat12.0',v=>v.version='7.0.4-compat13',v=>v.id='other',v=>v.delivery.target='other',v=>v.delivery.provider='runtime',v=>v.delivery.manage_route='security',v=>v.required_panel_features=[],v=>v.required_panel_features.push('pm2-root-vendor-v1'),v=>v.required_panel_features.push('pm2-configuration-archive-v1')];
 for(const change of changes){const v=structuredClone(good);change(v);assert(validateManifest(v).length>0);}
 for(const version of ['7.0.4-compat10','7.0.4-compat11'])assert.deepEqual(validateManifest(JSON.parse(fs.readFileSync(path.join(root,'candidate/dist/apps/pm2-manager',version,'manifest.json')))),[]);
});
test('archive schema preserves every old predicate and refuses damaged archive and legacy exceptions',()=>{
 const current=JSON.parse(fs.readFileSync(path.join(root,'schema/app.schema.json')));assert.equal(sha256(canonical(schemaBeforePM2ConfigurationArchive(current))),"d84732a1b661b1e378b7eef009d126ed9ab70b11561692ccfb64cd7ddb1030d4");
 for(const change of [s=>s.allOf.pop(),s=>s.properties.required_panel_features.items.enum.push('pm2-configuration-archive-v1'),s=>s.allOf[36].if.allOf[1].not.anyOf[0].properties.version.const='7.0.4-compat12',s=>s.allOf[0].then.oneOf.at(-1).properties.version.const='7.0.4-compat13',s=>s.properties.name.maxLength=999]){const v=structuredClone(current);change(v);assert.throws(()=>schemaBeforePM2ConfigurationArchive(v));}
});
