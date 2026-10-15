import test from 'node:test';
import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import {validateManifest,sha256} from '../tools/lib.mjs';
const read=p=>readFile(new URL('../'+p,import.meta.url));
test('host candidate is integration-only and exact two capability requirements cannot be borrowed',async()=>{
 const app=JSON.parse(await read('registry/candidates/disk-analysis-1.4.0.json'));
 assert.equal(app.stage,'integration');assert.deepEqual(validateManifest(app),[]);
 for(const kind of ['missing','inode-only','host-only','duplicate','extra','legacy','alias','short-alias','future','another-app','another-target','another-route','runtime','compose']){
  const m=structuredClone(app);
  if(kind==='missing')delete m.required_panel_features;
  else if(kind==='inode-only')m.required_panel_features=['disk-inode-usage-v1'];
  else if(kind==='host-only')m.required_panel_features=['disk-host-jobs-v1'];
  else if(kind==='duplicate')m.required_panel_features=['disk-host-jobs-v1','disk-host-jobs-v1'];
  else if(kind==='extra')m.required_panel_features.push('statistics-geodata-v2');
  else if(kind==='legacy')m.version='1.3.0';
  else if(kind==='alias')m.version='1.4.0-rc1';
  else if(kind==='short-alias')m.version='1.4';
  else if(kind==='future')m.version='1.4.1';
  else if(kind==='another-app'){m.id='daily-report';m.delivery.target=m.id}
  else if(kind==='another-target')m.delivery.target='daily-report';
  else if(kind==='another-route')m.delivery.manage_route='software';
  else m.delivery.provider=kind;
  assert(validateManifest(m).length>0,kind);
 }
 assert.equal(sha256(await read('dist/catalog-v1.json')),'fccca3c9e925e21b298d38a56c2bee9af15c6896ab514e931eb6d977aaa79ad3');
 assert.equal(sha256(await read('dist/apps/disk-analysis/1.3.0/manifest.json')),'4c971c1c079efb3b5b453d3906371284893ac6e06e5b4a4aa4359c680afd2a38');
});
