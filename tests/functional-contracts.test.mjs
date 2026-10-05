import test from 'node:test';
import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
const load=async name=>JSON.parse(await readFile(new URL(name,import.meta.url),'utf8'));
test('all 50 applications have business scenarios, not install-only acceptance',async()=>{
 const [registry,contracts]=await Promise.all([load('../registry/apps.json'),load('../registry/functional-contracts.json')]);
 assert.equal(contracts.commercial_feature_parity_complete,false);
 assert.equal(contracts.apps.length,50);
 assert.deepEqual(contracts.apps.map(a=>a.id).sort(),registry.apps.map(a=>a.id).sort());
 for(const app of contracts.apps){assert.ok(app.scenarios.length>=3,app.id);assert.ok(app.scenarios.every(s=>s.length>=4),app.id)}
 for(const id of ['website-analytics','files-sync','php-code-security','enterprise-tamper-proof'])assert.ok(contracts.apps.find(a=>a.id===id).gaps.length>0,id);
});
test('published manifest OS values are permitted by the schema',async()=>{
 const [registry,schema]=await Promise.all([load('../registry/apps.json'),load('../schema/app.schema.json')]);
 const systems=schema.properties.compatibility.properties.os.items.enum;
 for(const app of registry.apps)for(const os of app.compatibility.os)assert.ok(systems.includes(os),app.id+' '+os);
});
