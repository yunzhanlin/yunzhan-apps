import {readFileSync} from 'node:fs';
import assert from 'node:assert/strict';
import test from 'node:test';
import {validateManifest} from '../tools/lib.mjs';
const read=p=>JSON.parse(readFileSync(new URL('../'+p,import.meta.url),'utf8'));
test('fleet check belongs only to platform-ops 1.3.1 and preserves the published 1.3.0 manifest',()=>{
 const old=read('candidate/dist/apps/platform-ops/1.3.0/manifest.json');
 const next=read('candidate/dist/apps/platform-ops/1.3.1/manifest.json');
 assert.deepEqual(validateManifest(old),[]);
 assert.deepEqual(validateManifest(next),[]);
 assert.deepEqual(next.required_panel_features,['platform-maintenance-v1','platform-maintenance-fleet-check-v1']);
 for(const version of ['1.3.0','1.3.1-compat1','1.3.2'])assert(validateManifest({...next,version}).length);
});
