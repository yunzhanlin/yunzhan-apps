import test from'node:test';import assert from'node:assert/strict';import fs from'node:fs';import path from'node:path';import{createHash}from'node:crypto';import{fileURLToPath}from'node:url';
const root=fileURLToPath(new URL('../candidate/panel-integration-load-balance/',import.meta.url)),sha=b=>createHash('sha256').update(b).digest('hex');
test('source export includes every argument of actual multi-file normal build checks',()=>{
 const record=JSON.parse(fs.readFileSync(path.join(root,'source-sha256.json'),'utf8')),build=fs.readFileSync(path.join(root,'packaging/build-release.sh'),'utf8'),required=new Set();
 for(const line of build.split('\n'))if(line.includes('/opt/homebrew/bin/node '))for(const value of line.matchAll(/scripts\/[A-Za-z0-9-]+\.mjs/g))required.add(value[0]);
 assert(required.has('scripts/test-waf-country-identity.mjs'));assert(required.has('scripts/test-waf-country-policy.mjs'));assert(required.has('scripts/test-platform-health-lifecycle.mjs'));
 for(const name of required){assert.equal(typeof record.files[name],'string',name+' missing from normal source export');assert.equal(sha(fs.readFileSync(path.join(root,name))),record.files[name],name+' differs from frozen source');}
});
