import test from'node:test';import assert from'node:assert/strict';import fs from'node:fs/promises';import path from'node:path';import os from'node:os';import{fileURLToPath}from'node:url';import{spawnSync}from'node:child_process';import{generateKeyPairSync}from'node:crypto';
import{verifyCountryDataManifest}from'../tools/country-data-contract.mjs';
const source=fileURLToPath(new URL('..',import.meta.url)),relative='data/geodata/dbip-country-lite-v1',key=await fs.readFile(path.join(source,'signatures/catalog-v1.pub.pem')),current=JSON.parse(await fs.readFile(path.join(source,relative,'catalog.signed.json'),'utf8')),authority=verifyCountryDataManifest(current.manifest,current.signature,key),release=authority.manifest.release+'-r'+authority.manifest.revision+'-'+authority.sha256;
async function fixture(t){
 const root=await fs.realpath(await fs.mkdtemp(path.join(os.tmpdir(),'yunzhan-country-publisher-')));t.after(()=>fs.rm(root,{recursive:true,force:true}));for(const d of['tools','signatures','input'])await fs.mkdir(path.join(root,d));
 for(const n of['tools/build-country-data-channel.mjs','tools/country-data-contract.mjs','tools/lib.mjs','tools/memcached-unix-contract.mjs','tools/php-security-contract.mjs','tools/php-bounded-contract.mjs','tools/load-balance-stream-contract.mjs','signatures/catalog-v1.pub.pem'])await fs.copyFile(path.join(source,n),path.join(root,n));
 for(const a of authority.assets)await fs.copyFile(path.join(source,relative,'releases',release,a.code+'.cidr'),path.join(root,'input',a.code+'.cidr'));
 await fs.writeFile(path.join(root,'manifest.json'),current.manifest);await fs.writeFile(path.join(root,'manifest.sig'),current.signature+'\n');return root;
}
const run=root=>spawnSync(process.execPath,[path.join(root,'tools/build-country-data-channel.mjs'),path.join(root,'manifest.json'),path.join(root,'manifest.sig'),path.join(root,'input')],{encoding:'utf8',timeout:15000});
test('actual original signed parent and derived inventory require distinct domains pinned key and exact bytes',()=>{
 assert.equal(authority.assets.length,250);assert.equal(authority.manifest.networks,1287384);assert.equal(authority.manifest.bytes,27522952);
 assert.throws(()=>verifyCountryDataManifest(current.manifest.replace('2026-10','2026-09'),current.signature,key),/signature/);
 const foreign=generateKeyPairSync('ed25519').publicKey.export({type:'spki',format:'pem'});assert.throws(()=>verifyCountryDataManifest(current.manifest,current.signature,foreign),/original pinned/);
 assert.throws(()=>verifyCountryDataManifest(current.manifest,'A'.repeat(88),key),/signature/);
 assert.throws(()=>verifyCountryDataManifest(current.manifest,current.signature,key,new Date('2026-01-01Z')),/future/);
});
test('country publisher verifies all immutable members on repeat and never overwrites a changed asset',async t=>{
 const root=await fixture(t),first=run(root);assert.equal(first.status,0,first.stderr);assert.equal(run(root).status,0);
 const pointer=path.join(root,relative,'catalog.signed.json'),before=await fs.readFile(pointer),leaf=path.join(root,relative,'releases',release,'CN.cidr');await fs.writeFile(leaf,'external changed original; keep');assert.notEqual(run(root).status,0);assert.equal(await fs.readFile(leaf,'utf8'),'external changed original; keep');assert((await fs.readFile(pointer)).equals(before));
});
test('signature data mismatch and unsafe paths cannot publish or change outside data',async t=>{
 const root=await fixture(t);await fs.writeFile(path.join(root,'manifest.sig'),'A'.repeat(88));assert.notEqual(run(root).status,0);await assert.rejects(fs.access(path.join(root,'data')));
 await fs.writeFile(path.join(root,'manifest.sig'),current.signature+'\n');const leaf=path.join(root,'input','CN.cidr'),original=await fs.readFile(leaf);await fs.writeFile(leaf,original.subarray(0,original.length-1));assert.notEqual(run(root).status,0);await assert.rejects(fs.access(path.join(root,'data')));await fs.writeFile(leaf,original);
 const outside=await fs.realpath(await fs.mkdtemp(path.join(os.tmpdir(),'yunzhan-country-outside-')));t.after(()=>fs.rm(outside,{recursive:true,force:true}));await fs.writeFile(path.join(outside,'sentinel'),'preserve outside data');await fs.symlink(outside,path.join(root,'data'));assert.notEqual(run(root).status,0);assert.deepEqual(await fs.readdir(outside),['sentinel']);
 await fs.unlink(path.join(root,'data'));assert.equal(run(root).status,0);const target=path.join(root,relative,'releases',release,'NOTICE.txt');await fs.link(target,path.join(outside,'foreign-link'));assert.notEqual(run(root).status,0);assert.equal(await fs.readFile(path.join(outside,'sentinel'),'utf8'),'preserve outside data');
});
