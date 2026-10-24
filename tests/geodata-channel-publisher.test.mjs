import test from 'node:test';
import assert from 'node:assert/strict';
import {mkdtemp,mkdir,cp,readFile,writeFile,rm,symlink,link} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
import {spawnSync} from 'node:child_process';
const source=fileURLToPath(new URL('..',import.meta.url));
const channel='data/geodata/dbip-city-lite-v1';
const current=JSON.parse(await readFile(path.join(source,channel,'catalog.signed.json')));
const run=root=>spawnSync(process.execPath,[path.join(root,'tools/build-geodata-channel.mjs'),path.join(root,'input.json'),path.join(root,'input.sig')],{encoding:'utf8',timeout:10000});
async function fixture(t){
 const root=await mkdtemp(path.join(tmpdir(),'yunzhan-data-publisher-'));
 t.after(()=>rm(root,{recursive:true,force:true}));
 for(const directory of ['tools','signatures'])await mkdir(path.join(root,directory));
 for(const name of ['tools/build-geodata-channel.mjs','tools/lib.mjs','tools/memcached-unix-contract.mjs','tools/php-security-contract.mjs','tools/php-bounded-contract.mjs','signatures/catalog-v1.pub.pem'])await cp(path.join(source,name),path.join(root,name));
 await writeFile(path.join(root,'input.json'),current.manifest);await writeFile(path.join(root,'input.sig'),current.signature+'\n');
 return root;
}
test('publisher uses original signed small metadata and verifies immutable members even on repeat publication',async t=>{
 const root=await fixture(t);const first=run(root);assert.equal(first.status,0,first.stderr);
 const published=await readFile(path.join(root,channel,'catalog.signed.json'),'utf8');assert.deepEqual(JSON.parse(published),current);
 assert.equal(run(root).status,0);
 const {readdir}=await import('node:fs/promises');const [version]=await readdir(path.join(root,channel,'releases'));
 const member=path.join(root,channel,'releases',version,'NOTICE.txt');await writeFile(member,'tampered license notice');
 assert.notEqual(run(root).status,0);assert.equal(await readFile(member,'utf8'),'tampered license notice');
 assert.equal(await readFile(path.join(root,channel,'catalog.signed.json'),'utf8'),published);
});
test('publisher refuses signature corruption and caller-selected URLs without publishing',async t=>{
 const root=await fixture(t);await writeFile(path.join(root,'input.sig'),'A'.repeat(88));assert.notEqual(run(root).status,0);
 await writeFile(path.join(root,'input.sig'),current.signature);await writeFile(path.join(root,'input.json'),current.manifest.replace('https://download.db-ip.com/','http://127.0.0.1/'));
 assert.notEqual(run(root).status,0);
});
test('publisher refuses symlinked output and hardlinked immutable members without modifying targets',async t=>{
 const root=await fixture(t);const outside=await mkdtemp(path.join(tmpdir(),'yunzhan-data-outside-'));t.after(()=>rm(outside,{recursive:true,force:true}));
 await symlink(outside,path.join(root,'data'));assert.notEqual(run(root).status,0);await rm(path.join(root,'data'));
 assert.equal(run(root).status,0);
 const {readdir}=await import('node:fs/promises');const [version]=await readdir(path.join(root,channel,'releases'));
 const member=path.join(root,channel,'releases',version,'manifest.json');await link(member,path.join(outside,'foreign-link'));
 assert.notEqual(run(root).status,0);assert.equal(await readFile(member,'utf8'),current.manifest);
});
