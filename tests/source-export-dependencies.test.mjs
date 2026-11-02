import {test} from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {createHash} from 'node:crypto';
const text=fs.readFileSync(new URL('../tools/export-load-balance-candidate-source.mjs',import.meta.url),'utf8');
const start=text.indexOf('function normalBuildScripts('),end=text.indexOf('\nconst scripts=normalBuildScripts(',start);assert(start>=0&&end>start);
const sha=bytes=>createHash('sha256').update(bytes).digest('hex');
const collect=new Function('fs','assert','sha',text.slice(start,end)+';return normalBuildScripts;')(fs,assert,sha);
const build='node --test scripts/test-load-balance-stream.mjs scripts/test-load-balance-stream-account-entry.mjs';
function fixture(t){
 const root=fs.mkdtempSync(path.join(os.tmpdir(),'yunzhan-source-closure-'));t.after(()=>fs.rmSync(root,{recursive:true,force:true}));fs.mkdirSync(root+'/scripts');
 const input={files:{}};
 const write=(name,body)=>{fs.writeFileSync(root+'/'+name,body,{mode:0o600});input.files[name]={sha256:sha(body)};};
 write('scripts/test-load-balance-stream.mjs','');write('scripts/test-load-balance-stream-account-entry.mjs','');
 return{root,input,write};
}
test('normal exporter follows imported helpers and literal sibling URL fixtures transitively',t=>{
 const f=fixture(t);f.write('scripts/test-load-balance-stream.mjs',`import x from './helper.mjs';const entry=new URL('./retired-browser.mjs',import.meta.url);`);f.write('scripts/helper.mjs',`const fixture = new URL('./expected.json', import.meta.url);`);f.write('scripts/expected.json','{}');f.write('scripts/retired-browser.mjs',`throw Error('retired');`);
 const result=collect(f.root,f.input,build);for(const name of ['helper.mjs','expected.json','retired-browser.mjs'])assert(result.has('scripts/'+name));assert.equal(result.size,7);
 assert.match(text,/const scripts=normalBuildScripts\(panel,input,build\)/);
});
test('cyclic frozen helper references terminate without copying unrelated browser runners',t=>{
 const f=fixture(t);f.write('scripts/test-load-balance-stream.mjs',`import x from './helper.mjs';`);f.write('scripts/helper.mjs',`import x from './test-load-balance-stream.mjs';`);f.write('scripts/unrelated-browser.mjs','unrelated');
 const result=collect(f.root,f.input,build);assert.equal(result.size,5);assert(!result.has('scripts/unrelated-browser.mjs'));
});
test('a missing or changed mandatory URL fixture fails export instead of silently dropping the gate',t=>{
 const f=fixture(t);f.write('scripts/test-load-balance-stream.mjs',`new URL('./retired-browser.mjs',import.meta.url);`);assert.throws(()=>collect(f.root,f.input,build),/ENOENT/);
 f.write('scripts/retired-browser.mjs',`throw Error('retired');`);fs.writeFileSync(f.root+'/scripts/retired-browser.mjs','changed');assert.throws(()=>collect(f.root,f.input,build),/retired-browser/);
});
test('a linked frozen dependency is rejected before its bytes are adopted',t=>{
 const f=fixture(t);f.write('scripts/test-load-balance-stream.mjs',`new URL('./retired-browser.mjs',import.meta.url);`);f.write('scripts/real.mjs','real');fs.symlinkSync('real.mjs',f.root+'/scripts/retired-browser.mjs');f.input.files['scripts/retired-browser.mjs']={sha256:sha('real')};assert.throws(()=>collect(f.root,f.input,build),/retired-browser/);
});
