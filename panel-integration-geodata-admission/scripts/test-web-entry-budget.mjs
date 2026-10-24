import {test} from 'node:test';
import assert from 'node:assert/strict';
import {mkdtempSync,mkdirSync,writeFileSync,readFileSync,symlinkSync,rmSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {webEntryBudget} from './web-entry-budget.mjs';
import ts from '../web/node_modules/typescript/lib/typescript.js';
const html=(entry='./assets/index-fixture.js',preload='')=>`<script type="module" src="${entry}"></script>${preload}`;
function fixture(t,entry='export const entry=1;') {
 const root=mkdtempSync(join(tmpdir(),'panel-web-entry-budget-'));mkdirSync(join(root,'assets'));
 t.after(()=>{assert(root.startsWith(join(tmpdir(),'panel-web-entry-budget-')));rmSync(root,{recursive:true});});
 const put=(name,body)=>writeFileSync(join(root,name),body);
 put('index.html',html());put('assets/index-fixture.js',entry);put('assets/AppModuleManager-fixture.js','export const module=1;');
 return {root,put};
}
test('entry graph deduplicates modulepreloads and cycles without counting a deferred module as eager',t=>{
 const f=fixture(t,'import "./common.js";export const x=1;');f.put('assets/common.js','export {x} from "./index-fixture.js";');
 f.put('index.html',html(undefined,'<link rel="modulepreload" href="./assets/common.js"><link rel="modulepreload" href="./assets/common.js">'));
 const out=webEntryBudget(f.root);assert(out.passed);assert.equal(out.eager_assets.length,2);assert.equal(out.eager_javascript_bytes,out.eager_assets.reduce((n,x)=>n+x.bytes,0));assert.equal(out.eager_limit_bytes,1200000);
});
test('static eager import of the application manager is rejected',t=>{const f=fixture(t,'import "./AppModuleManager-fixture.js";');assert.throws(()=>webEntryBudget(f.root),/still eagerly loaded/);});
test('modulepreloading the manager is also an eager regression even without a static import',t=>{const f=fixture(t);f.put('index.html',html(undefined,'<link rel="modulepreload" href="./assets/AppModuleManager-fixture.js">'));assert.throws(()=>webEntryBudget(f.root),/still eagerly loaded/);});
test('separately undersized chunks cannot hide an oversized eager dependency graph',t=>{
 const f=fixture(t,'import "./common.js";/*'+'x'.repeat(650000)+'*/');f.put('assets/common.js','/*'+'x'.repeat(650000)+'*/');assert.throws(()=>webEntryBudget(f.root),/Eager entry JavaScript exceeds/);
});
test('an oversized deferred chunk is refused both at the byte sentinel and before oversized reading',t=>{
 const f=fixture(t);
 for(const bytes of [1200001,1200004]){f.put('assets/AppModuleManager-fixture.js','/*'+'x'.repeat(bytes-4)+'*/');assert.throws(()=>webEntryBudget(f.root),bytes===1200001?/deferred JavaScript chunk exceeds/:/bounded ordinary file/);}
});
test('an oversized single entry is rejected before parsing',t=>{const f=fixture(t,'/*'+'x'.repeat(1200000)+'*/');assert.throws(()=>webEntryBudget(f.root),/JavaScript asset exceeds|bounded ordinary file/);});
test('script and preload paths cannot point to external or parent files',t=>{
 const f=fixture(t);for(const path of ['https://example.test/index.js','../index.js','./assets/../index.js','./assets/index-fixture.js?new=1']){f.put('index.html',html(path));assert.throws(()=>webEntryBudget(f.root),/fixed local JavaScript/);}
 f.put('index.html',html(undefined,'<link rel="modulepreload" href="https://example.test/chunk.js">'));assert.throws(()=>webEntryBudget(f.root),/fixed local JavaScript/);
});
test('a static import cannot escape the fixed asset directory',t=>{const f=fixture(t,'import "../outside.js";');assert.throws(()=>webEntryBudget(f.root),/local asset directory/);});
test('symlinked assets cannot pass the ordinary build file check',t=>{const f=fixture(t,'import "./link.js";');symlinkSync(join(f.root,'assets/AppModuleManager-fixture.js'),join(f.root,'assets/link.js'));assert.throws(()=>webEntryBudget(f.root),/bounded ordinary file/);});
test('invalid generated JavaScript and missing actual deferred chunk fail closed',t=>{
 const f=fixture(t,'export const =;');assert.throws(()=>webEntryBudget(f.root),/could not be parsed/);
 const g=fixture(t);rmSync(join(g.root,'assets/AppModuleManager-fixture.js'));assert.throws(()=>webEntryBudget(g.root),/one actual deferred/);
});
test('eager graph count and total JavaScript inventory stay finite',t=>{
 const f=fixture(t,Array.from({length:65},(_,i)=>`import "./chunk${i}.js";`).join(''));
 for(let i=0;i<65;i++)f.put(`assets/chunk${i}.js`,'export const x=1;');assert.throws(()=>webEntryBudget(f.root),/64 assets/);
 const g=fixture(t);for(let i=0;i<127;i++)g.put(`assets/unused${i}.js`,'export const x=1;');assert.throws(()=>webEntryBudget(g.root),/128 entries/);
});
test('multiple module roots are not quietly summarized as a smaller single root',t=>{const f=fixture(t);f.put('index.html',html()+html());assert.throws(()=>webEntryBudget(f.root),/one module entry/);});
test('actual Vite chunk naming emits only the unchanged verifier-safe local asset shape',()=>{
 const source=readFileSync(new URL('../web/vite.config.ts',import.meta.url),'utf8');
 const js=ts.transpileModule(source,{compilerOptions:{target:ts.ScriptTarget.ES2022,module:ts.ModuleKind.ESNext}}).outputText.replace(/^import[^\n]*\n/gm,'').replace('export default','return');
 const config=new Function('defineConfig','vue','process',js)(value=>value,()=>({}),{env:{}}),emit=config.build.rollupOptions.output.chunkFileNames;
 assert.equal(typeof emit,'function');
 for(const name of ['runtime-core.esm-bundler','AppModuleManager','MemcachedAppUpdate','../outside','@scope/name','space name']){
  const path=emit({name});assert.match(path,/^assets\/[A-Za-z0-9_-]+-\[hash\]\.js$/);assert(!path.includes('..'));assert(!path.includes('?'));
 }
 assert.equal(config.build.chunkSizeWarningLimit,1200);
});
