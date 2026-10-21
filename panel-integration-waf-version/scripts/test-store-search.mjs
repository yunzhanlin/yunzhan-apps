import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import ts from '../web/node_modules/typescript/lib/typescript.js';
const source=fs.readFileSync(new URL('../web/src/storeSearch.ts',import.meta.url),'utf8');
const js=ts.transpileModule(source,{compilerOptions:{target:ts.ScriptTarget.ES2022,module:ts.ModuleKind.ESNext}}).outputText;
const {normalizeStoreSearch}=await import('data:text/javascript;base64,'+Buffer.from(js).toString('base64'));
test('Chinese software names match regardless of spacing, case or full width',()=>{
  for(const [query,text] of [['PHP代码安全','PHP 代码安全'],[' ｐｈｐ　代码 安全 ','PHP 代码安全'],['N G I N X WAF','Nginx WAF'],['网站分析','Website Analytics 网站 分析']]) assert(normalizeStoreSearch(text).includes(normalizeStoreSearch(query)));
  assert(!normalizeStoreSearch('PHP 8.4').includes(normalizeStoreSearch('PHP 7.4')));
  assert.equal(normalizeStoreSearch('   '),'');
});
test('all four store sources and panel card normalize both query and names',()=>{
  const app=fs.readFileSync(new URL('../web/src/App.vue',import.meta.url),'utf8');
  assert.equal((app.match(/const term = normalizeStoreSearch\(storeSearch.value\)/g)||[]).length,4);
  for(const fragment of ['normalizeStoreSearch(`${app.name} ${app.description}','normalizeStoreSearch(`${rt.name}','normalizeStoreSearch(`${app.name} ${app.family}','normalizeStoreSearch(`${app.name} ${localName}','normalizeStoreSearch("云栈面板 panel 运维")']) assert(app.includes(fragment),fragment);
});
