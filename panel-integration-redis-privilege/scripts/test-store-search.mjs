import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import ts from '../web/node_modules/typescript/lib/typescript.js';
const source=fs.readFileSync(new URL('../web/src/storeSearch.ts',import.meta.url),'utf8');
const js=ts.transpileModule(source,{compilerOptions:{target:ts.ScriptTarget.ES2022,module:ts.ModuleKind.ESNext}}).outputText;
const {normalizeStoreSearch,sortStoreSearchResults}=await import('data:text/javascript;base64,'+Buffer.from(js).toString('base64'));
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
const ids=items=>items.map(item=>item.id);
test('exact localized application identity precedes description-only matches without mutating catalog',()=>{
  const items=[{id:'disk-analysis',name:'Disk analysis',local:'磁盘分析'},{id:'website-analytics',name:'网站分析 · Website Analytics',local:'网站分析'}];
  const before=JSON.stringify(items);
  assert.deepEqual(ids(sortStoreSearchResults(items,'网站分析',a=>[a.id,a.name,a.local])),['website-analytics','disk-analysis']);
  assert.equal(JSON.stringify(items),before);
});
test('identity ranking is exact, prefix, substring, then capabilities-only with stable ties',()=>{
  const items=['body-only','abc-query','query-more','query','query-another','body-other'].map(id=>({id}));
  assert.deepEqual(ids(sortStoreSearchResults(items,'query',a=>[a.id])),['query','query-more','query-another','abc-query','body-only','body-other']);
  assert.deepEqual(ids(sortStoreSearchResults(items,'　 ',a=>[a.id])),ids(items));
});
test('English aliases, localized aliases, full-width names and runtime identifiers rank as presentation only',()=>{
  const items=[{id:'other',names:['site statistics']},{id:'nginx-waf',names:['Nginx 请求防火墙 · Nginx WAF']},{id:'php-84',names:['PHP 8.4']}];
  for(const query of [' ｎｇｉｎｘ　ｗａｆ ','nginx-waf','Nginx 请求防火墙'])
    assert.equal(sortStoreSearchResults(items,query,a=>[a.id,...a.names])[0].id,'nginx-waf');
  assert.equal(sortStoreSearchResults(items,'PHP8.4',a=>a.names)[0].id,'php-84');
});
test('all four sources restrict relevance ordering to comprehensive sort and preserve explicit sorts',()=>{
  const app=fs.readFileSync(new URL('../web/src/App.vue',import.meta.url),'utf8');
  assert.equal((app.match(/storeSort.value === "recommended" \? sortStoreSearchResults/g)||[]).length,4);
  assert.equal((app.match(/storeSort.value === "name"/g)||[]).length,4);
  assert.equal((app.match(/storeSort.value === "installed"/g)||[]).length,3);
});
