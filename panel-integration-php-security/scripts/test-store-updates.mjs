import test from 'node:test';import assert from 'node:assert/strict';import {readFileSync} from 'node:fs';import ts from '../web/node_modules/typescript/lib/typescript.js';
const source=readFileSync(new URL('../web/src/App.vue',import.meta.url),'utf8').split('<script setup lang="ts">')[1].split('</script>')[0],ast=ts.createSourceFile('App.ts',source,ts.ScriptTarget.Latest,true,ts.ScriptKind.TS);
const labelCode=ts.transpileModule(readFileSync(new URL('../web/src/registryVersionLabel.ts',import.meta.url),'utf8'),{compilerOptions:{target:ts.ScriptTarget.ES2022,module:ts.ModuleKind.ESNext}}).outputText;
const {registryVersionLabel}=await import('data:text/javascript;base64,'+Buffer.from(labelCode).toString('base64'));
const searchCode=ts.transpileModule(readFileSync(new URL('../web/src/storeSearch.ts',import.meta.url),'utf8'),{compilerOptions:{target:ts.ScriptTarget.ES2022,module:ts.ModuleKind.ESNext}}).outputText;
const {normalizeStoreSearch,sortStoreSearchResults}=await import('data:text/javascript;base64,'+Buffer.from(searchCode).toString('base64'));
function actual(name,b){const declarations=ast.statements.filter(ts.isVariableStatement).flatMap(n=>[...n.declarationList.declarations]),d=declarations.find(d=>d.name.getText(ast)===name);assert(d,name);const js=ts.transpileModule('const '+d.getText(ast)+';',{compilerOptions:{target:ts.ScriptTarget.ES2022}}).outputText;return new Function('b','with(b){'+js+';return '+name+';}')(b);}
function fixture(){
 const app=(id,risk='maintained')=>({id,name:id==='website-analytics'?'网站分析':'PHP 5.6',target:id,category:'professional',stage:'ready',risk,summary:'',capabilities:[]});
 const b={computed:fn=>({get value(){return fn()}}),storeCategory:{value:'recommended'},storeSearch:{value:''},storeStatus:{value:'all'},storeSort:{value:'recommended'},appRegistry:{value:{catalog:{apps:[app('website-analytics'),app('php-56','eol')]}}},softwareApps:{value:{catalog:[]}},normalizeStoreSearch:s=>s.replace(/\s/g,'').toLowerCase(),registryCategoryMap:{monitoring:['website-analytics'],cache:['redis']},storeFamilies:{web:['nginx'],cache:['redis']},runtimes:{value:{catalog:[{id:'nginx',family:'nginx',name:'Nginx',description:'',versions:[],state:'available'},{id:'redis',family:'redis',name:'Redis',description:'',versions:[],state:'available'}]}},versions:{value:{redis:'redis-installed'}},runtimeInstalled:id=>id==='redis-installed',registryStatus:()=>({installed:true,update_available:true,update_supported:true})};
 // Execute the real new imported helpers in the original compiled selectors;
 // do not stub relevance to a no-op or remove existing update-policy cases.
 Object.assign(b,{normalizeStoreSearch,sortStoreSearchResults});
 b.showReferenceRuntimeCards=actual('showReferenceRuntimeCards',b);b.filteredCatalog=actual('filteredCatalog',b);b.filteredRegistryApps=actual('filteredRegistryApps',b);return b;
}
test('actual signed registry selector prioritizes exact localized identity only in comprehensive search',()=>{
 const b=fixture();b.storeCategory.value='all';b.storeSearch.value='网站分析';
 b.appRegistry.value.catalog.apps=[
  {id:'disk-analysis',name:'Disk analysis',target:'disk-analysis',stage:'ready',risk:'maintained',summary:'保留网站分析与目录下载',capabilities:[]},
  {id:'website-analytics',name:'Website Analytics',target:'website-analytics',stage:'ready',risk:'maintained',summary:'浏览器采集',capabilities:[]},
 ];
 b.softwareApps.value.catalog=[{id:'website-analytics',name:'网站分析'}];
 const original=JSON.stringify(b.appRegistry.value.catalog.apps);
 assert.deepEqual(b.filteredRegistryApps.value.map(a=>a.id),['website-analytics','disk-analysis']);
 b.storeSort.value='installed';b.registryStatus=()=>({installed:true});
 assert.deepEqual(b.filteredRegistryApps.value.map(a=>a.id),['disk-analysis','website-analytics']);
 b.storeSort.value='name';
 assert.deepEqual(b.filteredRegistryApps.value.map(a=>a.name),['Disk analysis','Website Analytics']);
 assert.equal(JSON.stringify(b.appRegistry.value.catalog.apps),original);
});
test('actual recommended update filter lists signed application updates instead of unrelated runtime cards',()=>{const b=fixture();b.storeStatus.value='updates';assert.equal(b.showReferenceRuntimeCards.value,false);assert.deepEqual(b.filteredCatalog.value,[]);assert.equal(b.filteredRegistryApps.value.length,2);});
test('offline runtime catalog cannot fabricate available application updates',()=>{const b=fixture();b.appRegistry.value.catalog.apps=[];b.storeStatus.value='updates';assert.deepEqual(b.filteredCatalog.value,[]);assert.deepEqual(b.filteredRegistryApps.value,[]);});
test('actual default recommendations and installed runtime choices retain their old behavior',()=>{const b=fixture();assert(b.showReferenceRuntimeCards.value);assert.equal(b.filteredCatalog.value.length,2);assert.deepEqual(b.filteredRegistryApps.value,[]);b.storeStatus.value='installed';assert.equal(b.filteredCatalog.value.length,1);assert.equal(b.filteredCatalog.value[0].family,'redis');});
test('updates still require an actual update signal; unavailable handler remains visible without granting installation',()=>{const b=fixture();b.storeStatus.value='updates';b.registryStatus=id=>({installed:true,update_available:id==='website-analytics',update_supported:false});const rows=b.filteredRegistryApps.value;assert.equal(rows.length,1);assert.equal(rows[0].id,'website-analytics');assert.equal(b.registryStatus(rows[0].id).update_supported,false);});
test('actual update category and Chinese search keep narrowing known updates',()=>{const b=fixture();b.storeStatus.value='updates';b.storeCategory.value='monitoring';assert.equal(b.filteredRegistryApps.value.length,1);b.storeCategory.value='all';b.storeSearch.value='网站 分析';assert.equal(b.filteredRegistryApps.value.length,1);b.storeSearch.value='没有此应用';assert.deepEqual(b.filteredRegistryApps.value,[]);});
test('runtime and upstream image versions are not displayed as comparable package update revisions',()=>{
 const runtime={installed:true,version_known:true,installed_version:'29.8.2',update_available:false};assert.equal(registryVersionLabel('runtime','1-compat1',runtime),'已安装记录 29.8.2 · 仓库安装包 1-compat1');assert(!registryVersionLabel('runtime','1-compat1',{...runtime,update_available:true}).includes('→'));
 const image={...runtime,installed_version:'1.6.45',version_source:'upstream-image',update_available:true};assert.equal(registryVersionLabel('compose','1.6.45-compat2',image),'镜像程序 1.6.45 · 仓库应用包 1.6.45-compat2（应用包修订待核对）');assert(!registryVersionLabel('compose','1.6.45-compat2',image).includes('→'));
 assert(readFileSync(new URL('../web/src/App.vue',import.meta.url),'utf8').includes('registryVersionLabel(app.provider, app.version, registryStatus(app.id))'));
});
test('only a known installed package plus original backend update flag renders a revision arrow',()=>{
 const status={installed:true,version_known:true,installed_version:'2.3.0',update_available:true};assert.equal(registryVersionLabel('panel-module','2.3.1',status),'已安装应用包 2.3.0 → 仓库应用包 2.3.1');assert(!registryVersionLabel('panel-module','2.3.1',{...status,update_available:false}).includes('→'));assert(registryVersionLabel('panel-module','2.3.1',{...status,state_known:false}).includes('版本待核对'));assert(!registryVersionLabel('panel-module','2.3.1',{...status,version_known:false}).includes('→'));
 assert.equal(registryVersionLabel('compose','1.6.45-compat2',{...status,instances:[{},{}]}),'已安装 2 个实例（分别核对版本） · 仓库应用包 1.6.45-compat2');for(const bad of [undefined,'',42,'x'.repeat(129),'untrusted\nversion'])assert(registryVersionLabel('panel-module','2.3.1',{...status,installed_version:bad}).includes('版本待核对'));
});
