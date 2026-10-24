import test from'node:test';import assert from'node:assert/strict';import fs from'node:fs';import ts from'../web/node_modules/typescript/lib/typescript.js';
const source=fs.readFileSync(new URL('../web/src/phpSecurity.ts',import.meta.url),'utf8'),compiled=ts.transpileModule(source,{compilerOptions:{target:ts.ScriptTarget.ES2022,module:ts.ModuleKind.ESNext}}).outputText;
const {phpSecurityFor,phpSecurityExposure}=await import('data:text/javascript;base64,'+Buffer.from(compiled).toString('base64'));
const releases=[{id:'php-8.2.35',installation_allowed:true,security:{status:'fixed-for-advisory',message:'patched'}},{id:'php-8.2.33',installation_allowed:false,security:{status:'affected',message:'affected'}}];
test('exact source identity only; app-package revisions and duplicate rows cannot invent patch status',()=>{
 assert.equal(phpSecurityFor(releases,'php-8.2.35').status,'fixed-for-advisory');
 for(const id of['php-8.2.33-compat1','php-8.2.350','PHP-8.2.35','php-8.2.99'])assert.equal(phpSecurityFor(releases,id),undefined);
 assert.equal(phpSecurityFor([releases[0],releases[0]],releases[0].id),undefined);
});
test('installing the patch never hides sites still bound to the affected runtime',()=>{
 const installed=[{id:'php-8.2.33',family:'php'},{id:'php-8.2.35',family:'php'},{id:'nginx-1.30.6',family:'nginx'}],sites=[{php_version_id:'php-8.2.33'},{php_version_id:'php-8.2.35'},{php_version_id:''}];
 const before=JSON.stringify({releases,installed,sites});
 assert.deepEqual(phpSecurityExposure(releases,installed,sites),{installed:['php-8.2.33'],sites:1});
 assert.deepEqual(phpSecurityExposure(releases,installed,[{php_version_id:'php-8.2.35'}]),{installed:['php-8.2.33'],sites:0});
 assert.equal(JSON.stringify({releases,installed,sites}),before);
});
test('status is advisory-specific, never inferred from an install or health flag',()=>{
 const list=[{id:'php-8.2.99',family:'php'}];
 assert.deepEqual(phpSecurityExposure([],list,[{php_version_id:list[0].id}]),{installed:[],sites:0});
 assert.equal(phpSecurityFor([],list[0].id),undefined);
});
test('actual UI keeps affected installs visible, blocks new selections, and shows site migration boundary',()=>{
 const app=fs.readFileSync(new URL('../web/src/App.vue',import.meta.url),'utf8');
 for(const fragment of['data-testid="php-security-exposure"','data-php-security','release.installation_allowed === true','runtimeInstalled(item.id) || !runtimeInstallable(item.id)','新版本安装成功不代表旧网站已修复','当前可见网站中'])assert(app.includes(fragment),fragment);
 assert(app.includes('const versionManagerAvailable = computed(() => versionManagerRuntime.value?.releases?.filter(item => !runtimeInstalled(item.id) && runtimeInstallable(item.id))'));
});

