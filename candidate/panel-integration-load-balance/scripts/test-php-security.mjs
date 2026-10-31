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

const previewSource=fs.readFileSync(new URL('../web/src/phpSwitchPreview.ts',import.meta.url),'utf8');
const previewTools=await import('data:text/javascript;base64,'+Buffer.from(ts.transpileModule(previewSource,{compilerOptions:{target:ts.ScriptTarget.ES2022,module:ts.ModuleKind.ESNext}}).outputText).toString('base64'));
const phpApp=fs.readFileSync(new URL('../web/src/App.vue',import.meta.url),'utf8');
const phpAST=ts.createSourceFile('App.vue.ts',phpApp.slice(phpApp.indexOf('<script setup lang="ts">')+24,phpApp.indexOf('</script>')),ts.ScriptTarget.Latest,true,ts.ScriptKind.TS);
const phpFunctions=['phpSwitchContext','choosePHP','readPHPPreview','previewPHP','switchPHP'].map(name=>{
 const node=phpAST.statements.find(n=>ts.isFunctionDeclaration(n)&&n.name?.text===name);assert(node,name);return node.getText(phpAST);
}).join('\n');
const phpActual=ts.transpileModule(phpFunctions,{compilerOptions:{target:ts.ScriptTarget.ES2022,module:ts.ModuleKind.ESNext}}).outputText;
const phpContext=()=>({site_id:'a'.repeat(32),release_id:'php-8.4.27',current_release_id:'php-8.4.25',revision:7,access:'current account'});
const phpReceipt=(context=phpContext())=>({protocol:'php-vhost-switch-v1',site_id:context.site_id,release_id:context.release_id,revision:context.revision,current:'# original operator configuration\n',candidate:'# preserved operator configuration\n',config_sha:'b'.repeat(64),preserves_custom_config:true});
function phpHarness(api){return new Function('deps',`
 const {parsePHPSwitchPreview,samePHPSwitchContext}=deps.tools,ref=value=>({value});
 const sites=ref([{id:'a'.repeat(32),php_version_id:'php-8.4.25',settings_revision:7}]),phpTarget=ref(sites.value[0]),phpSelection=ref('php-8.4.27'),phpOpen=ref(true),phpPreview=ref(),submittingPHP=ref(false),accessPlan=ref({role:'admin',menu_ids:['sites'],user_id:'current'});
 let phpPreviewEpoch=0;const errors=[],jobs=[],ElMessage={error(e){errors.push(e)}},canOpenView=(plan,id)=>plan?.menu_ids.includes(id),api=deps.api,refresh=async()=>{},revealJob=async id=>jobs.push(id);
 ${phpActual}
 return{sites,phpTarget,phpSelection,phpOpen,phpPreview,submittingPHP,accessPlan,errors,jobs,choosePHP,previewPHP,switchPHP,context:phpSwitchContext,invalidate(){phpPreviewEpoch++;phpPreview.value=undefined}};
 `)({tools:previewTools,api});}
function pendingPHP(){let resolve,reject;const promise=new Promise((yes,no)=>{resolve=yes;reject=no});return{promise,resolve,reject};}
test('PHP preview rejects a wrong site, release, revision, malformed proof and UTF8 budget overflow',()=>{
 const context=phpContext(),receipt=phpReceipt();assert.deepEqual(previewTools.parsePHPSwitchPreview(receipt,context),receipt);
 for(const change of [{protocol:'generic-settings'},{site_id:'c'.repeat(32)},{release_id:'php-8.5.12'},{revision:6},{revision:NaN},{config_sha:'B'.repeat(64)},{preserves_custom_config:'true'},{current:'\0'},{candidate:'界'.repeat(22000)},{current:''}])assert.throws(()=>previewTools.parsePHPSwitchPreview({...receipt,...change},context));
 for(const key of ['site_id','release_id','current_release_id','revision','access'])assert.equal(previewTools.samePHPSwitchContext(context,{...context,[key]:key==='revision'?8:'changed'}),false);
 assert.equal(previewTools.samePHPSwitchContext(context,null),false);
});
test('actual PHP dialog obtains a current preview, then submits its SHA exactly once',async()=>{
 const calls=[],h=phpHarness(async(path,method,body)=>{calls.push({path,method,body});return path.endsWith('/preview')?phpReceipt():{job_id:'original-job'}});
 await h.switchPHP();assert.equal(calls.length,2);assert.equal(calls[0].path,'/sites/'+'a'.repeat(32)+'/php/preview');assert.deepEqual(calls[0].body,{release_id:'php-8.4.27'});assert.deepEqual(calls[1].body,{release_id:'php-8.4.27',expected_config_sha:'b'.repeat(64)});assert.deepEqual(h.jobs,['original-job']);assert.equal(h.phpOpen.value,false);assert.equal(h.errors.length,0);
});
test('late PHP previews cannot queue after selection, site binding, settings, account or dialog changes',async()=>{
 for(const change of [h=>{h.phpSelection.value='php-8.5.12'},h=>{h.sites.value[0].php_version_id='php-8.3.36'},h=>{h.sites.value[0].settings_revision++},h=>{h.accessPlan.value=null},h=>{h.phpOpen.value=false},h=>{h.accessPlan.value={role:'viewer',menu_ids:['sites']}},h=>{h.sites.value=[]},h=>{h.phpSelection.value='php-8.5.12';h.invalidate();h.phpSelection.value='php-8.4.27'}]){
  const d=pendingPHP(),calls=[],h=phpHarness((...args)=>{calls.push(args);return d.promise}),running=h.switchPHP();change(h);d.resolve(phpReceipt());await running;assert.equal(calls.length,1);assert.equal(h.jobs.length,0);assert.equal(h.errors.length,1);
 }
});
test('double PHP clicks do not duplicate requests and a failed original mutation is never retried',async()=>{
 const d=pendingPHP(),calls=[],h=phpHarness((...args)=>{calls.push(args);if(calls.length===1)return d.promise;throw Error('Original outcome requires observation')});
 const first=h.switchPHP();await h.switchPHP();assert.equal(calls.length,1);h.choosePHP({id:'c'.repeat(32),php_version_id:'php-8.5.12'});assert.equal(h.phpTarget.value.id,'a'.repeat(32));d.resolve(phpReceipt());await first;assert.equal(calls.length,2);assert.deepEqual(h.errors,['Original outcome requires observation']);assert.equal(h.jobs.length,0);
});
test('preview button reads only, and a rejected or malformed preview cannot switch',async()=>{
 const calls=[],h=phpHarness(async(...args)=>{calls.push(args);return phpReceipt()});await h.previewPHP();assert.equal(calls.length,1);assert.equal(h.phpOpen.value,true);assert.equal(h.phpPreview.value.preserves_custom_config,true);
 for(const fail of [async()=>{throw Error('executor unavailable')},async()=>({...phpReceipt(),revision:8})]){let count=0;const bad=phpHarness((...args)=>{count++;return fail(...args)});await bad.switchPHP();assert.equal(count,1);assert.equal(bad.jobs.length,0);assert.equal(bad.errors.length,1)}
 assert.match(phpApp,/watch\(\(\) => JSON\.stringify\(phpSwitchContext\(\)\).*flush:"sync"/);
 for(const text of ['data-testid="php-switch-preview-mode"','data-testid="php-switch-config-preview"',':disabled="submittingPHP"',':close-on-press-escape="!submittingPHP"','expected_config_sha: preview.config_sha'])assert(phpApp.includes(text),text);
});

