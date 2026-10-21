import test from'node:test';import assert from'node:assert/strict';import{readFileSync}from'node:fs';import ts from'../web/node_modules/typescript/lib/typescript.js';
async function load(name){const source=readFileSync(new URL('../web/src/'+name,import.meta.url),'utf8'),code=ts.transpileModule(source,{compilerOptions:{target:ts.ScriptTarget.ES2022,module:ts.ModuleKind.ESNext}}).outputText;return import('data:text/javascript;base64,'+Buffer.from(code).toString('base64'))}
const{registryUpdateBadge,registryUpdateActionLabel,registryManualUpdateReview}=await load('registryUpdateLabel.ts'),{registryVersionLabel}=await load('registryVersionLabel.ts');
test('runtime program detection is never labelled as an applied application package',()=>{
 const state={installed:true,state_known:true,version_known:true,installed_version:'1.30.6',version_source:'upstream-runtime',update_available:true,update_supported:true,update_kind:'runtime-package-review'};
 assert.equal(registryVersionLabel('runtime','1.30.6-compat2',state),'运行时程序 1.30.6 · 仓库安装包 1.30.6-compat2（应用包修订待核对）');assert.equal(registryUpdateBadge(state),'应用包待核对');assert.equal(registryUpdateActionLabel(state),'核对应用包');assert.equal(registryManualUpdateReview(state),false);
 assert.equal(registryVersionLabel('runtime','1.30.6-compat2',{...state,version_source:'application-receipt',installed_version:'1.30.6-compat1'}),'已安装应用包 1.30.6-compat1 · 仓库安装包 1.30.6-compat2');
});
test('manual host Docker and compose review do not grant automatic replacement',()=>{
 for(const state of [{update_kind:'runtime-host-review',update_supported:false},{update_kind:'compose-review',update_supported:false}])assert(registryManualUpdateReview(state));
 assert.equal(registryUpdateActionLabel({update_kind:'runtime-host-review',update_supported:false}),'核对 Docker 宿主');assert.equal(registryUpdateActionLabel({update_kind:'compose-review',update_supported:false}),'核对容器更新');assert.equal(registryUpdateActionLabel({update_kind:'runtime-package-review',update_supported:false}),'需升级面板');
 assert.equal(registryUpdateActionLabel({update_kind:'module',update_supported:true}),'更新应用');assert.equal(registryUpdateBadge({update_kind:'module'}),'有新版');assert.equal(registryManualUpdateReview({update_kind:'untrusted-kind'}),false);
});
test('actual store template retains backend update, stale-source and navigation boundaries',()=>{
 const app=readFileSync(new URL('../web/src/App.vue',import.meta.url),'utf8');assert(app.includes('registryUpdateBadge(registryStatus(app.id))'));assert(app.includes('registryUpdateActionLabel(registryStatus(app.id))'));assert(app.includes('registryStatus(app.id)?.update_supported ? updateRegistryApp(app) : (registryManualUpdateReview(registryStatus(app.id)) ? openRegistryApp(app)'));assert(app.includes(':disabled="registryInstalling.includes(app.id) || appRegistry.source.stale"'));
});

function actualUpdate(status){
 const source=readFileSync(new URL('../web/src/App.vue',import.meta.url),'utf8').split('<script setup lang="ts">')[1].split('</script>')[0],ast=ts.createSourceFile('App.ts',source,ts.ScriptTarget.Latest,true,ts.ScriptKind.TS),fn=ast.statements.find(n=>ts.isFunctionDeclaration(n)&&n.name?.text==='updateRegistryApp');assert(fn);
 const compiled=ts.transpileModule(fn.getText(ast),{compilerOptions:{target:ts.ScriptTarget.ES2022}}).outputText,events=[],b={registryStatus:()=>status,registryInstalling:{value:[]},ElMessage:{warning:message=>events.push(['warning',message]),success:message=>events.push(['success',message]),error:message=>events.push(['error',message])},api:async(...args)=>{events.push(['api',...args]);return{job_id:'actual-returned-fixture-job'}},refresh:async()=>events.push(['refresh']),revealJob:async id=>events.push(['reveal',id]),memcachedAppUpdate:{value:null}};
 return{fn:new Function('b','with(b){'+compiled+';return updateRegistryApp;}')(b),events,b};
}
test('actual selected frontend handler never submits a host/manual or unsupported update',async()=>{
 for(const status of [{update_kind:'runtime-host-review',update_supported:false},{update_kind:'runtime-package-review',update_supported:false},{update_kind:'compose-review',update_supported:false},undefined]){
  const f=actualUpdate(status);await f.fn({id:'docker-manager'});assert.equal(f.events.filter(e=>e[0]==='api').length,0);assert.equal(f.events[0][0],'warning');assert.deepEqual(f.b.registryInstalling.value,[]);
 }
});
test('actual selected package review handler posts one original version/hash update, reveals original job and claims only submission',async()=>{
 const f=actualUpdate({update_kind:'runtime-package-review',update_supported:true}),app={id:'nginx',name:'Nginx',version:'1.30.6-compat1',sha256:'a'.repeat(64)};await f.fn(app);
 assert.deepEqual(f.events.filter(e=>e[0]==='api'),[['api','/app-registry/nginx/update','POST',{expected_version:app.version,expected_sha256:app.sha256}]]);assert(f.events.some(e=>e[0]==='reveal'&&e[1]==='actual-returned-fixture-job'));assert(f.events.some(e=>e[0]==='success'&&e[1].includes('核对/安装')&&e[1].includes('成功完成后才记录版本')));assert.deepEqual(f.b.registryInstalling.value,[]);
});
