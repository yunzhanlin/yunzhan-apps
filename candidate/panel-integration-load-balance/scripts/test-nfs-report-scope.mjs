import {test} from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {createRequire} from 'node:module';
import ts from '../web/node_modules/typescript/lib/typescript.js';
const require=createRequire(import.meta.url),sfc=require('../web/node_modules/@vue/compiler-sfc/dist/compiler-sfc.cjs.js');
async function load(name){const source=readFileSync(new URL('../web/src/'+name+'.ts',import.meta.url),'utf8');return import('data:text/javascript;base64,'+Buffer.from(ts.transpileModule(source,{compilerOptions:{target:ts.ScriptTarget.ES2022,module:ts.ModuleKind.ESNext}}).outputText).toString('base64'));}
const scope=await load('nfsReportScope'),permissions=await load('menuPermissions'),provenance=await load('moduleReportProvenance');
const manager=readFileSync(new URL('../web/src/AppModuleManager.vue',import.meta.url),'utf8'),parsed=sfc.parse(manager),source=parsed.descriptor.scriptSetup.content;
const ast=ts.createSourceFile('AppModuleManager.ts',source,ts.ScriptTarget.Latest,true,ts.ScriptKind.TS);
const wanted=['sectionReport','nfsReadCurrent','queueNFSSectionRead','startNFSSectionRead','cancelNFSSectionRead','fieldLabel','setReport'];
const declarations=wanted.map(name=>{const node=ast.statements.find(n=>ts.isFunctionDeclaration(n)&&n.name?.text===name);assert(node,name);return node.getText(ast);}).join('\n');
const actual=ts.transpileModule(declarations,{compilerOptions:{target:ts.ScriptTarget.ES2022,module:ts.ModuleKind.ESNext}}).outputText;
const server=()=>({config:{revision:9,bind_address:'::1',port:24249,exports:[{id:'share-one',site_id:'a'.repeat(32),clients:['::1'],read_only:false,uid:988,gid:33}]},service_active:true,boot_enabled:true,runtime_ready:true,recovery_pending:false});
const clients=()=>({mounts:[]});
function deferred(){let resolve,reject;const promise=new Promise((yes,no)=>{resolve=yes;reject=no});return{promise,resolve,reject};}
async function settle(){await Promise.resolve();await Promise.resolve();}
function harness(api){
 return new Function('deps',`
  const {nfsReportKind,nfsReportForSection,nfsSectionKind,nfsSectionReadAction}=deps.scope;
  const {canOpenAppModule}=deps.permissions,{moduleReportProvenance}=deps.provenance;
  const ref=value=>({value}),definition=ref({id:'nfs-manager'}),installed=ref(true),installedUnknown=ref(false),installedInstance=ref('a'.repeat(32)),installedVersion=ref('1.3.0'),visible=ref(true),busy=ref(false),activeTab=ref('server'),report=ref(deps.server()),reportStateUnknown=ref(false),reportProvenance=ref(),nfsSectionRead=ref(),nfsSectionReadError=ref(''),form=ref({confirm:'previous confirmation'}),selectedPlanID=ref(''),error=ref('Original mutation outcome remains unverified');
  let idsAccessGeneration=7,nfsPageReady=true,nfsNavigationKind='server',nfsSectionReadController;
  const props={api:deps.api,access:undefined},platformHealthSnapshot={remember(){throw Error('NFS must not mutate another application cache')}},platformSnapshotContext=()=>undefined;
  const loadBalanceReportForSection=(section,value)=>({section,value});
  ${actual}
  return{definition,installed,installedUnknown,installedInstance,installedVersion,visible,busy,activeTab,report,form,error,nfsSectionReadError,nfsSectionRead,
   go(section){activeTab.value=section;queueNFSSectionRead(section)},start:startNFSSectionRead,sectionReport,fieldLabel,setReport,
   revoke(){props.access=null;idsAccessGeneration++;cancelNFSSectionRead()},close(){visible.value=false;cancelNFSSectionRead()},
   changeInstallation(){installedInstance.value='b'.repeat(32);cancelNFSSectionRead()}};
 `)({scope,permissions,provenance,server,api});
}
test('server and client reports never appear in each other’s management pages',()=>{
 for(const section of ['server','listener','export','export-remove']){assert.equal(scope.nfsReportForSection(section,server())?.config.revision,9);assert.equal(scope.nfsReportForSection(section,clients()),undefined);}
 for(const section of ['mounts','mount','unmount']){assert.deepEqual(scope.nfsReportForSection(section,clients()),clients());assert.equal(scope.nfsReportForSection(section,server()),undefined);}
 for(const section of ['overview','history','reports','version','unknown'])assert.equal(scope.nfsSectionKind(section),undefined);
 for(const value of [null,[],{},'server',{config:{}},{config:{...server().config,revision:'9'}},{config:{...server().config,port:NaN}},{mounts:'empty'},{...server(),mounts:[]}])assert.equal(scope.nfsReportKind(value),undefined);
});
test('verified operation receipts retain their server or client context, including genuine false RPC results',()=>{
 for(const value of [{actual_nfs_v4_rpc:true,exports:1,encrypted:false},{actual_nfs_v4_rpc:false,exports:1,encrypted:false},{service_active:false,exports_and_files_retained:true}])assert.equal(scope.nfsReportKind(value),'server');
 for(const value of [{mounted:'client-one',path:'/srv/panel/nfs/client-one'},{unmounted:'client-one'}])assert.equal(scope.nfsReportKind(value),'clients');
 for(const value of [{mounted:'client-one',path:'/other'},{unmounted:'../escape'},{unmounted:'invalid_name'},{actual_nfs_v4_rpc:'true',exports:1,encrypted:false}])assert.equal(scope.nfsReportKind(value),undefined);
});
test('actual component navigation makes exactly one empty-body read and waits for the correct result',async()=>{
 const d=deferred(),calls=[];const h=harness((...args)=>{calls.push(args);return d.promise});h.go('mounts');assert.equal(h.busy.value,true);assert.equal(h.sectionReport('mounts'),undefined);h.go('mount');
 assert.equal(calls.length,1);assert.deepEqual(calls[0].slice(0,4),['/app-modules/nfs-manager/run','POST',{},undefined]);assert(calls[0][4]instanceof AbortSignal);assert.equal(h.form.value.confirm,'');
 d.resolve(clients());await settle();assert.deepEqual(h.sectionReport('mounts'),clients());assert.equal(h.sectionReport('server'),undefined);assert.equal(h.busy.value,false);assert.equal(h.error.value,'Original mutation outcome remains unverified');
 h.go('unmount');await h.start();assert.equal(calls.length,1);
});
test('rapid page switches discard a late client response and perform only the queued server read',async()=>{
 const first=deferred(),second=deferred(),calls=[];const h=harness((...args)=>{calls.push(args);return calls.length===1?first.promise:second.promise});const original=h.report.value;h.go('mounts');h.go('listener');
 first.resolve(clients());await settle();assert.equal(h.report.value,original);assert.equal(h.busy.value,false);await Promise.resolve();const running=h.start();assert.equal(calls.length,2);assert.deepEqual(calls[1].slice(0,3),['/app-modules/nfs-manager/server-report','POST',{}]);second.resolve(server());await running;
 assert.equal(h.form.value.port,24249);assert.equal(h.form.value.bind_address,'::1');assert.equal(h.form.value.expected_revision,9);assert.equal(h.sectionReport('mounts'),undefined);
});
test('a navigation queued behind an existing operation issues no mutation or duplicate read',async()=>{
 const calls=[];const h=harness(async(...args)=>{calls.push(args);return clients()});h.busy.value=true;h.go('mounts');await h.start();assert.equal(calls.length,0);h.busy.value=false;await h.start();await h.start();assert.equal(calls.length,1);assert.equal(calls[0][0],'/app-modules/nfs-manager/run');
});
test('failed or wrong-context reads retain the original report, show an error and never automatically retry',async()=>{
 for(const mode of ['rejected','wrong-context']){
  let calls=0;const h=harness(async()=>{calls++;if(mode==='rejected')throw Error('executor offline');return server()});const original=h.report.value;h.go('mounts');await settle();assert.equal(h.report.value,original);assert.equal(h.sectionReport('mounts'),undefined);assert.match(h.nfsSectionReadError.value,/读取当前 NFS 页面失败/);await h.start();assert.equal(calls,1);assert.equal(h.error.value,'Original mutation outcome remains unverified');
  h.setReport(clients());assert.equal(h.nfsSectionReadError.value,'');assert.deepEqual(h.sectionReport('mounts'),clients());
 }
});
test('logout, closing the dialog and installation changes invalidate and abort an old read',async()=>{
 for(const action of ['revoke','close','changeInstallation']){
  const d=deferred(),calls=[];const h=harness((...args)=>{calls.push(args);return d.promise});const original=h.report.value;h.go('mounts');h[action]();assert(calls[0][4].aborted);d.resolve(clients());await settle();assert.equal(h.report.value,original);assert.equal(h.busy.value,false);assert.equal(h.nfsSectionReadError.value,'');
 }
});
test('uninstalled, unknown and unauthorized contexts issue no background read',async()=>{
 for(const status of ['uninstalled','unknown','unauthorized']){
  let calls=0;const h=harness(async()=>{calls++;return clients()});if(status==='uninstalled')h.installed.value=false;if(status==='unknown')h.installedUnknown.value=true;if(status==='unauthorized')h.revoke();h.go('mounts');await h.start();assert.equal(calls,0);
 }
});
test('export forms label shared exports and readonly shares without changing mount form labels',()=>{
 const h=harness(async()=>clients());assert.equal(h.fieldLabel({key:'resource_id',label:'挂载名称'},{id:'export'}),'共享导出名称');assert.equal(h.fieldLabel({key:'read_only',label:'只读挂载'},{id:'export'}),'只读共享');assert.equal(h.fieldLabel({key:'resource_id',label:'挂载名称'},{id:'unmount'}),'挂载名称');
});
test('the actual Vue template compiles and keeps unrelated page scoping and cleanup wiring',()=>{
 assert.equal(parsed.errors.length,0);const compiled=sfc.compileTemplate({source:parsed.descriptor.template.content,filename:'AppModuleManager.vue',id:'nfs-report-scope'});assert.deepEqual(compiled.errors,[]);
 const h=harness(async()=>clients());const value=h.report.value;h.definition.value={id:'platform-ops'};assert.equal(h.sectionReport('host'),value);h.definition.value={id:'load-balance'};assert.deepEqual(h.sectionReport('transactions'),{section:'transactions',value});
 assert.match(manager,/watch\(busy, value => \{ if \(!value\) void startNFSSectionRead\(\)/);assert.match(manager,/onBeforeUnmount\(cancelNFSSectionRead\)/);
 assert.match(manager,/if \(inspection\) await execute\(inspection\);\s+if \(id === 'nfs-manager'/);assert.match(manager,/<\/section>\s*<p v-else-if="definition.id==='load-balance'"/);
});
