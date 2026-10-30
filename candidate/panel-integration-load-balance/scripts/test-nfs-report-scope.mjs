import {test} from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {createRequire} from 'node:module';
import ts from '../web/node_modules/typescript/lib/typescript.js';
const require=createRequire(import.meta.url),sfc=require('../web/node_modules/@vue/compiler-sfc/dist/compiler-sfc.cjs.js');
async function load(name){const source=readFileSync(new URL('../web/src/'+name+'.ts',import.meta.url),'utf8');return import('data:text/javascript;base64,'+Buffer.from(ts.transpileModule(source,{compilerOptions:{target:ts.ScriptTarget.ES2022,module:ts.ModuleKind.ESNext}}).outputText).toString('base64'));}
const drafts=await load('nfsFormDrafts'),scope=await load('nfsReportScope'),permissions=await load('menuPermissions'),provenance=await load('moduleReportProvenance');
const manager=readFileSync(new URL('../web/src/AppModuleManager.vue',import.meta.url),'utf8'),parsed=sfc.parse(manager),source=parsed.descriptor.scriptSetup.content;
const ast=ts.createSourceFile('AppModuleManager.ts',source,ts.ScriptTarget.Latest,true,ts.ScriptKind.TS);
const wanted=['activateNFSDraft','observeNFSConfig','selected','sectionReport','nfsReadCurrent','queueNFSSectionRead','startNFSSectionRead','cancelNFSSectionRead','fieldLabel','setReport'];
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
  const nfsFormDrafts=new deps.drafts.NFSFormDrafts();nfsFormDrafts.observe(report.value.config);
  const clearWriteOnlyFields=()=>{},ElMessage={info(){},error(){}};
  const props={api:deps.api,access:undefined},platformHealthSnapshot={remember(){throw Error('NFS must not mutate another application cache')}},platformSnapshotContext=()=>undefined;
  const loadBalanceReportForSection=(section,value)=>({section,value});
  ${actual}
  return{definition,installed,installedUnknown,installedInstance,installedVersion,visible,busy,activeTab,report,form,error,nfsSectionReadError,nfsSectionRead,
   go(section){activeTab.value=section;activateNFSDraft(section);queueNFSSectionRead(section)},selected,start:startNFSSectionRead,sectionReport,fieldLabel,setReport,
   revoke(){props.access=null;idsAccessGeneration++;cancelNFSSectionRead()},close(){visible.value=false;cancelNFSSectionRead()},
   changeInstallation(){installedInstance.value='b'.repeat(32);cancelNFSSectionRead()}};
 `)({drafts,scope,permissions,provenance,server,api});
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
 assert.equal(calls.length,1);assert.deepEqual(calls[0].slice(0,4),['/app-modules/nfs-manager/run','POST',{},undefined]);assert(calls[0][4]instanceof AbortSignal);assert(!h.form.value.confirm);
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

test('selecting a writable export cannot contaminate the actual remote mount or unmount form',async()=>{
 const calls=[],h=harness(async(...args)=>{calls.push(args);return clients()});
 h.selected({...server().config.exports[0],resource_id:'share-one'});
 assert.equal(h.activeTab.value,'export');assert.equal(h.form.value.read_only,false);assert.equal(h.form.value.resource_id,'share-one');
 h.go('mount');await settle();
 assert.deepEqual(h.form.value,{resource_id:'',source:'',port:2049,read_only:true});
 h.form.value.resource_id='client-two';h.form.value.source='[::1]:/share-one';h.form.value.port=24270;
 h.go('unmount');assert.deepEqual(h.form.value,{resource_id:''});
 h.go('mount');assert.deepEqual(h.form.value,{resource_id:'client-two',source:'[::1]:/share-one',port:24270,read_only:true});
 h.go('export');await settle();assert.equal(h.form.value.resource_id,'share-one');assert.equal(h.form.value.read_only,false);
 h.go('export-remove');assert.deepEqual(h.form.value,{resource_id:'share-one',expected_revision:9});
 assert(calls.every(call=>['/app-modules/nfs-manager/run','/app-modules/nfs-manager/server-report'].includes(call[0])));
});
test('readonly server observations update pristine listener drafts but preserve remote port and dirty revision',()=>{
 const d=new drafts.NFSFormDrafts();d.observe(server().config);
 const listener=d.activate('listener');assert.equal(listener.port,24249);listener.port=24250;listener.confirm='EXPOSE NFS [::1]:24250';
 const exported=d.activate('export');assert.equal(listener.confirm,'');exported.resource_id='draft-new';
 const mount=d.activate('mount');mount.port=24300;mount.read_only=false;
 d.observe({...server().config,revision:10,port:24260});
 assert.equal(listener.port,24250);assert.equal(listener.expected_revision,9);assert.equal(exported.expected_revision,9);assert.equal(mount.port,24300);assert.equal(mount.read_only,false);
 const pristine=new drafts.NFSFormDrafts();const untouched=pristine.activate('listener');pristine.observe(server().config);assert.equal(untouched.port,24249);assert.equal(untouched.expected_revision,9);
});
test('only an unchanged acknowledged operation may advance its own draft revision',()=>{
 const d=new drafts.NFSFormDrafts();d.observe(server().config);const listener=d.activate('listener');listener.port=24250;
 const original=d.submission('listener','server-config');assert(original);assert.equal(d.submission('mount','mount'),undefined);
 d.observe({...server().config,port:24250,revision:10},original);assert.equal(listener.expected_revision,10);assert.equal(listener.port,24250);
 const next=d.submission('listener','server-config');listener.port=24251;d.observe({...server().config,port:24250,revision:11},next);assert.equal(listener.expected_revision,10);assert.equal(listener.port,24251);
});
test('closing, logout and installation replacement discard every NFS draft and require fresh confirmation',async()=>{
 for(const action of ['close','revoke','changeInstallation']){
  const h=harness(async()=>clients());h.selected({...server().config.exports[0],resource_id:'share-one'});h.form.value.confirm='SHARE RW share-one';h.go('mount');await settle();h.form.value.source='[::1]:/share-one';h.form.value.read_only=false;h[action]();
  h.go('mount');assert.deepEqual(h.form.value,{resource_id:'',source:'',port:2049,read_only:true});h.go('export');assert.equal(h.form.value.resource_id,'');assert.equal(h.form.value.confirm,'');
 }
});
test('remote port label and real Vue reactive draft values follow observation without crossing operations',async()=>{
 const vue=await import('../web/node_modules/vue/dist/vue.runtime.esm-bundler.js');const d=new drafts.NFSFormDrafts(value=>vue.reactive(value));const listener=d.activate('listener'),port=vue.computed(()=>listener.port);assert.equal(port.value,2049);d.observe(server().config);assert.equal(port.value,24249);const mount=d.activate('mount');d.observe({...server().config,port:24255,revision:10});assert.equal(port.value,24255);assert.equal(mount.port,2049);
 const h=harness(async()=>clients());assert.equal(h.fieldLabel({key:'port',label:'NFSv4 监听端口'},{id:'mount'}),'远程 NFSv4 端口');
 assert.match(manager,/watch\(activeTab, activateNFSDraft, \{flush: 'sync'\}\)/);assert.match(manager,/nfsFormDrafts.reset\(\)/);
});

test('a selected export keeps its CAS revision after save until selected again, even if unchanged',()=>{
 const d=new drafts.NFSFormDrafts();d.observe(server().config);const row={...server().config.exports[0],resource_id:'share-one'};d.select(row);const value=d.activate('export'),submitted=d.submission('export','export-save');d.observe({...server().config,revision:10},submitted);assert.equal(value.expected_revision,10);d.observe({...server().config,revision:11});assert.equal(value.expected_revision,10);d.select(row);assert.equal(value.expected_revision,11);
 for(const invalid of [{...row,read_only:'false'},{...row,site_id:'bad'},{...row,clients:'::1'},{...row,clients:[]}])assert.equal(d.select(invalid),undefined);
});
