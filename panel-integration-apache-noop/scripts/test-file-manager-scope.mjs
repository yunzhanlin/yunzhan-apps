import test from 'node:test';import assert from 'node:assert/strict';import {readFileSync} from 'node:fs';
import ts from '../web/node_modules/typescript/lib/typescript.js';
import {ref,reactive,computed,watch,effectScope} from '../web/node_modules/vue/index.mjs';
const component=readFileSync(new URL('../web/src/FileManager.vue',import.meta.url),'utf8'),body=component.split('<script setup lang="ts">')[1].split('</script>')[0];
const ast=ts.createSourceFile('FileManager.ts',body,ts.ScriptTarget.Latest,true,ts.ScriptKind.TS),names=['fileDialogCurrent','resetSharedFileDialogs','loadMailSettings','openMailConfig','saveMailConfig','sendShareMail','openFileCloud','uploadFileCloud','loadFileShares','openFileShare','createFileShare','revokeFileShare'];
const selected=ast.statements.filter(n=>{
 if(ts.isFunctionDeclaration(n))return names.includes(n.name?.text);
 if(ts.isVariableStatement(n))return n.declarationList.declarations.some(d=>['canWriteSite','canReadDisk','canUseSharedInfrastructure','fileDialogEpoch','fileDialogsAlive'].includes(d.name.getText(ast)));
 if(!ts.isExpressionStatement(n)||!ts.isCallExpression(n.expression))return false;
 const callee=n.expression.expression.getText(ast),text=n.getText(ast);
 return callee==='onBeforeUnmount'||callee==='watch'&&(text.includes('props.csrf')||text.includes('watch(mailConfigOpen'));
});
assert.equal(selected.filter(ts.isFunctionDeclaration).length,names.length);
const js=ts.transpileModule(selected.map(n=>n.getText(ast)).join('\n'),{compilerOptions:{target:ts.ScriptTarget.ES2022,module:ts.ModuleKind.ESNext}}).outputText;
const menus=['overview','sites','databases','files','security','runtimes','schedules','monitor','terminal','panel-access','audit','system-tools'];
test('actual unauthorized empty state is distinct from an empty directory and cannot retain a removed site selection',()=>{
 assert(component.includes(`<el-empty v-if="!selected && !systemMode" :description="canReadSystem ? '先创建网站，再管理它的文件。' : '当前账户暂无已授权的可管理网站'" />`));
 const availableWatch=ast.statements.find(n=>ts.isExpressionStatement(n)&&ts.isCallExpression(n.expression)&&n.expression.expression.getText(ast)==='watch'&&n.expression.arguments[0]?.getText(ast)==='available');assert(availableWatch);
 const callback=availableWatch.expression.arguments[1].getText(ast),code=ts.transpileModule('const callback='+callback,{compilerOptions:{target:ts.ScriptTarget.ES2022}}).outputText;
 const b={siteID:{value:'old-site'},systemMode:{value:false},requestSequence:0,entries:{value:[{name:'old-private-file'}]},total:{value:1},clearPreview(){b.previewCleared=true;},props:{initialSiteID:''},recentSiteID(){return '';},selectSite(){assert.fail('empty authority selected a site');}};
 new Function('b','with(b){'+code+';callback([]);}')(b);assert.equal(b.siteID.value,'');assert.deepEqual(b.entries.value,[]);assert.equal(b.total.value,0);assert.equal(b.requestSequence,1);assert(b.previewCleared);
});
const deferred=()=>{let resolve,reject;const promise=new Promise((a,b)=>{resolve=a;reject=b});return {promise,resolve,reject};};
function fixture(api,confirm=async()=>{}){
 const messages=[],calls=[],scope=effectScope(),b={ref,computed,watch,props:reactive({csrf:'fixture-session-a',access:{role:'admin',menu_ids:[...menus]},api:(...args)=>{calls.push(args);return api(...args)}}),siteID:ref('a'.repeat(32)),systemMode:ref(false),ElMessage:Object.fromEntries(['success','warning','info'].map(k=>[k,v=>messages.push([k,v])])),ElMessageBox:{confirm},requestSequence:0,transfer:undefined,clearPreview(){},dismissContext(){},escapeContext(){},document:{removeEventListener(){}},onBeforeUnmount(fn){b.dispose=fn;}};
 for(const [k,v] of Object.entries({shareOpen:false,shareEntry:null,shareHours:24,shareBusy:false,shareError:'',shareURL:'',shareURLPath:'',shareList:[],mailSettings:null,mailConfigOpen:false,mailRecipient:'',mailBusy:false,mailError:'',mailDraft:{host:'',port:587,mode:'starttls',username:'',from:'',password:'',enabled:true},cloudOpen:false,cloudEntry:null,cloudRemotes:[],cloudRemoteID:'',cloudBusy:false,cloudError:'',cloudResult:null}))b[k]=ref(v);
 const methods=scope.run(()=>new Function('bindings','with(bindings){'+js+';return {'+names.join(',')+'};}')(b));
 return {b,methods,messages,calls,close(){try{b.dispose();}finally{scope.stop();}}};
}
test('actual Vue synchronous scope watch clears secrets and ignores cloud list replies from old site or account',async()=>{
 for(const change of [f=>{f.b.siteID.value='b'.repeat(32)},f=>{f.b.props.csrf='fixture-session-b'},f=>{f.b.props.access={role:'admin',menu_ids:['files']}}]){
  const d=deferred(),f=fixture(()=>d.promise);try{
   f.b.mailDraft.value.password='entered-fixture-only';const pending=f.methods.openFileCloud({kind:'file',path:'old.txt'});assert(f.b.cloudOpen.value);change(f);assert(!f.b.cloudOpen.value);assert.equal(f.b.mailDraft.value.password,'');
   d.resolve({remotes:[{id:'old-private-profile',enabled:true}]});await pending;assert.deepEqual(f.b.cloudRemotes.value,[]);assert.equal(f.b.cloudRemoteID.value,'');assert.equal(f.calls.length,1);
  }finally{f.close();}
 }
});
test('actual cloud write keeps original submitted site and late completion cannot clear a newer busy state',async()=>{
 const d=deferred(),f=fixture(()=>d.promise);try{
  f.b.cloudEntry.value={path:'source.txt'};f.b.cloudRemoteID.value='fixture-remote';const pending=f.methods.uploadFileCloud();assert.equal(f.calls[0][0],'/sites/'+'a'.repeat(32)+'/files/cloud-upload');
  f.b.siteID.value='b'.repeat(32);f.b.cloudBusy.value=true;d.resolve({remote_path:'old-private-path',bytes:4,sha256:'a'.repeat(64)});await pending;
  assert.equal(f.b.cloudResult.value,null);assert(f.b.cloudBusy.value);assert(!f.messages.some(([kind])=>kind==='success'));assert.equal(f.calls.length,1);
 }finally{f.close();}
});
test('actual share creation cannot publish an old bearer URL or refresh history under a replacement account',async()=>{
 const d=deferred(),f=fixture(()=>d.promise);try{
  f.b.shareEntry.value={path:'source.txt'};const pending=f.methods.createFileShare();f.b.props.csrf='fixture-session-b';
  d.resolve({public_url:'https://panel.example/share/old-capability',url_path:'/share/old-capability'});await pending;
  assert.equal(f.b.shareURL.value,'');assert.deepEqual(f.b.shareList.value,[]);assert.equal(f.calls.length,1);assert(!f.messages.some(([kind])=>kind==='success'));
 }finally{f.close();}
});
test('actual share revoke confirmation is one pending intent and cannot dispatch after site change',async()=>{
 const confirmation=deferred(),f=fixture(()=>assert.fail('stale confirmation dispatched'),()=>confirmation.promise);try{
  const pending=f.methods.revokeFileShare({id:'c'.repeat(32),name:'old.txt'});assert(f.b.shareBusy.value);
  await f.methods.revokeFileShare({id:'d'.repeat(32),name:'another.txt'});f.b.siteID.value='b'.repeat(32);confirmation.resolve();await pending;assert.equal(f.calls.length,0);
 }finally{f.close();}
});
test('actual SMTP read and write replies do not cross revoked authority or unmount; closing clears entered password',async()=>{
 const d=deferred(),f=fixture(()=>d.promise);try{
  const pending=f.methods.openMailConfig();f.b.props.access={role:'admin',menu_ids:['files']};d.resolve({host:'old-private-host',port:465,mode:'tls',username:'old-owner',from:'from@example.test',enabled:true});await pending;
  assert.equal(f.b.mailSettings.value,null);assert(!f.b.mailConfigOpen.value);
  await f.methods.loadMailSettings();assert.equal(f.calls.length,1);
 }finally{f.close();}
 const write=deferred(),g=fixture(()=>write.promise);try{
  g.b.mailConfigOpen.value=true;g.b.mailDraft.value.password='entered-only';g.b.mailConfigOpen.value=false;assert.equal(g.b.mailDraft.value.password,'');
  const pending=g.methods.saveMailConfig();g.b.dispose();write.resolve({host:'late'});await pending;assert.equal(g.b.mailSettings.value,null);assert(!g.messages.some(([kind])=>kind==='success'));
 }finally{g.close();}
});
test('actual site operator sharing does not query global SMTP or WebDAV profiles',async()=>{
 const f=fixture(async(url)=>{assert.equal(url,'/sites/'+'a'.repeat(32)+'/files/shares');return [];});try{
  f.b.props.access={role:'operator',menu_ids:['files']};await f.methods.openFileShare({kind:'file',path:'site.txt'});assert(f.b.shareOpen.value);assert.equal(f.calls.length,1);assert.equal(f.b.shareError.value,'');
  await f.methods.openFileCloud({kind:'file',path:'site.txt'});await f.methods.sendShareMail();assert.equal(f.calls.length,1);
 }finally{f.close();}
});
test('actual same-scope cloud and share callbacks still complete with truthful original results',async()=>{
 const result={remote_path:'https://storage.example.test/file',bytes:4,sha256:'a'.repeat(64)},f=fixture(async()=>result);try{
  f.b.cloudEntry.value={path:'site.txt'};f.b.cloudRemoteID.value='fixture-remote';await f.methods.uploadFileCloud();assert.deepEqual(f.b.cloudResult.value,result);assert(!f.b.cloudBusy.value);
 }finally{f.close();}
 const g=fixture(async(url,method)=>method==='POST'?{public_url:'https://panel.example/share/new',url_path:'/share/new'}:[]);try{
  g.b.shareEntry.value={path:'site.txt'};await g.methods.createFileShare();assert.equal(g.b.shareURL.value,'https://panel.example/share/new');assert.equal(g.calls.length,2);assert(!g.b.shareBusy.value);
 }finally{g.close();}
});
