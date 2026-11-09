import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {createRequire} from 'node:module';
import {createHash} from 'node:crypto';
import {beforeUnpublishedCopyBuild} from './release-build-baseline.mjs';
import ts from '../web/node_modules/typescript/lib/typescript.js';
import * as u from '../web/src/remoteUnpublishedCopy.ts';

const target='owned-target',actor='a'.repeat(32),tx='b'.repeat(32),digest='c'.repeat(64);
const fragment={name:'record-'+ 'd'.repeat(32)+'.part',bytes:17,sha256:'e'.repeat(64)};
const row={remote_target_id:target,backup_transaction_id:tx,revision:7,fragment_state:'unpublished-needs-review',snapshot_sha256:digest,retained_at:'',retained_bytes:17,fragments:[fragment],root_private:true,backup_complete:false,source_authority:false,downloadable:false};
const closed=()=>({...structuredClone(row),fragment_state:'unpublished-retained',retained_at:'2026-11-05T12:00:00Z',retained_bytes:1000});
const inventory=(rows=[structuredClone(row)])=>({unpublished_records:rows,total:rows.length,offset:0,limit:16,global_copies:rows.length,retained_bytes:0,unpublished_bytes:rows.reduce((n,r)=>n+r.retained_bytes,0),remote_files_changed:false});
const receipt=()=>({unpublished_record:closed(),original_fragments_preserved:true,backup_complete:false,remote_files_changed:false});
const clone=v=>structuredClone(v);
test('the new mandatory build gate is exactly additive to the complete original C63 build',()=>{
 const text=readFileSync(new URL('../packaging/build-release.sh',import.meta.url),'utf8');
 assert.equal(createHash('sha256').update(beforeUnpublishedCopyBuild(text)).digest('hex'),'e4d975a400b249fb85eb91b348453c6c19627acb1ae42fb7e0c400c31551ef38');
 const gate='(cd "$BUILD_ROOT" && /opt/homebrew/bin/node --test scripts/test-remote-unpublished-copy.mjs) 2>&1 | tee -a "$STAGE/$NAME/BUILD_CHECKS.txt"\n';
 for(const changed of[text.replace(gate,''),text.replace(gate,gate+gate),text.replace(gate,gate.replace('--test','--check')),text.replace(gate,'')+gate])assert.throws(()=>beforeUnpublishedCopyBuild(changed));
 assert.equal(beforeUnpublishedCopyBuild(text+'\n# unrelated source change'),beforeUnpublishedCopyBuild(text)+'\n# unrelated source change');
});
test('unpublished empty and opaque metadata never become source/copy authority',()=>{
 assert(u.unpublishedCopyValid(row,target,7));assert(u.unpublishedCopyValid(closed(),target,7));
 assert(u.unpublishedCopyValid({...row,fragments:[],retained_bytes:0},target,7));
 assert.deepEqual(u.unpublishedInventory(inventory(),target,7,0).rows,[row]);
 const body=u.unpublishedMutationBody(row,'RETAIN FRAGMENTS '+tx);
 assert.equal(body.expected_sha,digest);assert.deepEqual(Object.keys(body),['remote_target_id','expected_revision','resource_id','expected_sha','confirm']);
 assert.throws(()=>u.unpublishedMutationBody(row,'COPY BACKUP '+tx));assert.throws(()=>u.unpublishedMutationBody(closed(),'RETAIN FRAGMENTS '+tx));
});
for(const[name,edit]of Object.entries({
 other_target:v=>v.remote_target_id='other-target',other_revision:v=>v.revision++,unsafe_transaction:v=>v.backup_transaction_id='../unknown',array_digest:v=>v.snapshot_sha256=[digest],invented_state:v=>v.fragment_state='committed',invented_source:v=>v.source_authority=true,success_claim:v=>v.backup_complete=true,download_claim:v=>v.downloadable=true,missing_private:v=>delete v.root_private,duplicate_part:v=>{v.fragments.push(clone(fragment));v.retained_bytes+=17},unsafe_name:v=>v.fragments[0].name='../record-'+ 'd'.repeat(32)+'.part',oversize_part:v=>v.fragments[0].bytes=32769,array_file_digest:v=>v.fragments[0].sha256=[fragment.sha256],unaccounted_bytes:v=>v.retained_bytes++,unbounded_parts:v=>v.fragments=Array(9).fill(fragment),unknown_time:v=>v.retained_at='2026-11-05T12:00:00Z',
}))test('rejects unbound unpublished record: '+name,()=>{const v=clone(row);edit(v);assert.equal(u.unpublishedCopyValid(v,target,7),false)});
test('retained state requires a valid timestamp and separately bounded original receipt bytes',()=>{
 for(const edit of[v=>v.retained_at='',v=>v.retained_bytes=17,v=>v.retained_bytes=32786,v=>v.fragment_state='success']){const v=closed();edit(v);assert(!u.unpublishedCopyValid(v,target,7));}
});
test('incomplete or malformed inventory is rejected instead of becoming an empty success',()=>{
 for(const edit of[v=>v.total=2,v=>v.global_copies=0,v=>v.global_copies=129,v=>v.offset=16,v=>v.limit=32,v=>v.unpublished_records.push(clone(row)),v=>delete v.unpublished_bytes,v=>v.unpublished_bytes=128*9*32768+1,v=>v.remote_files_changed=true]){const v=inventory();edit(v);assert.throws(()=>u.unpublishedInventory(v,target,7,0));}
 assert.throws(()=>u.unpublishedInventory(inventory(),target,7,-1));
});
test('retention acknowledgement binds the original transaction, snapshot and false authority flags',()=>{
 assert(u.unpublishedReply(receipt(),target,7,tx,digest));
 for(const edit of[v=>v.original_fragments_preserved=false,v=>v.backup_complete=true,v=>v.remote_files_changed=true,v=>v.unpublished_record.snapshot_sha256='f'.repeat(64),v=>v.unpublished_record.revision++,v=>v.unpublished_record.fragment_state='unpublished-needs-review']){const v=receipt();edit(v);assert.throws(()=>u.unpublishedReply(v,target,7,tx,digest));}
});
test('an original pending condition cannot become another actor or another action',()=>{
 const p={actor,target,revision:7,transaction:tx,sha256:digest,action:'retain-remote-copy-fragments'};
 assert(u.unpublishedPendingValid(p,actor));assert(!u.unpublishedPendingValid(p,'f'.repeat(32)));assert(!u.unpublishedPendingValid({...p,action:'copy-remote-backup'},actor));
});

const require=createRequire(new URL('../web/package.json',import.meta.url)),{parse,compileScript}=require('@vue/compiler-sfc'),{createRenderer,defineComponent,h,nextTick}=require('vue');
const data=code=>'data:text/javascript;base64,'+Buffer.from(code).toString('base64');
const compile=code=>ts.transpileModule(code,{compilerOptions:{target:ts.ScriptTarget.ES2022,module:ts.ModuleKind.ESNext}}).outputText;
const menu=data(compile(readFileSync(new URL('../web/src/menuPermissions.ts',import.meta.url),'utf8')));
let backup=compile(readFileSync(new URL('../web/src/remoteIndependentBackup.ts',import.meta.url),'utf8')).replaceAll("'./menuPermissions'",JSON.stringify(menu));
for(const dep of['@noble/hashes/sha2.js','@noble/hashes/utils.js'])backup=backup.replaceAll("'"+dep+"'",JSON.stringify(new URL('../web/node_modules/'+dep,import.meta.url).href));
const backupURL=data(backup),unpublishedURL=data(compile(readFileSync(new URL('../web/src/remoteUnpublishedCopy.ts',import.meta.url),'utf8')));
let js=compile(compileScript(parse(readFileSync(new URL('../web/src/RemoteUnpublishedFragments.vue',import.meta.url),'utf8')).descriptor,{id:'qa-unpublished-copy',inlineTemplate:true}).content);
js=js.replace(/from ['"]vue['"]/g,'from '+JSON.stringify(new URL('../web/node_modules/vue/index.mjs',import.meta.url).href)).replace(/from ['"]\.\/remoteIndependentBackup['"]/g,'from '+JSON.stringify(backupURL)).replace(/from ['"]\.\/remoteUnpublishedCopy['"]/g,'from '+JSON.stringify(unpublishedURL));
const component=(await import(data(js))).default,{menuPermissionIDs}=await import(menu);
const flush=async()=>{await nextTick();await Promise.resolve();await nextTick();};
function node(type,text=''){return{type,text,props:{},children:[],parent:null};}
function harness(initial={},storage=new Map()){
 const requests=[],warnings=[],events=[];
 globalThis.sessionStorage={getItem:k=>storage.get(k)??null,setItem:(k,v)=>storage.set(k,v),removeItem:k=>storage.delete(k)};
 const insert=(child,parent,anchor=null)=>{if(child.parent){const i=child.parent.children.indexOf(child);if(i>=0)child.parent.children.splice(i,1);}child.parent=parent;const at=anchor?parent.children.indexOf(anchor):-1;parent.children.splice(at<0?parent.children.length:at,0,child);};
 const renderer=createRenderer({createElement:t=>node(t),createText:t=>node('#text',t),createComment:t=>node('#comment',t),setText:(n,t)=>{n.text=t},setElementText:(n,t)=>{n.children=[];n.text=t},patchProp:(n,k,_old,v)=>{n.props[k]=v},insert,remove:n=>{if(n.parent){const i=n.parent.children.indexOf(n);if(i>=0)n.parent.children.splice(i,1)}n.parent=null},parentNode:n=>n.parent,nextSibling:n=>n.parent?.children[n.parent.children.indexOf(n)+1]||null,insertStaticContent:(t,p,a)=>{const n=node('#static',t);insert(n,p,a);return[n,n]}});
 const root=node('root'),props={api:(path,method,body,_key,signal)=>new Promise((resolve,reject)=>requests.push({path,method,body,signal,resolve,reject})),actor,access:{role:'admin',menu_ids:[...menuPermissionIDs]},active:true,installedVersion:'2.0.1',connection:{id:target,revision:7},onRetained:r=>events.push(r),...initial};
 const app=renderer.createApp(component,props);app.config.warnHandler=message=>warnings.push(message);
 for(const name of['el-alert','el-input','el-button'])app.component(name,defineComponent({inheritAttrs:false,setup(_,{attrs,slots}){return()=>h(name,{...attrs},slots.default?.())}}));
 const vm=app.mount(root),all=type=>{const out=[];const walk=n=>{if(n.type===type)out.push(n);for(const child of n.children)walk(child)};walk(root);return out;},text=n=>n.text+n.children.map(text).join('');
 const button=label=>{const n=all('el-button').find(n=>text(n).trim()===label);assert(n,'Missing button: '+label);return n;};
 const update=(n,v)=>{assert.equal(typeof n.props['onUpdate:modelValue'],'function');n.props['onUpdate:modelValue'](v)};
 return{requests,events,storage,all,root,text,button,update,
  async change(next){Object.assign(vm.$.props,next);await flush();},
  async refresh(){void button('离线核对未发布原片段').props.onClick();await flush();},
  async resolve(index,value){requests[index].resolve(value);await flush();},
  async reject(index,message='response lost'){requests[index].reject(Error(message));await flush();},
  async select(){const n=all('button').find(n=>text(n).includes(tx));assert(n);n.props.onClick();await flush();},
  async confirm(value){const n=all('el-input').find(n=>n.props['aria-label']==='未发布原片段精确确认');assert(n);update(n,value);await flush();},
  async retryConfirm(value){const n=all('el-input').find(n=>n.props['aria-label']==='原片段条件重试确认');assert(n);update(n,value);await flush();},
  stop(){app.unmount();assert.deepEqual(warnings,[]);},
 };
}
test('actual Vue stays read-only until an explicit review and exact confirmation',async()=>{
 const ui=harness();try{await flush();assert.equal(ui.requests.length,0);await ui.refresh();assert.equal(ui.requests.length,1);assert.equal(ui.requests[0].path,'/app-modules/files-sync/remote-copy-fragments');await ui.resolve(0,inventory());await ui.select();assert(ui.button('明确保留原片段 · 不视为成功').props.disabled);await ui.confirm('COPY BACKUP '+tx);assert(ui.button('明确保留原片段 · 不视为成功').props.disabled);await ui.confirm('RETAIN FRAGMENTS '+tx);assert.equal(ui.button('明确保留原片段 · 不视为成功').props.disabled,false);void ui.button('明确保留原片段 · 不视为成功').props.onClick();await flush();assert.equal(ui.requests.length,2);assert.deepEqual(ui.requests[1].body,u.unpublishedMutationBody(row,'RETAIN FRAGMENTS '+tx));await ui.resolve(1,receipt());assert.equal(ui.events.length,1);assert(ui.text(ui.root).includes('不是成功备份'));}finally{ui.stop()}
});
test('actual Vue preserves a lost response and acknowledges only a matching read-only retained receipt',async()=>{
 const ui=harness();try{await ui.refresh();await ui.resolve(0,inventory());await ui.select();await ui.confirm('RETAIN FRAGMENTS '+tx);void ui.button('明确保留原片段 · 不视为成功').props.onClick();await flush();await ui.reject(1);assert(ui.text(ui.root).includes('结果待核对'));assert.equal(ui.events.length,0);assert.equal(ui.requests.length,2);await ui.refresh();await ui.resolve(2,inventory([closed()]));assert.equal(ui.events.length,1);assert.equal(ui.requests.filter(r=>r.path.endsWith('/retain-remote-copy-fragments')).length,1);assert.equal(ui.storage.has('yunzhan-unpublished-retention-pending-v1/'+actor),false);}finally{ui.stop()}
});
test('actual Vue discards a late inventory after actor and permission changes',async()=>{
 const ui=harness();try{await ui.refresh();await ui.change({actor:'f'.repeat(32),access:{role:'viewer',menu_ids:[]}});assert(ui.requests[0].signal.aborted);await ui.resolve(0,inventory());assert.equal(ui.all('button').length,0);assert.equal(ui.events.length,0);assert.equal(ui.button('离线核对未发布原片段').props.disabled,true);}finally{ui.stop()}
});
test('actual Vue exposes no forensic requests for the old installed package',async()=>{
 const ui=harness({installedVersion:'2.0.0'});try{await flush();assert.equal(ui.requests.length,0);assert.equal(ui.all('section').length,0);}finally{ui.stop()}
});
test('actual Vue rejects a forged acknowledgement while retaining the original conditional request',async()=>{
 const ui=harness();try{await ui.refresh();await ui.resolve(0,inventory());await ui.select();await ui.confirm('RETAIN FRAGMENTS '+tx);void ui.button('明确保留原片段 · 不视为成功').props.onClick();await flush();const bad=receipt();bad.unpublished_record.snapshot_sha256='f'.repeat(64);await ui.resolve(1,bad);assert.equal(ui.events.length,0);assert(ui.storage.has('yunzhan-unpublished-retention-pending-v1/'+actor));assert(ui.all('el-alert').some(n=>String(n.props.title).includes('尚未完整核对')));}finally{ui.stop()}
});
test('actual Vue retries only the explicitly confirmed original condition after a lost response',async()=>{
 const ui=harness();try{await ui.refresh();await ui.resolve(0,inventory());await ui.select();await ui.confirm('RETAIN FRAGMENTS '+tx);void ui.button('明确保留原片段 · 不视为成功').props.onClick();await flush();const original=clone(ui.requests[1].body);await ui.reject(1);assert(ui.button('按原条件明确重试').props.disabled);await ui.retryConfirm('RETRY FRAGMENTS '+tx);assert.equal(ui.button('按原条件明确重试').props.disabled,false);void ui.button('按原条件明确重试').props.onClick();await flush();assert.equal(ui.requests.length,3);assert.deepEqual(ui.requests[2].body,original);await ui.resolve(2,receipt());assert.equal(ui.events.length,1);assert.equal(ui.requests.filter(r=>r.path.endsWith('/retain-remote-copy-fragments')).length,2);}finally{ui.stop()}
});
test('actual Vue preserves a superseded original condition and releases it only after an explicit server revision check',async()=>{
 const pending={actor,target,revision:6,transaction:tx,sha256:digest,action:'retain-remote-copy-fragments'},key='yunzhan-unpublished-retention-pending-v1/'+actor,storage=new Map([[key,JSON.stringify(pending)]]),ui=harness({},storage);
 try{await flush();assert.equal(ui.requests.length,0);assert(ui.button('按原条件明确重试').props.disabled);void ui.button('核对并保留已失效条件').props.onClick();await flush();assert.equal(ui.requests[0].path,'/app-modules/files-sync/remote-targets');await ui.resolve(0,{remote_targets:[{id:target,remote_target_id:target,revision:7}]});assert.deepEqual(JSON.parse(storage.get(key+'/superseded')),[pending]);assert.equal(storage.has(key),false);assert.equal(ui.events.length,0);assert.equal(ui.requests.length,1);assert(ui.all('el-alert').some(n=>String(n.props.title).includes('未判定原操作成功')));}finally{ui.stop()}
});
