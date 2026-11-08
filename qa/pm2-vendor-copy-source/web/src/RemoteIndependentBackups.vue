<script setup lang="ts">
import {computed,onBeforeUnmount,ref,shallowRef,watch} from 'vue';
import type {AccessPlan} from './menuPermissions';
import {independentBackupSupported,independentCopyValid,independentDownload,independentFullAdministrator,independentMutationBody,independentPendingValid,independentReplyCopy,independentSourceValid,independentStateLabels,type IndependentAPI,type IndependentCopy,type IndependentFile,type IndependentPending,type IndependentSource} from './remoteIndependentBackup';
import RemoteUnpublishedFragments from './RemoteUnpublishedFragments.vue';
import {unpublishedCopyValid,type UnpublishedCopy} from './remoteUnpublishedCopy';

const props=defineProps<{api:IndependentAPI;actor:string;access?:AccessPlan|null;active:boolean;installed:boolean;installedVersion?:string}>();
type Target={id:string;revision:number;enabled:boolean;host_key_fingerprint:string};
const targets=shallowRef<Target[]>([]),target=ref(''),copies=shallowRef<IndependentCopy[]>([]),sources=shallowRef<IndependentSource[]>([]);
const selected=shallowRef<IndependentCopy>(),reviewed=shallowRef<IndependentSource>(),pending=shallowRef<IndependentPending>();
const busy=ref(false),error=ref(''),notice=ref(''),confirmation=ref(''),mode=ref<'copy-remote-backup'|'recover-remote-copy'|'retain-remote-copy'>('copy-remote-backup');
const localPage=ref(0),sourcePage=ref(0),localTotal=ref<number>(),sourceTotal=ref<number>(),globalCount=ref<number>(),globalBytes=ref<number>(),downloadProgress=ref('');
let generation=0,controller:AbortController|undefined;
const readable=computed(()=>props.active&&props.installed&&independentBackupSupported(props.installedVersion)&&/^[a-f0-9]{32}$/.test(props.actor)&&independentFullAdministrator(props.access));
const connection=computed(()=>targets.value.find(v=>v.id===target.value));
const mutationRow=computed(()=>mode.value==='copy-remote-backup'?reviewed.value:selected.value);
const phrase=computed(()=>{const tx=mutationRow.value?.backup_transaction_id;if(!tx)return '';return `${mode.value==='copy-remote-backup'?'COPY BACKUP ':mode.value==='recover-remote-copy'?'RECOVER COPY ':'RETAIN COPY '}${tx}`});
const canSubmit=computed(()=>{if(!readable.value||busy.value||pending.value||!mutationRow.value)return false;try{independentMutationBody(mode.value,mutationRow.value,confirmation.value);return true}catch{return false}});
function storageKey(actor:string){return `yunzhan-independent-backup-pending-v1/${actor}`}
function remember(value:IndependentPending){pending.value=value;try{sessionStorage.setItem(storageKey(value.actor),JSON.stringify(value))}catch{notice.value='浏览器未保存原请求；当前页面保留其标识，服务器原记录不会删除。'}}
function forget(){const value=pending.value;pending.value=undefined;if(value)try{sessionStorage.removeItem(storageKey(value.actor))}catch{/* Only the browser observation is removed. */}}
function stop(){generation++;controller?.abort();controller=undefined;busy.value=false;selected.value=undefined;reviewed.value=undefined;confirmation.value='';downloadProgress.value=''}
function chooseConnection(){stop();copies.value=[];sources.value=[];localTotal.value=sourceTotal.value=undefined;localPage.value=sourcePage.value=0;error.value='';notice.value='当前连接尚未刷新库存；打开页面不会复制或连接远端。'}
function bytes(n:number|undefined){return n===undefined?'尚未核对':n<1024?`${n} B`:`${(n/1024/1024).toFixed(2)} MiB`}
async function run(task:(request:AbortController,current:()=>boolean)=>Promise<void>){
 if(!readable.value||busy.value)return;
 const epoch=generation,actor=props.actor,chosen=target.value,request=new AbortController();controller=request;busy.value=true;error.value='';
 const current=()=>epoch===generation&&actor===props.actor&&chosen===target.value&&readable.value&&!request.signal.aborted;
 try{await task(request,current)}catch(e){if(current())error.value=e instanceof Error?e.message:String(e)}finally{if(epoch===generation){busy.value=false;controller=undefined;downloadProgress.value=''}}
}
async function refreshTargets(){
 await run(async(request,current)=>{
  const value=await props.api<any>('/app-modules/files-sync/remote-targets','POST',{},undefined,request.signal);
  if(!current())return;
  if(!Array.isArray(value?.remote_targets)||value.remote_targets.length>16)throw Error('连接清单不完整，未沿用旧修订号');
  const seen=new Set<string>(),out:Target[]=[];
  for(const row of value.remote_targets){if(!row||typeof row.id!=='string'||!/^[a-z0-9][a-z0-9-]{2,63}$/.test(row.id)||row.remote_target_id!==row.id||seen.has(row.id)||!Number.isSafeInteger(row.revision)||row.revision<1||row.revision>1e9||typeof row.enabled!=='boolean'||typeof row.host_key_fingerprint!=='string'||!row.host_key_fingerprint.startsWith('SHA256:'))throw Error('连接身份或修订号无法核对');seen.add(row.id);out.push({id:row.id,revision:row.revision,enabled:row.enabled,host_key_fingerprint:row.host_key_fingerprint})}
  const old=connection.value?.revision;targets.value=out;
  if(old!==connection.value?.revision){copies.value=[];sources.value=[];selected.value=reviewed.value=undefined;localTotal.value=sourceTotal.value=undefined;confirmation.value=''}
  notice.value=out.length?'已只读刷新本机连接配置；尚未连接远端。':'尚无受限 SFTP 连接，请先在“跨服务器 SFTP 连接”登记。';
  if(pending.value){const cfg=out.find(v=>v.id===pending.value!.target);if(cfg&&cfg.revision!==pending.value.revision){forget();notice.value='连接修订已变化，原条件请求已失效；服务器原记录保留，请刷新实际库存核对，不据此判定备份成功。'}}
 });
}
async function localInventory(request:AbortController,current:()=>boolean){
 const cfg=connection.value;if(!cfg)throw Error('先选择已核对的连接');
 const value=await props.api<any>('/app-modules/files-sync/remote-copies','POST',{remote_target_id:cfg.id,expected_revision:cfg.revision,limit:16,offset:localPage.value*16},undefined,request.signal);
 if(!current())return;
 if(!Array.isArray(value?.independent_backups)||value.independent_backups.length>16||!Number.isSafeInteger(value.total)||value.total<0||value.total>128||!Number.isSafeInteger(value.global_copies)||value.global_copies<value.total||value.global_copies>128||!Number.isSafeInteger(value.retained_bytes)||value.retained_bytes<0||value.retained_bytes>1024**3||value.remote_files_changed!==false||value.offset!==localPage.value*16||value.limit!==16||!value.independent_backups.every((v:unknown)=>independentCopyValid(v,cfg.id,cfg.revision)))throw Error('本机独立副本库存不能完整核对，未显示为备份成功');
 const ids=new Set(value.independent_backups.map((r:IndependentCopy)=>r.backup_transaction_id));if(ids.size!==value.independent_backups.length)throw Error('独立备份库存含重复身份');
 copies.value=value.independent_backups;localTotal.value=value.total;globalCount.value=value.global_copies;globalBytes.value=value.retained_bytes;
 selected.value=undefined;reviewed.value=undefined;confirmation.value='';
 const ticket=pending.value;
 if(ticket&&ticket.target===cfg.id){
  const row=copies.value.find(r=>r.backup_transaction_id===ticket.transaction);
  if(row){
   if(ticket.action==='copy-remote-backup'&&row.source_snapshot_sha256!==ticket.sha256)throw Error('原请求与已保留副本的源摘要不一致，未解除待核对状态');
   if(ticket.action==='copy-remote-backup'||row.copy_state_sha256!==ticket.sha256||row.independent_copy_state!=='needs-review'||cfg.revision!==ticket.revision){forget();notice.value='已核对原请求对应的实际副本状态，没有重发操作。请选中记录查看完整核验或恢复选项。'}
   else notice.value='原条件尚未见到状态变化；结果仍待核对。可以继续只读刷新，或明确重试同一条件请求；状态改变后迟到请求会被拒绝。';
  }else notice.value='本页尚未找到原请求回执；不据此判定未执行，也不会自动重传。请按原事务核对其他分页。';
 }else notice.value='已离线读取本机库存元数据；“已保存”不代表本次完整内容核验通过。';
}
async function refreshLocal(){await run(localInventory)}
async function refreshSources(){
 await run(async(request,current)=>{
  const cfg=connection.value;if(!cfg)throw Error('先选择已核对的连接');
  const value=await props.api<any>('/app-modules/files-sync/remote-backup-archive','POST',{remote_target_id:cfg.id,expected_revision:cfg.revision,limit:16,offset:sourcePage.value*16},undefined,request.signal);
  if(!current())return;
  if(!Array.isArray(value?.remote_backup_archive)||value.remote_backup_archive.length>16||!Number.isSafeInteger(value.total)||value.total<0||value.total>512||value.remote_files_changed!==false||value.offset!==sourcePage.value*16||value.limit!==16)throw Error('远端归档分页无法核对');
  // Noncommitted records remain visible in their existing recovery workspace;
  // they never become a copy source merely by appearing in this inventory.
  const out:IndependentSource[]=[];
  for(const row of value.remote_backup_archive){if(row?.backup_archive_state!=='committed')continue;if(!independentSourceValid(row,cfg.id,cfg.revision))throw Error('已提交远端归档身份无法核对');out.push(row)}
  sources.value=out;sourceTotal.value=value.total;selected.value=reviewed.value=undefined;confirmation.value='';notice.value='已查询远端归档元数据。选择已提交记录后，还须完整核对原件；未开始复制。';
 });
}
async function review(row:IndependentSource){
 await run(async(request,current)=>{
  const cfg=connection.value;if(!cfg||!independentSourceValid(row,cfg.id,cfg.revision))throw Error('所选远端归档已变化');
  selected.value=reviewed.value=undefined;confirmation.value='';
  const value=await props.api<any>('/app-modules/files-sync/remote-copy-preview','POST',{remote_target_id:cfg.id,expected_revision:cfg.revision,resource_id:row.backup_transaction_id},undefined,request.signal);
  if(!current())return;
  if(value?.remote_files_changed!==false)throw Error('原件核对回执无法确认');
  if(independentCopyValid(value.independent_backup,cfg.id,cfg.revision)){selected.value=value.independent_backup;mode.value='recover-remote-copy';notice.value='此原事务已有本机副本；保留原记录，未重新复制。';return}
  if(!independentSourceValid(value.independent_backup,cfg.id,cfg.revision)||value.independent_backup.backup_transaction_id!==row.backup_transaction_id||value.independent_backup.backup_snapshot_sha256!==row.backup_snapshot_sha256||value.source_content_verified===false||value.independent_backup.source_content_verified!==true||value.independent_backup.content_verified!==true)throw Error('所选原归档完整内容未核对通过');
  reviewed.value=value.independent_backup;mode.value='copy-remote-backup';notice.value='原远端归档完整摘要已核对；等待明确创建本机独立副本。';
 });
}
function select(row:IndependentCopy){if(busy.value)return;selected.value={...row,content_verified:false};reviewed.value=undefined;confirmation.value='';mode.value='recover-remote-copy';error.value=''}
function unpublishedRetained(row:UnpublishedCopy){
 const cfg=connection.value,ticket=pending.value;
 if(!cfg||!unpublishedCopyValid(row,cfg.id,cfg.revision)||row.fragment_state!=='unpublished-retained')return;
 if(ticket?.action==='copy-remote-backup'&&ticket.actor===props.actor&&ticket.target===cfg.id&&ticket.transaction===row.backup_transaction_id){
  // The retained original directory permanently blocks the old create intent.
  // This only resolves the browser observation; it is never a copy receipt.
  forget();notice.value='原创建请求对应的目录已明确保留为未发布片段；原条件不能覆盖该目录。未声明备份成功，请从其他完整归档建立新副本。';
 }
 copies.value=[];selected.value=reviewed.value=undefined;localTotal.value=undefined;confirmation.value='';
}
async function verify(){
 const row=selected.value;if(!row)return;
 await run(async(request,current)=>{
  selected.value={...row,content_verified:false};
  const value=await props.api<unknown>('/app-modules/files-sync/verify-remote-copy','POST',{remote_target_id:row.remote_target_id,expected_revision:row.revision,resource_id:row.backup_transaction_id},undefined,request.signal);
  if(!current())return;const verified=independentReplyCopy(value,row.remote_target_id,row.revision,row.backup_transaction_id);
  if(!verified.content_verified||verified.copy_intent_sha256!==row.copy_intent_sha256||verified.copy_state_sha256!==row.copy_state_sha256)throw Error('原独立副本状态改变，未沿用旧核验');
  selected.value=verified;notice.value='本机独立副本全部文件摘要已核验通过；本次未连接远端。';
 });
}
async function submit(original?:IndependentPending){
 const row=mutationRow.value;if(!original&&(!row||!canSubmit.value))return;
 let body:ReturnType<typeof independentMutationBody>,action:IndependentPending['action'];
 if(original){if(!pending.value||!independentPendingValid(original,props.actor)||connection.value?.id!==original.target||connection.value.revision!==original.revision||confirmation.value!==`RETRY COPY ${original.transaction}`)return;action=original.action;body={remote_target_id:original.target,expected_revision:original.revision,resource_id:original.transaction,expected_sha:original.sha256,confirm:`${action==='copy-remote-backup'?'COPY BACKUP ':action==='recover-remote-copy'?'RECOVER COPY ':'RETAIN COPY '}${original.transaction}`}}
 else{action=mode.value;body=independentMutationBody(action,row!,confirmation.value)}
 await run(async(request,current)=>{
  remember({actor:props.actor,target:body.remote_target_id,revision:body.expected_revision,transaction:body.resource_id,sha256:body.expected_sha,action});
  const value=await props.api<unknown>('/app-modules/files-sync/'+action,'POST',body,undefined,request.signal);
  if(!current())return;const result=independentReplyCopy(value,body.remote_target_id,body.expected_revision,body.resource_id);
  if(action==='retain-remote-copy'?result.independent_copy_state!=='retained-incomplete'||result.content_verified:result.independent_copy_state!=='committed'||!result.content_verified)throw Error('原操作终态尚未核对，保留原请求');
  forget();selected.value=result;reviewed.value=undefined;confirmation.value='';copies.value=[];localTotal.value=undefined;
  notice.value=action==='retain-remote-copy'?'原片段和 inode 已明确保留；此记录不是成功备份，不能下载为完整文件。':'本机独立副本已完整核验并保存；原件、远端归档和检查点保留。';
 });
}
async function download(file:IndependentFile){
 const row=selected.value;if(!row?.content_verified)return;
 await run(async(request,current)=>{
  downloadProgress.value=`正在读取并核对 ${file.name}，完整摘要通过前不会生成文件…`;
  const data=await independentDownload(props.api,row,file,request.signal,()=>current()&&selected.value===row);
  if(!current()||selected.value!==row)return;
  const url=URL.createObjectURL(new Blob([data as Uint8Array<ArrayBuffer>],{type:'application/octet-stream'}));
  const link=document.createElement('a');link.href=url;link.download=`${row.remote_target_id}-${row.backup_transaction_id}-${file.name}.backup`;link.click();setTimeout(()=>URL.revokeObjectURL(url),1000);
  notice.value=`${file.name} 的 ${bytes(data.length)} 字节和整文件 SHA-256 已核对，已交付浏览器下载。`;
 });
}
watch(target,chooseConnection);
watch(()=>[props.active,props.installed,props.installedVersion,props.actor,JSON.stringify(props.access)],()=>{
 stop();targets.value=[];target.value='';copies.value=[];sources.value=[];globalCount.value=globalBytes.value=localTotal.value=sourceTotal.value=undefined;pending.value=undefined;error.value='';
 if(readable.value)try{const raw=sessionStorage.getItem(storageKey(props.actor));if(raw){const value=JSON.parse(raw);if(!independentPendingValid(value,props.actor))throw Error('浏览器保存的原请求身份损坏，请按服务器原库存核对');pending.value=value;notice.value='已恢复本账户原待核对请求，只读核对后再操作；不会自动重发。'}}catch(e){error.value=e instanceof Error?e.message:String(e)}
},{immediate:true});
onBeforeUnmount(stop);
</script>

<template>
 <section class="independent-backups" aria-label="本机独立备份">
  <div class="copy-heading"><div><h3>本机独立备份</h3><p>将已提交的远端归档另存到本机 Root 私有目录。远端旧写入句柄无法修改本机副本；原数据保持原样。</p></div><el-tag type="info">文件同步 {{installedVersion||'尚未核对'}}</el-tag></div>
  <el-alert v-if="!installed||!independentBackupSupported(installedVersion)" title="请先通过签名应用商店安装或更新文件同步 2.0.0 或 2.0.1，再使用独立备份。" type="warning" :closable="false"/>
  <el-alert v-else-if="!independentFullAdministrator(access)" title="本机 Root 私有备份仅向完整权限管理员开放。" type="warning" :closable="false"/>
  <template v-else>
   <el-alert v-if="error" :title="error" type="error" :closable="false" role="alert"/>
   <el-alert v-if="notice" :title="notice" type="info" :closable="false" role="status"/>
   <div v-if="pending" class="copy-pending"><strong>原请求结果待核对</strong><p>连接 {{pending.target}} · 原事务 <code>{{pending.transaction}}</code>。刷新本机库存不会重发操作；本页未找到记录也不代表没有执行。</p><p>先选择原连接。如需显式重试原条件请求，请填写 <code>RETRY COPY {{pending.transaction}}</code>。它沿用原修订和摘要，状态变化后迟到请求会被拒绝。</p><el-input v-model="confirmation" :disabled="busy" :aria-label="'原条件重试确认'"/><el-button :disabled="busy||connection?.id!==pending.target||connection?.revision!==pending.revision||confirmation!==`RETRY COPY ${pending.transaction}`" @click="submit(pending)">按原条件显式重试</el-button></div>
   <div class="copy-toolbar"><el-button :loading="busy" :disabled="!readable" @click="refreshTargets">刷新连接配置</el-button><label>选择受限 SFTP 连接<el-select v-model="target" :disabled="busy" :teleported="false" placeholder="先刷新连接配置"><el-option v-for="cfg in targets" :key="cfg.id" :label="cfg.id+(cfg.enabled?'':'（已停用，可离线核验）')" :value="cfg.id"/></el-select></label></div>
   <p v-if="connection" class="copy-identity">连接修订 {{connection.revision}} · <code>{{connection.host_key_fingerprint}}</code>。本机清单、核验与下载可离线使用。</p>
   <div class="copy-cards"><article><span>全连接保留副本</span><strong>{{globalCount===undefined?'尚未核对':globalCount+' / 128'}}</strong></article><article><span>含保留片段的逻辑容量</span><strong>{{bytes(globalBytes)}}</strong><small>总预算 1 GiB，不自动清理</small></article><article><span>当前所选副本</span><strong>{{selected?(selected.content_verified?'完整内容已核验':independentStateLabels[selected.independent_copy_state]):'尚未选择'}}</strong></article></div>
   <h4>本机保留副本</h4><div class="copy-actions"><el-button :disabled="busy||!connection" @click="refreshLocal">离线刷新本机库存</el-button><el-button :disabled="busy||!connection||localPage===0" @click="localPage--;refreshLocal()">上一页</el-button><el-button :disabled="busy||!connection||localTotal===undefined||(localPage+1)*16>=localTotal" @click="localPage++;refreshLocal()">下一页</el-button><span>第 {{localPage+1}} 页 · {{localTotal===undefined?'尚未查询':localTotal+' 条'}}</span></div>
   <div class="copy-list"><button v-for="row in copies" :key="row.backup_transaction_id" type="button" class="copy-row" :disabled="busy" @click="select(row)"><strong>{{independentStateLabels[row.independent_copy_state]}}</strong><code>{{row.backup_transaction_id}}</code><small>保留 {{bytes(row.retained_bytes)}} · {{row.retained_attempts}} / 8 次尝试 · {{row.created_at}}</small></button><p v-if="localTotal===0" class="copy-empty">当前连接尚无本机独立副本。</p></div>
   <RemoteUnpublishedFragments :api="api" :actor="actor" :access="access" :active="readable" :installed-version="installedVersion" :connection="connection" @retained="unpublishedRetained" />
   <article v-if="selected" class="copy-selected"><h4>原事务 <code>{{selected.backup_transaction_id}}</code></h4><p>{{selected.content_verified?'全部原文件摘要已独立核验':independentStateLabels[selected.independent_copy_state]}}</p><details><summary>核对原摘要</summary><p>源归档 <code>{{selected.source_snapshot_sha256}}</code></p><p>副本意图 <code>{{selected.copy_intent_sha256}}</code></p><p>当前状态 <code>{{selected.copy_state_sha256}}</code></p></details>
    <template v-if="selected.independent_copy_state==='committed'"><div class="copy-actions"><el-button :disabled="busy" @click="verify">离线核验完整副本</el-button><el-button v-for="file in selected.files" :key="file.name" :disabled="busy||!selected.content_verified" @click="download(file)">核验并下载 {{file.name}} · {{bytes(file.bytes)}}</el-button></div><p class="copy-explanation">下载逐段校验，并在整文件摘要通过后才生成文件。连接、权限或选中记录变化时丢弃本次下载。</p></template>
    <template v-else-if="selected.independent_copy_state==='needs-review'"><p class="copy-explanation">恢复保留所有原片段和 inode；完整原尝试可离线确认，残片则创建新的私有尝试。只保留片段会解除本次待恢复状态，但不会成为成功备份。</p><el-radio-group v-model="mode" :disabled="busy||!!pending"><el-radio-button value="recover-remote-copy">核对原状态并恢复</el-radio-button><el-radio-button value="retain-remote-copy">仅保留未完成片段</el-radio-button></el-radio-group></template>
    <p v-else class="copy-explanation">原未完成片段已保留，未声明成功；此记录不能作为完整原文件下载。</p>
   </article>
   <h4>从已提交远端归档建立副本</h4><p class="copy-explanation">先在“受控远端备份归档”完成原归档。此处选择记录后完整读取核对，明确确认才建立本机副本。</p><div class="copy-actions"><el-button :disabled="busy||!connection||!connection.enabled" @click="refreshSources">连接远端，查询归档库存</el-button><el-button :disabled="busy||!connection||!connection.enabled||sourcePage===0" @click="sourcePage--;refreshSources()">上一页</el-button><el-button :disabled="busy||!connection||!connection.enabled||sourceTotal===undefined||(sourcePage+1)*16>=sourceTotal" @click="sourcePage++;refreshSources()">下一页</el-button><span>第 {{sourcePage+1}} 页 · {{sourceTotal===undefined?'尚未查询':sourceTotal+' 条原归档'}}</span></div>
   <div class="copy-list"><button v-for="row in sources" :key="row.backup_transaction_id" type="button" class="copy-row" :disabled="busy||!!pending" @click="review(row)"><strong>核对原件 · {{bytes(row.backup_bytes)}}</strong><code>{{row.backup_transaction_id}}</code><small>已提交远端归档，尚未核对完整内容</small></button><p v-if="sourceTotal===0" class="copy-empty">远端尚无保留归档，请先完成受控归档。</p><p v-else-if="sourceTotal!==undefined&&!sources.length" class="copy-empty">本页没有已提交归档；未完成记录请回到原归档页面恢复。</p></div>
   <div v-if="!pending&&phrase&&(reviewed||selected?.independent_copy_state==='needs-review')" class="copy-confirm"><p>原事务 <code>{{mutationRow?.backup_transaction_id}}</code></p><label>精确确认：<code>{{phrase}}</code><el-input v-model="confirmation" :disabled="busy" :aria-label="'独立备份精确确认'"/></label><el-button type="primary" :disabled="!canSubmit" :loading="busy" @click="submit()">{{mode==='copy-remote-backup'?'创建本机独立副本':mode==='recover-remote-copy'?'按当前状态核对恢复':'明确保留未完成片段'}}</el-button></div>
   <p v-if="downloadProgress" role="status">{{downloadProgress}}</p>
   <details class="copy-limits"><summary>备份范围与保留限制</summary><p>每份最多两个 8 MiB 文件，全连接最多 128 份，文件内容与未完成数据片段的逻辑总量最多 1 GiB，每份最多 8 次明确尝试。原记录和回执另按固定条数和大小限制；未发布主记录目录也占用全机 128 份名额。新复制预留 256 MiB 可用空间；这是安全余量，并非磁盘硬配额。中断或异常保留原记录，不自动删除、截断或重传。</p><p>原远端仍限定为可信 Linux/OpenSSH 固定公钥受限账户。本机副本与远端 inode 独立，但不是整站一致性快照，也不抵御同等 Root 权限主动修改本机数据。</p></details>
  </template>
 </section>
</template>

<style scoped>
.independent-backups{min-width:0}.copy-heading,.copy-toolbar,.copy-actions{display:flex;gap:12px;align-items:center;flex-wrap:wrap}.copy-heading{justify-content:space-between;align-items:flex-start}.copy-heading h3{margin:4px 0;font-size:19px}.copy-heading p,.copy-explanation,.copy-limits p,.copy-identity{color:var(--el-text-color-secondary);line-height:1.65}.independent-backups .el-alert{margin:12px 0}.copy-toolbar{margin:20px 0;align-items:flex-end}.copy-toolbar label,.copy-confirm label{display:grid;gap:8px;min-width:0;flex:1 1 260px}.copy-toolbar .el-select{width:100%}.copy-cards{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:12px;margin:18px 0}.copy-cards article{display:grid;gap:8px;padding:16px;border:1px solid var(--el-border-color-light);border-radius:8px;min-width:0}.copy-cards span,.copy-cards small,.copy-row small{font-size:12px;color:var(--el-text-color-secondary)}.copy-cards strong{font-size:17px}.copy-actions{margin:12px 0}.copy-actions .el-button+.el-button{margin-left:0}.copy-actions span{font-size:12px;color:var(--el-text-color-secondary)}.copy-list{display:grid;gap:8px;grid-template-columns:repeat(2,minmax(0,1fr))}.copy-row{text-align:left;display:grid;gap:8px;background:var(--el-fill-color-blank);color:var(--el-text-color-primary);border:1px solid var(--el-border-color-light);border-radius:7px;padding:14px;cursor:pointer;min-width:0}.copy-row:hover:enabled{border-color:var(--el-color-primary)}.copy-row:disabled{cursor:wait;opacity:.65}.independent-backups code{overflow-wrap:anywhere;white-space:normal;font-size:12px}.independent-backups p,.copy-row small,.copy-cards strong{overflow-wrap:anywhere}.copy-selected,.copy-confirm,.copy-pending,.copy-limits{padding:16px;border:1px solid var(--el-border-color-light);border-radius:8px;margin:18px 0;min-width:0}.copy-selected h4{margin-top:0}.copy-pending{border-color:var(--el-color-warning-light-5)}.copy-confirm .el-button,.copy-pending .el-button{margin-top:12px}.copy-empty{color:var(--el-text-color-secondary);padding:12px}.independent-backups summary{cursor:pointer}.independent-backups .el-radio-group{display:flex;flex-wrap:wrap}@media(max-width:700px){.copy-cards,.copy-list{grid-template-columns:1fr}.copy-actions .el-button,.copy-confirm .el-button,.copy-pending .el-button{max-width:100%;white-space:normal;height:auto;min-height:34px;padding:10px}.copy-toolbar label{flex-basis:100%}.copy-heading .el-tag{height:auto;white-space:normal}.copy-selected,.copy-confirm,.copy-pending{padding:12px}.independent-backups .el-radio-group{gap:8px}}
</style>
