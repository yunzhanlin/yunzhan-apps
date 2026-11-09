<script setup lang="ts">
import {computed,onBeforeUnmount,ref,shallowRef,watch} from 'vue';
import type {AccessPlan} from './menuPermissions';
import {independentFullAdministrator,type IndependentAPI} from './remoteIndependentBackup';
import {unpublishedRetentionVersion,unpublishedCopyValid,unpublishedInventory,unpublishedMutationBody,unpublishedPendingValid,unpublishedReply,type UnpublishedCopy,type UnpublishedPending} from './remoteUnpublishedCopy';
const props=defineProps<{api:IndependentAPI;actor:string;access?:AccessPlan|null;active:boolean;installedVersion?:string;connection?:{id:string;revision:number}}>();
const emit=defineEmits<{retained:[row:UnpublishedCopy]}>();
const rows=shallowRef<UnpublishedCopy[]>([]),selected=shallowRef<UnpublishedCopy>(),pending=shallowRef<UnpublishedPending>();
const busy=ref(false),error=ref(''),notice=ref(''),confirm=ref(''),page=ref(0),total=ref<number>();
let generation=0,controller:AbortController|undefined;
const readable=computed(()=>props.active&&props.installedVersion===unpublishedRetentionVersion&&/^[a-f0-9]{32}$/.test(props.actor)&&independentFullAdministrator(props.access)&&!!props.connection);
const phrase=computed(()=>selected.value?`RETAIN FRAGMENTS ${selected.value.backup_transaction_id}`:'');
const canSubmit=computed(()=>{if(!readable.value||busy.value||pending.value||!selected.value)return false;try{unpublishedMutationBody(selected.value,confirm.value);return true}catch{return false}});
const key=(actor:string)=>`yunzhan-unpublished-retention-pending-v1/${actor}`;
function remember(ticket:UnpublishedPending){pending.value=ticket;try{sessionStorage.setItem(key(ticket.actor),JSON.stringify(ticket))}catch{notice.value='浏览器未能保存原请求，当前页面保留其标识；服务器原片段和回执不会删除。'}}
function forget(){const t=pending.value;pending.value=undefined;if(t)try{sessionStorage.removeItem(key(t.actor))}catch{/* Server receipts and original bytes are never cleared. */}}
function stop(){generation++;controller?.abort();controller=undefined;busy.value=false;rows.value=[];selected.value=undefined;confirm.value='';total.value=undefined;page.value=0;}
function bytes(n:number){return n<1024?`${n} B`:`${(n/1024).toFixed(2)} KiB`;}
async function run(task:(signal:AbortSignal,current:()=>boolean)=>Promise<void>){
 if(!readable.value||busy.value)return;const epoch=generation,actor=props.actor,connection=props.connection!,request=new AbortController();controller=request;busy.value=true;error.value='';
 const current=()=>epoch===generation&&actor===props.actor&&connection.id===props.connection?.id&&connection.revision===props.connection?.revision&&readable.value&&!request.signal.aborted;
 try{await task(request.signal,current)}catch(e){if(current())error.value=e instanceof Error?e.message:String(e)}finally{if(epoch===generation){busy.value=false;controller=undefined;}}
}
async function refresh(){
 await run(async(signal,current)=>{
  const cfg=props.connection!,offset=page.value*16;rows.value=[];selected.value=undefined;confirm.value='';total.value=undefined;
  const value=await props.api<unknown>('/app-modules/files-sync/remote-copy-fragments','POST',{remote_target_id:cfg.id,expected_revision:cfg.revision,limit:16,offset},undefined,signal);
  if(!current())return;const out=unpublishedInventory(value,cfg.id,cfg.revision,offset);rows.value=out.rows;total.value=out.total;
  const ticket=pending.value,row=ticket&&out.rows.find(r=>r.backup_transaction_id===ticket.transaction&&r.remote_target_id===ticket.target&&r.snapshot_sha256===ticket.sha256&&r.fragment_state==='unpublished-retained');
  if(row){forget();emit('retained',row);notice.value='已只读核对原请求的明确保留回执；原片段不是成功备份，未重新提交。';}
  else notice.value=ticket?'本页尚未核对到原请求终态，不据此判定没有执行；可继续只读翻页核对。':'已离线完整核对本机未发布主意图的目录和原片段；未连接远端，未解释片段内容。';
 });
}
function select(row:UnpublishedCopy){if(busy.value)return;selected.value=row;confirm.value='';error.value='';if(row.fragment_state==='unpublished-retained')emit('retained',row);}
async function submit(original?:UnpublishedPending){
 const cfg=props.connection;if(!cfg)return;let ticket:UnpublishedPending,body;
 if(original){if(!pending.value||!unpublishedPendingValid(original,props.actor)||original.target!==cfg.id||original.revision!==cfg.revision||confirm.value!==`RETRY FRAGMENTS ${original.transaction}`)return;ticket={...original};body={remote_target_id:ticket.target,expected_revision:ticket.revision,resource_id:ticket.transaction,expected_sha:ticket.sha256,confirm:`RETAIN FRAGMENTS ${ticket.transaction}`};}
 else{if(!canSubmit.value||!selected.value)return;body=unpublishedMutationBody(selected.value,confirm.value);ticket={actor:props.actor,target:cfg.id,revision:cfg.revision,transaction:body.resource_id,sha256:body.expected_sha,action:'retain-remote-copy-fragments'};}
 await run(async(signal,current)=>{
  remember(ticket);const value=await props.api<unknown>('/app-modules/files-sync/retain-remote-copy-fragments','POST',body,undefined,signal);if(!current())return;
  const row=unpublishedReply(value,cfg.id,cfg.revision,ticket.transaction,ticket.sha256);forget();selected.value=row;rows.value=[];total.value=undefined;confirm.value='';emit('retained',row);
  notice.value='已明确保留全部原片段和原目录；这不是成功备份，不能作为复制来源或完整文件下载。';
 });
}
async function acknowledgeSuperseded(){
 const original=pending.value;if(!original)return;
 await run(async(signal,current)=>{
  const value=await props.api<any>('/app-modules/files-sync/remote-targets','POST',{},undefined,signal);if(!current())return;
  if(!Array.isArray(value?.remote_targets)||value.remote_targets.length>16)throw Error('原连接当前修订无法完整核对，保留原请求');
  const matches=value.remote_targets.filter((v:any)=>v?.id===original.target&&v.remote_target_id===original.target);
  if(matches.length!==1||!Number.isSafeInteger(matches[0].revision)||matches[0].revision<=original.revision||matches[0].revision>1e9)throw Error('尚未证明原条件已失效；请核对原连接和实际库存');
  // Keep the original browser ticket as evidence. A strictly newer server
  // revision fences the old condition but says nothing about prior completion.
  const historyKey=key(original.actor)+'/superseded',raw=sessionStorage.getItem(historyKey),history=raw?JSON.parse(raw):[];
  if(!Array.isArray(history)||history.length>=32||history.some(v=>!unpublishedPendingValid(v,original.actor)))throw Error('浏览器原条件保留清单无法追加，请先保留原请求标识');
  history.push(original);sessionStorage.setItem(historyKey,JSON.stringify(history));forget();
  notice.value='已从服务器确认原修订失效，原请求标识另行保留。未判定原操作成功，请刷新实际片段库存再决定。';
 });
}
watch(()=>[props.active,props.installedVersion,props.actor,props.connection?.id,props.connection?.revision,JSON.stringify(props.access)],()=>{
 stop();error.value='';pending.value=undefined;
 if(readable.value)try{const raw=sessionStorage.getItem(key(props.actor));if(raw){const value=JSON.parse(raw);if(!unpublishedPendingValid(value,props.actor))throw Error('浏览器原片段保留请求身份损坏，请按服务器实际库存核对');pending.value=value;notice.value='已恢复原条件请求；只读核对前不会自动重发。';}}catch(e){error.value=e instanceof Error?e.message:String(e);}
},{immediate:true});
onBeforeUnmount(stop);
</script>

<template>
 <section v-if="installedVersion===unpublishedRetentionVersion" class="unpublished-fragments" aria-label="未发布原记录片段">
  <h4>未发布原记录片段</h4><p>断电或中断可能发生在备份主记录保存前。此处只核对本机原目录、片段及完整摘要，绝不将片段内容当作来源或复制授权。明确保留后仍不是成功备份。</p>
  <el-alert v-if="error" :title="error" type="error" :closable="false" role="alert"/><el-alert v-if="notice" :title="notice" type="info" :closable="false" role="status"/>
  <div v-if="pending" class="fragment-pending"><strong>原片段保留结果待核对</strong><p>连接 {{pending.target}} · 原事务 <code>{{pending.transaction}}</code> · 原修订 {{pending.revision}}。本页没有回执不表示没有执行。</p><p>只读刷新不会重发；按原条件明确重试须填写 <code>RETRY FRAGMENTS {{pending.transaction}}</code>。</p><el-input v-model="confirm" :disabled="busy" aria-label="原片段条件重试确认"/><el-button :disabled="busy||connection?.id!==pending.target||connection?.revision!==pending.revision||confirm!==`RETRY FRAGMENTS ${pending.transaction}`" @click="submit(pending)">按原条件明确重试</el-button><el-button v-if="connection?.id===pending.target&&connection.revision>pending.revision" :disabled="busy" @click="acknowledgeSuperseded">核对并保留已失效条件</el-button></div>
  <div class="fragment-actions"><el-button :disabled="busy||!readable" :loading="busy" @click="refresh">离线核对未发布原片段</el-button><el-button :disabled="busy||!readable||page===0" @click="page--;refresh()">上一页</el-button><el-button :disabled="busy||!readable||total===undefined||(page+1)*16>=total" @click="page++;refresh()">下一页</el-button><span>第 {{page+1}} 页 · {{total===undefined?'尚未查询':total+' 条'}}</span></div>
  <div class="fragment-list"><button v-for="row in rows" :key="row.backup_transaction_id" type="button" :disabled="busy" @click="select(row)"><strong>{{row.fragment_state==='unpublished-retained'?'仅保留原片段 · 非成功备份':'主记录未发布 · 待明确核对'}}</strong><code>{{row.backup_transaction_id}}</code><span>{{row.fragments.length}} 个原片段 · {{bytes(row.retained_bytes)}}</span></button><p v-if="total===0">当前连接没有未发布主记录的目录。</p></div>
  <article v-if="selected" class="fragment-selected"><h5>原事务 <code>{{selected.backup_transaction_id}}</code></h5><p>原目录及文件的私有权限、属主和无符号/硬链接限制已核对。{{selected.fragments.length?'以下仅为原始片段摘要，不解释其中的业务字段。':'原目录为空：未生成主记录，也不补造复制来源。'}}</p><ul><li v-for="f in selected.fragments" :key="f.name"><code>{{f.name}}</code> · {{bytes(f.bytes)}}<br/><code>{{f.sha256}}</code></li></ul><p>完整状态摘要 <code>{{selected.snapshot_sha256}}</code></p><p v-if="selected.fragment_state==='unpublished-retained'">已明确保留原目录和片段，未声明成功；不能从此记录恢复或下载完整备份。{{selected.retained_at}}</p><template v-else><el-alert v-if="selected.fragments.length>=8" title="原记录片段已达保留上限，不能追加新回执；原字节保留，不自动清理。" type="warning" :closable="false"/><template v-if="!pending"><label>精确确认 <code>{{phrase}}</code><el-input v-model="confirm" :disabled="busy" aria-label="未发布原片段精确确认"/></label><el-button type="primary" :disabled="!canSubmit" :loading="busy" @click="submit()">明确保留原片段 · 不视为成功</el-button></template></template></article>
 </section>
</template>

<style scoped>
.unpublished-fragments{margin:22px 0;padding:16px;border:1px solid var(--el-border-color-light);border-radius:8px;min-width:0}.unpublished-fragments h4{margin-top:0}.unpublished-fragments p{line-height:1.65;color:var(--el-text-color-secondary);overflow-wrap:anywhere}.unpublished-fragments code{overflow-wrap:anywhere;white-space:normal;font-size:12px}.unpublished-fragments .el-alert{margin:10px 0}.fragment-actions{display:flex;gap:10px;align-items:center;flex-wrap:wrap;margin:14px 0}.fragment-actions .el-button+.el-button{margin-left:0}.fragment-actions span{font-size:12px}.fragment-list{display:grid;gap:10px;grid-template-columns:repeat(2,minmax(0,1fr))}.fragment-list button{display:grid;gap:8px;text-align:left;padding:12px;border:1px solid var(--el-border-color-light);background:var(--el-fill-color-blank);color:var(--el-text-color-primary);border-radius:6px;min-width:0;cursor:pointer}.fragment-list span{font-size:12px;color:var(--el-text-color-secondary)}.fragment-selected,.fragment-pending{padding:14px;border:1px solid var(--el-border-color-light);border-radius:6px;margin:14px 0;min-width:0}.fragment-pending{border-color:var(--el-color-warning-light-5)}.fragment-selected label{display:grid;gap:8px}.fragment-selected li{margin:10px 0}.fragment-selected .el-button,.fragment-pending .el-button{margin-top:12px;max-width:100%}@media(max-width:700px){.unpublished-fragments{padding:12px}.fragment-list{grid-template-columns:1fr}.unpublished-fragments .el-button{height:auto;min-height:34px;white-space:normal;overflow-wrap:anywhere;padding:10px}.fragment-selected,.fragment-pending{padding:12px}}
</style>
