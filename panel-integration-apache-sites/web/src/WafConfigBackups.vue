<script setup lang="ts">
import {onUnmounted,ref,watch} from "vue";
import {formatPanelDateTime} from "./panelTime";
import {archiveWafConfigBackup,decodeWafConfigBackup,readWafConfigBackups,readWafConfigBackupArchive,readWafConfigBackupArchiveRecovery,readWafConfigBackupSlots,readWafConfigBackupSnapshot,wafConfigBackupArchiveInput,wafConfigBackupArchiveRecoveredInput,type WafConfigBackup,type WafConfigBackupInventory,type WafConfigBackupSlots,type WafConfigBackupArchiveInput,type WafConfigBackupArchiveRecovery} from "./wafConfigBackups";
type API=<T>(path:string,method?:string,body?:unknown,key?:string)=>Promise<T>;
const props=defineProps<{api:API;active:boolean}>();
const inventory=ref<WafConfigBackupInventory>(),error=ref(""),busy=ref(false);
const slots=ref<WafConfigBackupSlots>(),archived=ref<WafConfigBackupInventory>(),selected=ref<WafConfigBackup>(),confirmation=ref(""),receipt=ref(""),evidence=ref("");
const pendingArchive=ref<{input:WafConfigBackupArchiveInput}>();
const recovery=ref<WafConfigBackupArchiveRecovery>(),recoveryError=ref(""),recoveryConflict=ref(false);
let generation=0,disposed=false;
const bytes=(n:number)=>n<1024?`${n} 字节`:n<1048576?`${(n/1024).toFixed(2)} KiB`:`${(n/1048576).toFixed(2)} MiB`;
async function refresh(){
  if(disposed||!props.active||busy.value)return;
  const token=++generation;
  const current=()=>!disposed&&props.active&&token===generation;
  busy.value=true;inventory.value=undefined;slots.value=undefined;selected.value=undefined;confirmation.value="";error.value="";
  recovery.value=undefined;recoveryError.value="";recoveryConflict.value=false;
  try{await recoverArchiveRequest(current);}
  catch(e){if(current())recoveryError.value=e instanceof Error?e.message:"当前账户的待核对请求未知；暂不允许归档。";}
  if(!current())return;
  try{const next=await readWafConfigBackups(props.api,current);if(current())inventory.value=next;}
  catch(e){if(current())error.value=e instanceof Error?e.message:"配置备份库存不可核对";}
  finally{if(current())busy.value=false;}
}
async function recoverArchiveRequest(current:()=>boolean){
  const next=await readWafConfigBackupArchiveRecovery(props.api,current);
  if(!current())return;
  if(next.pending){
    const original=wafConfigBackupArchiveRecoveredInput(next.pending),memory=pendingArchive.value?.input;
    if(memory&&(memory.resource_id!==original.resource_id||memory.expected_sha!==original.expected_sha)){
      recoveryConflict.value=true;recoveryError.value="服务端有另一份待核对请求。本工作区保留原身份，不替换它；请在独立工作区先核对服务端请求，再返回重试原身份。";
    }else if(!memory){pendingArchive.value={input:original};selected.value=undefined;confirmation.value="";receipt.value="";evidence.value="";}
  }
  // Explicit absence is not confirmation of an in-memory unknown result.
  recovery.value=next;
}
async function loadSlots(){
  if(disposed||!props.active||busy.value)return;
  const token=++generation,current=()=>!disposed&&props.active&&token===generation;
  busy.value=true;slots.value=undefined;selected.value=undefined;confirmation.value="";error.value="";
  try{const next=await readWafConfigBackupSlots(props.api,current);if(current())slots.value=next;}
  catch(e){if(current())error.value=e instanceof Error?e.message:"目录标识不可核对";}
  finally{if(current())busy.value=false;}
}
function choose(row:WafConfigBackup){
  if(disposed||!props.active||busy.value||pendingArchive.value||!recovery.value||recoveryConflict.value)return;
  selected.value={...decodeWafConfigBackup(row)};confirmation.value="";receipt.value="";evidence.value="";
}
async function verifySnapshot(id:string){
  if(disposed||!props.active||busy.value||pendingArchive.value||!recovery.value||recoveryConflict.value)return;
  const token=++generation,current=()=>!disposed&&props.active&&token===generation;
  busy.value=true;selected.value=undefined;confirmation.value="";error.value="";
  try{const row=await readWafConfigBackupSnapshot(props.api,current,id);if(current()){selected.value=row;receipt.value="";evidence.value="";}}
  catch(e){if(current())error.value=e instanceof Error?e.message:"所选原快照尚未完整核验";}
  finally{if(current())busy.value=false;}
}
async function loadArchive(){
  if(disposed||!props.active||busy.value)return;
  const token=++generation,current=()=>!disposed&&props.active&&token===generation;
  busy.value=true;archived.value=undefined;error.value="";
  try{const next=await readWafConfigBackupArchive(props.api,current);if(current())archived.value=next;}
  catch(e){if(current())error.value=e instanceof Error?e.message:"归档库存尚未完整核验";}
  finally{if(current())busy.value=false;}
}
async function archiveSelected(){
  if(disposed||!props.active||busy.value||!recovery.value||recoveryConflict.value)return;
  let input=pendingArchive.value?.input;
  if(!input){
    if(!selected.value)return;
    try{input=wafConfigBackupArchiveInput(selected.value,confirmation.value);}
    catch(e){error.value=e instanceof Error?e.message:"原归档确认无效";return;}
    pendingArchive.value={input}; // Retain exact original ID/SHA BEFORE POST.
  }
  const token=++generation,current=()=>!disposed&&props.active&&token===generation;
  busy.value=true;error.value="";receipt.value="";evidence.value="";
  try{
    const out=await archiveWafConfigBackup(props.api,current,input);
    if(!current())return;
    receipt.value=`原标识 ${out.snapshot.id} 的完整归档及审计回执已核对${out.replayed?'（原身份重试）':''}；配置未改变，全部字节保留。`;
    pendingArchive.value=undefined;selected.value=undefined;confirmation.value="";
    inventory.value=undefined;slots.value=undefined;archived.value=undefined;
    recovery.value=undefined;
  }catch(e){if(current())error.value=e instanceof Error?e.message:"归档结果尚未确认，保留原身份，不自动重试";}
  finally{if(current())busy.value=false;}
}
async function inspectOriginal(){
  if(disposed||!props.active||busy.value||!pendingArchive.value)return;
  const input=pendingArchive.value.input,token=++generation,current=()=>!disposed&&props.active&&token===generation;
  busy.value=true;error.value="";evidence.value="";
  try{
    const row=await readWafConfigBackupSnapshot(props.api,current,input.resource_id,true);
    if(row.sha256!==input.expected_sha)throw new Error("原归档摘要不匹配；仍保留原请求，不替换身份。");
    if(current())evidence.value="原标识和完整摘要的归档证据已核验。此只读核对不代表原操作回执或审计已完成；可显式按原身份核对回执。";
  }catch(e){if(current())error.value=e instanceof Error?e.message:"原归档证据尚未确认；不宣称未移动";}
  finally{if(current())busy.value=false;}
}
function invalidate(){generation++;inventory.value=undefined;slots.value=undefined;archived.value=undefined;selected.value=undefined;confirmation.value="";error.value="";receipt.value="";evidence.value="";recovery.value=undefined;recoveryError.value="";recoveryConflict.value=false;busy.value=false;}
watch(()=>props.active,active=>{if(active)void refresh();else invalidate();},{immediate:true});
onUnmounted(()=>{disposed=true;invalidate();});
</script>

<template>
  <section class="waf-config-backups" aria-label="防火墙原配置备份库存" :aria-busy="busy">
    <div class="backup-heading"><h4>原配置备份库存</h4><div class="backup-actions"><el-button :loading="busy" :disabled="!active" @click="refresh">只读核对库存</el-button><el-button :disabled="busy || !active" @click="loadSlots">只读列出目录标识</el-button><el-button :disabled="busy || !active" @click="loadArchive">只读核对归档</el-button></div></div>
    <p>每次修改前保留的完整原配置快照。只核验索引和全部文件的权限、身份与摘要；不重载网站，不返回配置正文或原文件路径。</p>
    <el-alert title="归档只将所选完整原快照无覆盖移动至同一文件系统的私有归档区，保留全部字节；不删除、不导出配置正文、不回滚或重载网站。活动区最多 100 份，归档区最多 100 份及 128 MiB 逻辑容量；完整库存扫描上限为 128 MiB，不是磁盘硬配额。不会自动清理证据。" type="info" :closable="false"/>
    <el-alert v-if="error" :title="error" type="error" :closable="false"/>
    <el-alert v-if="recoveryError" :title="recoveryError" type="warning" :closable="false"/>
    <p v-if="recovery && !recovery.pending">当前账户本次读取无待核对请求记录；这不确认本工作区仍保留的未知操作结果。</p>
    <p v-else-if="!busy && !recovery">当前账户的待核对请求尚不可确认；只读库存仍可查看，暂不允许发起或重试归档。</p>
    <el-alert v-if="receipt" :title="receipt" type="success" :closable="false"/>
    <el-alert v-if="evidence" :title="evidence" type="info" :closable="false"/>
    <section v-if="pendingArchive" class="backup-original" aria-label="原归档请求身份">
      <el-alert title="原归档结果尚未确认。服务端在执行前将当前账户的原标识、摘要与请求审计一并保存，重开界面仅只读恢复；这不是文件归档或结果审计完成的证明。未到达服务端的请求仅保留在本工作区，请记录以下身份。不自动重试、更换摘要或宣称未移动。" type="warning" :closable="false"/>
      <p>原标识：<code>{{pendingArchive.input.resource_id}}</code><br>原完整摘要：<code>{{pendingArchive.input.expected_sha}}</code></p>
      <p v-if="recoveryConflict && recovery?.pending">服务端另一原标识：<code>{{recovery.pending.resource_id}}</code><br>另一完整摘要：<code>{{recovery.pending.expected_sha}}</code></p>
      <div class="backup-actions"><el-button :disabled="busy || !active" @click="inspectOriginal">只读核对原归档证据</el-button><el-button type="primary" :disabled="busy || !active || !recovery || recoveryConflict" @click="archiveSelected">按原身份核对归档回执</el-button></div>
    </section>
    <p v-if="busy" role="status">正在完整核验原备份；尚未宣称核对完成。</p>
    <el-alert v-else-if="inventory && !inventory.available" title="尚无可核对的原配置锁。库存不可确认，不代表没有备份；未创建目录或锁。" type="warning" :closable="false"/>
    <template v-else-if="inventory?.available">
      <p class="backup-summary">已完整核验 {{inventory.entries.length}} / {{inventory.count_max}} 份 · {{bytes(inventory.bytes)}} · 仅限本次读取时的库存</p>
      <el-alert v-if="inventory.entries.length>=inventory.count_max" title="备份数量已满。未删除或归档证据；配置修改仍会被拒绝。" type="warning" :closable="false"/>
      <el-table :data="inventory.entries" max-height="420" empty-text="本次在原配置锁下完整核验，未发现备份快照">
        <el-table-column label="快照标识" min-width="230"><template #default="{row}"><code>{{row.id}}</code></template></el-table-column>
        <el-table-column label="创建时间" min-width="170"><template #default="{row}">{{formatPanelDateTime(row.created_at)}}</template></el-table-column>
        <el-table-column prop="files" label="索引文件数" width="110"/>
        <el-table-column label="实际备份容量" width="140"><template #default="{row}">{{bytes(row.bytes)}}</template></el-table-column>
        <el-table-column label="完整内容摘要" min-width="250"><template #default="{row}"><code>{{row.sha256}}</code></template></el-table-column>
        <el-table-column label="操作" width="100"><template #default="{row}"><el-button link type="primary" :disabled="busy || !!pendingArchive || !recovery || recoveryConflict" @click="choose(row)">选择归档</el-button></template></el-table-column>
      </el-table>
    </template>
    <p v-else-if="!busy && !error">尚未读取库存；不显示演示数量或空列表结论。</p>
    <section v-if="slots" aria-label="仅目录标识">
      <h4>仅目录标识</h4>
      <el-alert title="此列表只核对私有目录身份，尚未读取索引或文件内容。目录数量不等于完整快照核验数量；每份需单独核验后才能选择归档。" type="warning" :closable="false"/>
      <p v-if="!slots.available">目录标识未知，不代表没有快照。</p>
      <el-table v-else :data="slots.ids.map(id=>({id}))" max-height="420" empty-text="本次原锁下未发现目录标识；没有核验快照内容">
        <el-table-column prop="id" label="目录标识（内容未核验）" min-width="250"/>
        <el-table-column label="操作" width="110"><template #default="{row}"><el-button link type="primary" :disabled="busy || !!pendingArchive || !recovery || recoveryConflict" @click="verifySnapshot(row.id)">核验此份</el-button></template></el-table-column>
      </el-table>
    </section>
    <section v-if="selected && !pendingArchive" class="backup-original" aria-label="所选完整快照归档">
      <h4>所选完整原快照</h4><p>标识：<code>{{selected.id}}</code><br>完整摘要：<code>{{selected.sha256}}</code><br>{{selected.files}} 个索引文件 · {{bytes(selected.bytes)}} · 只核验此份，不代表整批库存通过。</p>
      <label for="waf-backup-archive-confirm">输入 <code>ARCHIVE NGINX CONFIG {{selected.id}}</code> 以确认保留全部字节的归档</label>
      <el-input id="waf-backup-archive-confirm" v-model="confirmation" :disabled="busy" autocomplete="off"/>
      <el-button type="primary" :disabled="busy || !recovery || recoveryConflict || confirmation!=='ARCHIVE NGINX CONFIG '+selected.id" @click="archiveSelected">保留证据并归档此份</el-button>
    </section>
    <section v-if="archived" aria-label="完整归档库存">
      <h4>完整归档库存</h4><p v-if="!archived.available">原归档库存不可确认，不代表没有归档。</p>
      <template v-else><p>已完整核验 {{archived.entries.length}} / 100 份归档 · {{bytes(archived.bytes)}} · 仅限本次读取</p>
        <el-table :data="archived.entries" max-height="420" empty-text="本次原锁下未发现归档快照"><el-table-column prop="id" label="原标识" min-width="250"/><el-table-column label="完整摘要" min-width="260"><template #default="{row}"><code>{{row.sha256}}</code></template></el-table-column><el-table-column label="容量" width="120"><template #default="{row}">{{bytes(row.bytes)}}</template></el-table-column></el-table>
      </template>
    </section>
  </section>
</template>

<style scoped>
.waf-config-backups{min-width:0}.backup-heading,.backup-actions{display:flex;gap:12px;align-items:center;justify-content:space-between;flex-wrap:wrap}.backup-actions :deep(.el-button){margin-left:0}.backup-heading h4{margin:0}.waf-config-backups p{line-height:1.7}.waf-config-backups :deep(.el-alert){margin:12px 0}.backup-summary{color:#28614b}.backup-original{border:1px solid #dce6e1;border-radius:8px;padding:12px;margin:16px 0;min-width:0}.backup-original :deep(.el-input){margin:10px 0}code{font-size:12px;overflow-wrap:anywhere}.waf-config-backups :deep(.el-table){max-width:100%}@media(max-width:600px){.backup-heading{align-items:flex-start}.backup-actions{align-items:flex-start;justify-content:flex-start}.waf-config-backups p{font-size:12px}}
</style>
