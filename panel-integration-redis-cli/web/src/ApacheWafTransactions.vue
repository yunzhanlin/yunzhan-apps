<script setup lang="ts">
import {computed,onUnmounted,ref,watch} from "vue";
import {formatPanelDateTime} from "./panelTime";
import {apacheArchiveBody,apacheArchiveReceipt,apacheTransactionInventory,apacheTransactionQuery,type ApacheTransactionInventory,type ApacheTransactionRow,type ApacheArchiveReceipt} from "./apacheWafTransactions";
type API=<T>(path:string,method?:string,body?:unknown,key?:string)=>Promise<T>;
const props=defineProps<{api:API;active:boolean;installed:boolean;version?:string;parentBusy:boolean}>();
const inventory=ref<ApacheTransactionInventory>(),receipt=ref<ApacheArchiveReceipt>(),selected=ref<ApacheTransactionRow>();
const confirm=ref(""),error=ref(""),operationError=ref(""),busy=ref(false),known=ref(false),page=ref(1);
const limit=16;
let epoch=0,disposed=false;
const readable=computed(()=>props.installed&&["2.0.0","2.1.0","2.2.0","2.3.0"].includes(props.version||""));
const selectedCurrent=computed(()=>selected.value&&known.value&&inventory.value?.apache_transactions.find(row=>row.transaction_id===selected.value?.transaction_id&&row.transaction_sha256===selected.value?.transaction_sha256&&row.transaction_archived===selected.value?.transaction_archived));
const writable=computed(()=>!!selectedCurrent.value&&props.version==="2.3.0"&&!props.parentBusy&&!busy.value&&
  inventory.value?.transaction_replay_ready&&(selectedCurrent.value.transaction_archived||selectedCurrent.value.transaction_archivable)&&
  confirm.value===`ARCHIVE APACHE TRANSACTION ${selectedCurrent.value.transaction_id}`);
const label=(state:string)=>({committed:"已提交",recovered:"已恢复",applying:"未结束"}[state]||"未知状态");
const bytes=(n:number)=>n<1048576?`${(n/1024).toFixed(2)} KiB`:`${(n/1048576).toFixed(2)} MiB`;
function choose(row:ApacheTransactionRow){if(busy.value||!known.value)return;selected.value={...row};confirm.value="";receipt.value=undefined;error.value="";operationError.value="";}
async function refresh(){
  if(disposed||!props.active||!readable.value||busy.value||props.parentBusy)return;
  const ticket=epoch,offset=(page.value-1)*limit;
  busy.value=true;known.value=false;error.value="";
  try{
    const out=await props.api<unknown>(`/software/apache-waf/transactions${apacheTransactionQuery(limit,offset)}`);
    if(disposed||ticket!==epoch)return;
    if(!apacheTransactionInventory(out,limit,offset))throw new Error("事务库存响应或分页身份无法核验，未返回部分统计");
    inventory.value=out;known.value=true;
  }catch(e){if(!disposed&&ticket===epoch){error.value=(e as Error).message;known.value=false;}}
  finally{if(ticket===epoch)busy.value=false;}
}
async function archive(){
  if(!writable.value||!selectedCurrent.value)return;
  const row={...selectedCurrent.value},body=apacheArchiveBody(row,confirm.value),ticket=epoch;
  busy.value=true;error.value="";operationError.value="";receipt.value=undefined;
  try{
    const out=await props.api<unknown>("/software/apache-waf/archive-transaction","POST",body);
    if(disposed||ticket!==epoch)return;
    if(!apacheArchiveReceipt(out,row))throw new Error("原归档回执无法核验，操作可能已完成；请刷新后按同一标识和摘要核对");
    receipt.value=out;selected.value=undefined;confirm.value="";known.value=false;
  }catch(e){if(!disposed&&ticket===epoch){operationError.value=`${(e as Error).message}；未宣称归档成功。保留原标识与摘要，先刷新库存，再由你核对原归档；不会自动重试。`;known.value=false;}}
  finally{if(ticket===epoch)busy.value=false;}
  if(!disposed&&ticket===epoch&&receipt.value)await refresh();
}
watch(()=>[props.active,props.installed,props.version],async()=>{
  epoch++;busy.value=false;known.value=false;inventory.value=undefined;receipt.value=undefined;selected.value=undefined;confirm.value="";error.value="";operationError.value="";page.value=1;
  if(props.active&&readable.value)await refresh();
},{immediate:true});
watch(()=>props.parentBusy,(value)=>{if(!value&&props.active&&readable.value&&!known.value)void refresh();});
onUnmounted(()=>{disposed=true;epoch++;});
</script>

<template>
  <section aria-label="Apache 配置事务维护">
    <el-alert v-if="!readable" title="先安装已知版本 Apache WAF。旧版 2.0 / 2.1 / 2.2 仅查看，签名升级到 2.3.0 后开放归档，不以面板版本冒充应用已升级。" type="info" :closable="false"/>
    <div class="actions"><p>完整核对三文件事务后返回分页元数据，不显示配置备份内容。</p><el-button :loading="busy" :disabled="!readable || parentBusy" @click="refresh">刷新 Apache 事务库存</el-button></div>
    <el-alert v-if="error" :title="error" type="error" :closable="false"/>
    <el-alert v-if="operationError" :title="operationError" type="error" :closable="false"/>
    <el-alert v-if="!known && inventory" title="库存未核验，旧统计不能当作最新结果，维护暂停。" type="warning" :closable="false"/>
    <template v-if="known && inventory">
      <p>活动 {{inventory.transaction_active_count}} / 100 份 · {{bytes(inventory.transaction_active_bytes)}} / 128 MiB；归档 {{inventory.transaction_archive_count}} / 512 份 · {{bytes(inventory.transaction_archive_bytes)}} / 256 MiB；剩余条数槽位 {{inventory.transaction_slots_available}}（仍需满足字节预算）。</p>
      <el-alert v-if="inventory.transaction_archive_blocked" :title="inventory.transaction_archive_blocked" type="warning" :closable="false"/>
      <el-table :data="inventory.apache_transactions" max-height="340" empty-text="完整核对后没有事务" @row-click="choose">
        <el-table-column prop="transaction_id" label="原事务标识" min-width="265"/>
        <el-table-column label="状态" min-width="115"><template #default="{row}">{{label(row.transaction_state)}} · {{row.transaction_archived?'归档':'活动'}}</template></el-table-column>
        <el-table-column label="时间" min-width="160"><template #default="{row}">{{formatPanelDateTime(row.created_at)}}</template></el-table-column>
        <el-table-column label="完整记录大小" min-width="130"><template #default="{row}">{{bytes(row.transaction_bytes)}}</template></el-table-column>
        <el-table-column label="维护" min-width="120"><template #default="{row}"><el-button :disabled="busy || parentBusy || !inventory.transaction_replay_ready || (!row.transaction_archived && !row.transaction_archivable)" @click.stop="choose(row)">{{row.transaction_archived?'核对原归档':'选择归档'}}</el-button></template></el-table-column>
      </el-table>
      <el-pagination v-model:current-page="page" :page-size="limit" :total="inventory.total" :disabled="busy || parentBusy" layout="total, prev, pager, next" @current-change="selected=undefined;confirm='';refresh()"/>
    </template>
    <div v-if="selected" class="selection">
      <h4>{{selected.transaction_archived?'核对原归档（不再移动）':'归档所选已结束事务'}}</h4>
      <p>原标识：<code>{{selected.transaction_id}}</code></p><p>完整原文件 SHA-256：<code>{{selected.transaction_sha256}}</code></p>
      <p>仅无覆盖移动原记录。不会修改网站、重载 Apache / Nginx 或删除备份。未知条目、链接、损坏内容或待恢复事务会拒绝维护。</p>
      <label :for="'apache-archive-confirm'">精确填写 ARCHIVE APACHE TRANSACTION {{selected.transaction_id}}</label>
      <el-input id="apache-archive-confirm" v-model="confirm" :disabled="busy || parentBusy" :maxlength="64" autocomplete="off" aria-label="Apache 原事务归档确认"/>
      <el-button type="warning" :loading="busy" :disabled="!writable" @click="archive">{{selected.transaction_archived?'按原标识和摘要核对':'归档完整原事务'}}</el-button>
    </div>
    <el-alert v-if="receipt" :title="receipt.replayed?'已核对原归档；没有再次移动或创建新事务。':'已核对完整原事务归档；配置未修改，备份未删除。'" type="success" :closable="false"/>
    <p>这是本机有界逻辑预算，不是内核硬配额，也不是外部异地备份。归档满额停止，不自动清理证据。旧 config-backups 保持原样、不纳入此库存；2.3.0 的新修改仅使用完整持久化事务，避免重复生成另一套无法维护的备份。</p>
  </section>
</template>

<style scoped>
section{min-width:0}.actions{display:flex;gap:12px;align-items:center;justify-content:space-between;flex-wrap:wrap}p{line-height:1.7;overflow-wrap:anywhere}code{word-break:break-all}.selection{padding:14px;border:1px solid var(--el-border-color);border-radius:8px;margin-block:14px}.selection label{display:block;overflow-wrap:anywhere;line-height:1.7}.selection .el-input{margin:8px 0 12px}:deep(.el-alert){margin-block:12px}:deep(.el-pagination){flex-wrap:wrap;max-width:100%;margin-block:12px}@media(max-width:720px){.selection{padding:10px}.actions .el-button{max-width:100%}}
</style>
