<script setup lang="ts">
import {onUnmounted,ref,watch} from "vue";
import {formatPanelDateTime} from "./panelTime";
import {readWafOriginalPage,readWafOriginalRequest,type WafApplyEngine,type WafOriginalPage,type WafOriginalRequest,type WafOriginalSummary} from "./wafApplyRecovery";
type API=<T>(path:string,method?:string,body?:unknown,key?:string)=>Promise<T>;
const props=defineProps<{api:API;engine:WafApplyEngine;active:boolean;blocked:boolean}>();
const emit=defineEmits<{restore:[original:WafOriginalRequest]}>();
const page=ref<WafOriginalPage>(),error=ref(""),busy=ref(false);
let disposed=false,generation=0;
const stateLabel=(v:string)=>({queued:"已入队",running:"执行中",succeeded:"任务已完成，生效仍须核对",failed:"任务失败",needs_attention:"结果未知，需核对",cancelled:"任务已取消"}[v]||"未知");
async function load(cursor=""){
  if(disposed||!props.active||busy.value)return;
  const token=++generation,current=()=>!disposed&&props.active&&token===generation;
  busy.value=true;page.value=undefined;error.value="";
  try{const out=await readWafOriginalPage(props.api,current,props.engine,cursor);if(current())page.value=out;}
  catch(e){if(current())error.value=e instanceof Error?e.message:"当前账户的原请求目录不可核对。";}
  finally{if(current())busy.value=false;}
}
async function restore(row:WafOriginalSummary){
  if(disposed||!props.active||busy.value||props.blocked)return;
  const token=++generation,current=()=>!disposed&&props.active&&token===generation;
  busy.value=true;error.value="";
  try{
    const original=await readWafOriginalRequest(props.api,current,props.engine,row);
    // A different action may have acquired an unresolved identity while this
    // read was outstanding. It must never be overwritten by the late detail.
    if(!current()||props.blocked)return;
    emit("restore",original); // Adoption only. No apply, POST or automatic job polling.
  }catch(e){if(current())error.value=e instanceof Error?e.message:"原任务身份或配置不可完整核对。";}
  finally{if(current())busy.value=false;}
}
function invalidate(){generation++;page.value=undefined;error.value="";busy.value=false;}
watch(()=>props.active,active=>{if(active)void load();else invalidate();},{immediate:true});
onUnmounted(()=>{disposed=true;invalidate();});
</script>
<template>
 <section class="waf-apply-recovery" aria-label="当前账户原任务恢复" :aria-busy="busy">
  <div class="recovery-heading"><h4>当前账户的原安装与配置请求</h4><el-button :loading="busy" :disabled="!active" @click="load()">只读核对原请求目录</el-button></div>
  <el-alert title="仅列出当前账户的绑定记录与旧版签名仓库安装记录。目录状态、签名安装绑定和原配置都不是软件安装或防护生效回执；恢复只载入已知原任务，再显式点击“核对原任务”读取结果及当前配置。不自动安装、配置、预览、重发或删除记录。未入队或旧版未绑定的请求可能不在目录中，空目录不代表没有提交。" type="info" :closable="false"/>
  <el-alert v-if="blocked" title="本工作区已有待核对请求或操作正在进行，不能用另一个记录替换它。目录仍可只读查看；必要时在独立工作区选择服务端原任务。" type="warning" :closable="false"/>
  <el-alert v-if="error" :title="error" type="error" :closable="false"/>
  <p v-if="busy" role="status">正在只读核对原请求身份；尚未恢复或宣称操作成功。</p>
  <template v-else-if="page">
   <p>本页 {{page.entries.length}} 条绑定记录；每页最多 20 条，只代表本次读取，不代表全账户或全部软件验收。</p>
   <el-table class="original-table" :data="page.entries" max-height="420" empty-text="本页未找到当前账户的绑定记录；不能据此认定没有提交">
    <el-table-column label="原任务标识" min-width="235"><template #default="{row}"><code>{{row.id}}</code></template></el-table-column>
    <el-table-column label="请求类型" width="100"><template #default="{row}">{{row.kind==='software_install'?'安装':'配置'}}</template></el-table-column>
    <el-table-column label="创建时间" min-width="170"><template #default="{row}">{{formatPanelDateTime(row.created_at)}}</template></el-table-column>
    <el-table-column label="本次任务状态" min-width="190"><template #default="{row}">{{stateLabel(row.state)}}</template></el-table-column>
    <el-table-column label="原请求完整摘要" min-width="250"><template #default="{row}"><code>{{row.request_sha256}}</code></template></el-table-column>
    <el-table-column label="签名安装请求绑定" width="150"><template #default="{row}">{{row.signed_install_binding?'绑定已核对，非安装回执':row.kind==='software_install'?'直接安装，非签名安装证明':'非安装请求'}}</template></el-table-column>
    <el-table-column label="操作" width="155" fixed="right"><template #default="{row}"><el-button link type="primary" :disabled="busy || blocked || !active" @click="restore(row)">仅恢复此原任务</el-button></template></el-table-column>
   </el-table>
   <div class="original-cards">
    <p v-if="!page.entries.length">本页未找到当前账户的绑定记录；不能据此认定没有提交。</p>
    <article v-for="row in page.entries" :key="row.id" :aria-labelledby="engine+'-original-'+row.id">
     <h5 :id="engine+'-original-'+row.id">{{row.kind==='software_install'?'原安装任务':'原配置任务'}}</h5>
     <dl>
      <dt>原任务标识</dt><dd><code>{{row.id}}</code></dd>
      <dt>创建时间</dt><dd>{{formatPanelDateTime(row.created_at)}}</dd>
      <dt>本次任务状态</dt><dd>{{stateLabel(row.state)}}</dd>
      <dt>原请求完整摘要</dt><dd><code>{{row.request_sha256}}</code></dd>
      <dt>签名安装请求绑定</dt><dd>{{row.signed_install_binding?'绑定已核对，非安装回执':row.kind==='software_install'?'直接安装，非签名安装证明':'非安装请求'}}</dd>
     </dl>
     <el-button :disabled="busy || blocked || !active" @click="restore(row)">仅恢复此原任务</el-button>
    </article>
   </div>
   <div class="recovery-actions"><el-button v-if="page.next_cursor" :disabled="busy || !active" @click="load(page.next_cursor)">只读读取下一页</el-button></div>
  </template>
  <p v-else-if="!busy && !error">原请求目录尚未读取，不显示旧数据或空目录结论。</p>
 </section>
</template>
<style scoped>
.waf-apply-recovery{min-width:0}.recovery-heading{display:flex;justify-content:space-between;align-items:center;gap:12px;flex-wrap:wrap}.recovery-heading h4{margin:0}.waf-apply-recovery :deep(.el-alert){margin:12px 0}.waf-apply-recovery p{line-height:1.7}.waf-apply-recovery :deep(.el-table){max-width:100%}.waf-apply-recovery :deep(.el-button.is-disabled){color:#737d78}.recovery-actions{margin-top:12px}code{font-size:12px;overflow-wrap:anywhere}.original-cards{display:none}.original-cards article{border:1px solid var(--border-color,#dfe8e3);border-radius:8px;padding:14px;margin:12px 0;min-width:0}.original-cards h5{font-size:14px;margin:0 0 12px}.original-cards dl{margin:0}.original-cards dt{font-size:12px;color:#6b8075;margin-top:10px}.original-cards dd{margin:4px 0 12px;line-height:1.6;overflow-wrap:anywhere}@media(max-width:600px){.recovery-heading{align-items:flex-start}.waf-apply-recovery p{font-size:12px}.original-table{display:none}.original-cards{display:block}}
</style>
