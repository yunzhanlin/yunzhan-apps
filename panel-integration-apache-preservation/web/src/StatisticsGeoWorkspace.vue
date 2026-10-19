<script setup lang="ts">
import {onMounted,onUnmounted,ref,watch} from 'vue';
import StatisticsGeoJobRecords from './StatisticsGeoJobRecords.vue';
import {IndexedStatisticsGeoStorage,StatisticsGeoRequestIdentity,type StatisticsGeoSelection as Selection,type StatisticsGeoTicket,type StatisticsGeoOutcome} from './statisticsGeoIdentity';
import {randomId} from './randomId';
type API=<T>(path:string,method?:string,body?:unknown,key?:string,signal?:AbortSignal)=>Promise<T>;
type Stored={release:string;manifest_sha256:string;app_manifest_sha256:string;selected:boolean;archived?:boolean;previous?:boolean;high_water?:boolean};
type Page={state:{installed:boolean;app_version:string;installation_id:string;loading:boolean;error?:string;checked_at:string;metadata:{available:boolean;release?:string;stale?:boolean};stored:Stored[]};available?:{app_version:string;app_manifest_sha256:string;manifest_sha256:string;manifest:{release:string;compressed_bytes:number}}|null;source_error:string;jobs:{id:string;state:string;error:string;created_at:string}[]};
const props=defineProps<{api:API;onJob:(id:string)=>Promise<void>;actor:string}>();
const page=ref<Page>(),busy=ref(false),error=ref(''),pending=ref<StatisticsGeoTicket>(),outcome=ref<StatisticsGeoOutcome>(),blocked=ref(false);
const storage=new IndexedStatisticsGeoStorage();
const identity=()=>new StatisticsGeoRequestIdentity(storage,props.actor,randomId);
let generation=0,abort=new AbortController();
function reset(){generation++;abort.abort();abort=new AbortController();page.value=undefined;pending.value=undefined;outcome.value=undefined;busy.value=blocked.value=false;error.value='';}
watch(()=>props.actor,()=>{reset();void refresh();});onUnmounted(reset);
async function checkOriginal(context:StatisticsGeoRequestIdentity,g:number){
  const original=pending.value;if(!original)return;
  const reply=await props.api<StatisticsGeoOutcome>(`/software/website-statistics-v2/geodata/requests/${original.key}`,'GET',undefined,undefined,abort.signal);
  if(g!==generation)return;
  const next=await context.observe(reply);if(g!==generation)return;
  pending.value=next;outcome.value=reply;
}
async function refresh(){
  if(busy.value)return;const g=++generation;abort.abort();abort=new AbortController();busy.value=true;error.value='';blocked.value=true;outcome.value=undefined;
  try{const context=identity(),original=await context.read();if(g!==generation)return;pending.value=original;await checkOriginal(context,g);if(g!==generation)return;
    const value=await props.api<Page>('/software/website-statistics-v2/geodata','GET',undefined,undefined,abort.signal);if(g!==generation)return;
    if(!value||!value.state||!Array.isArray(value.state.stored)||!Array.isArray(value.jobs))throw new Error('地域数据状态格式不能核对');page.value=value;blocked.value=false;
  }catch(e){if(g===generation)error.value=`${(e as Error).message}。未新建或重发任务；保留浏览器原记录。`;}finally{if(g===generation)busy.value=false;}
}
async function submit(selection:Selection){
  if(busy.value||blocked.value)return;const g=generation;busy.value=true;error.value='';
  try{const context=identity(),original=await context.begin(selection);if(g!==generation)return;if(!original)throw new Error('原提交记录没有完成持久化');pending.value=original;
    if(original.job){await props.onJob(original.job);return;}
    const result=await props.api<{job_id:string}>('/software/website-statistics-v2/geodata','POST',original.selection,original.key,abort.signal);if(g!==generation)return;
    const accepted=await context.accepted(original,result?.job_id);if(g!==generation)return;pending.value=accepted;
    await props.onJob(result.job_id);if(g!==generation)return;await checkOriginal(context,g);
  }catch(e){if(g===generation)error.value=`${(e as Error).message}。保留原编号；可只读核对原请求，不新建另一份任务。`;}finally{if(g===generation)busy.value=false;}
  if(g===generation&&!pending.value)await refresh();
}
function install(){const p=page.value;if(!p?.available)return;void submit({action:'install',app_version:p.available.app_version,app_manifest_sha256:p.available.app_manifest_sha256,installation_id:p.state.installation_id,release:p.available.manifest.release,data_manifest_sha256:p.available.manifest_sha256});}
function rollback(row:Stored){const p=page.value;if(!p)return;void submit({action:'rollback',app_version:p.state.app_version,app_manifest_sha256:row.app_manifest_sha256,installation_id:p.state.installation_id,release:row.release,data_manifest_sha256:row.manifest_sha256});}
function maintain(row:Stored,action:'archive'|'restore'){const p=page.value;if(!p)return;void submit({action,app_version:p.state.app_version,app_manifest_sha256:row.app_manifest_sha256,installation_id:p.state.installation_id,release:row.release,data_manifest_sha256:row.manifest_sha256});}
onMounted(refresh);
</script>
<template>
  <section class="geo-workspace" aria-label="统计地域数据管理">
    <h3>离线 IP 地域数据</h3><p>仅管理员可管理。下载和完整校验在限时后台进程中执行；只有原始应用与数据签名、安装实例、字节数和完整库都核对后才切换。失败保留旧库，不改网站或自动安装应用。</p>
    <p>城市及坐标是网络地址近似位置，不是设备定位；历史 IP 使用当前所示月份的库查询，不能作为历史时刻的定位证据。<a href="https://db-ip.com/" target="_blank" rel="noopener noreferrer">IP Geolocation by DB-IP</a> · <a href="https://creativecommons.org/licenses/by/4.0/" target="_blank" rel="noopener noreferrer">CC BY 4.0</a>。</p>
    <el-alert v-if="error" type="error" :title="error" :closable="false" />
    <el-button :loading="busy" @click="refresh">刷新数据与原任务状态</el-button>
    <section v-if="pending" aria-live="polite"><p>已持久保留原编号：<code>{{pending.key}}</code><span v-if="pending.job"> · 原任务：<code>{{pending.job}}</code></span>。刷新、切换实例或退出账户不会删除原记录。</p><el-button :disabled="busy" @click="refresh">只读核对原请求</el-button><el-button v-if="pending.job" :disabled="busy" @click="onJob(pending.job)">查看原任务</el-button><el-button v-else type="warning" :disabled="busy||blocked" @click="submit(pending.selection)">恢复原提交（同一编号与选项）</el-button><p>恢复只复用原编号；已存在时只返回原任务。服务端保留不确定状态或审计冲突时拒绝新任务，不会重新执行原生操作。</p></section>
    <p v-if="outcome">原请求记录：{{outcome.state_known?({queued:'排队中',running:'运行中',succeeded:'成功',failed:'失败',needs_attention:'待核对'} as Record<string,string>)[outcome.state]:'尚不能确认是否已提交'}}；不是当前已选择城市库的证明。</p>
    <template v-if="page">
      <el-alert v-if="!page.state.installed||page.state.app_version!=='2.6.0'" type="info" title="需要明确安装或升级统计2.6；更新面板不会自动升级旧版应用或开启地域数据。" :closable="false" />
      <template v-else>
        <el-alert v-if="page.state.error" type="warning" :title="page.state.error" :closable="false" />
        <p>后台读取：{{page.state.loading?'完整库核对中':'未在读取'}}；报表内存库：{{page.state.metadata.available?page.state.metadata.release:'尚不可用'}}；最近核对：{{page.state.checked_at||'尚未完成'}}。</p>
        <el-alert v-if="page.source_error" type="warning" :title="`最新签名目录待核对：${page.source_error}`" :closable="false" />
        <div v-if="page.available" class="geo-available"><span>已验签数据月份：{{page.available.manifest.release}} · 下载约 {{(page.available.manifest.compressed_bytes/1048576).toFixed(1)}} MiB</span><el-button type="primary" :disabled="busy||!!pending||blocked" @click="install">下载或切换已签名城市库</el-button></div>
        <p>活动区最多8份；私有归档区最多24份。归档只移动并保留完整原副本，不切换数据；当前、上一份及最高签名月份的防重放锚点禁止归档。恢复只返回活动区，回滚需另行明确提交。归档满后仍需后续导出与受控清理，不会自动删除数据。</p>
        <el-table :data="page.state.stored" empty-text="没有已保留副本"><el-table-column prop="release" label="数据月份" width="110"/><el-table-column label="位置／保护" min-width="185"><template #default="{row}">{{row.archived?'私有归档':'活动区'}}<small>{{[row.selected?'当前选择':'',row.previous?'上一份':'',row.high_water?'防重放锚点':''].filter(Boolean).join(' · ')}}</small></template></el-table-column><el-table-column label="操作" min-width="240"><template #default="{row}"><el-button v-if="!row.archived" :disabled="busy||!!pending||blocked||row.selected" @click="rollback(row)">核对并回滚到此副本</el-button><el-button v-if="row.archived!==undefined" :disabled="busy||!!pending||blocked||!row.archived&&(row.selected||row.previous||row.high_water)" @click="maintain(row,row.archived?'restore':'archive')">{{row.archived?'恢复副本（不切换）':'归档旧副本（不删除）'}}</el-button></template></el-table-column></el-table>
        <p>回滚不会删除较新库或降低防重放记录。内存报表读取可能晚于提交完成；以实际报表的库月份、错误与后台核对状态为准。</p>
      </template>
      <h4>保留的后台任务</h4><el-table :data="page.jobs" empty-text="没有地域后台任务"><el-table-column prop="created_at" label="创建时间" min-width="165"/><el-table-column label="状态" min-width="90"><template #default="{row}">{{({succeeded:'成功',failed:'失败',queued:'排队中',running:'运行中',needs_attention:'待核对'} as Record<string,string>)[row.state]||'状态待核对'}}</template></el-table-column><el-table-column prop="error" label="告警" min-width="145"/><el-table-column label="查看" width="120"><template #default="scope"><el-button @click="onJob(scope.row.id)">查看原任务</el-button></template></el-table-column></el-table>
      <StatisticsGeoJobRecords :api="api" :on-job="onJob"/>
    </template>
  </section>
</template>
<style scoped>
.geo-workspace{min-width:0}.geo-workspace p{line-height:1.7;color:var(--el-text-color-secondary);overflow-wrap:anywhere}.geo-workspace .el-alert{margin:12px 0}.geo-available{display:flex;gap:12px;align-items:center;justify-content:space-between;margin:16px 0}.geo-available span{overflow-wrap:anywhere}
.geo-workspace small{display:block;overflow-wrap:anywhere}.geo-workspace :deep(.el-table .cell){overflow-wrap:anywhere}
@media(max-width:640px){.geo-available{flex-direction:column;align-items:flex-start}}
</style>
