<script setup lang="ts">
import {onMounted,ref} from 'vue';
import StatisticsGeoJobRecords from './StatisticsGeoJobRecords.vue';
type API=<T>(path:string,method?:string,body?:unknown,key?:string)=>Promise<T>;
type Stored={release:string;manifest_sha256:string;app_manifest_sha256:string;selected:boolean};
type Selection={action:'install'|'rollback';app_version:string;app_manifest_sha256:string;installation_id:string;release:string;data_manifest_sha256:string};
type Page={state:{installed:boolean;app_version:string;installation_id:string;loading:boolean;error?:string;checked_at:string;metadata:{available:boolean;release?:string;stale?:boolean};stored:Stored[]};available?:{app_version:string;app_manifest_sha256:string;manifest_sha256:string;manifest:{release:string;compressed_bytes:number}}|null;source_error:string;jobs:{id:string;state:string;error:string;created_at:string}[]};
const props=defineProps<{api:API;onJob:(id:string)=>Promise<void>}>();
const page=ref<Page>(),busy=ref(false),error=ref(''),pending=ref<{selection:Selection;key:string}>();
const validSHA=(v:unknown):v is string=>typeof v==='string'&&/^[a-f0-9]{64}$/.test(v);
const validID=(v:unknown):v is string=>typeof v==='string'&&/^[a-f0-9]{32}$/.test(v);
async function refresh(){busy.value=true;error.value='';try{const value=await props.api<Page>('/software/website-statistics-v2/geodata');if(!value||!value.state||!Array.isArray(value.state.stored)||!Array.isArray(value.jobs))throw new Error('地域数据状态格式不能核对');page.value=value;}catch(e){error.value=(e as Error).message;}finally{busy.value=false;}}
async function submit(selection:Selection){
  if(busy.value)return;
  if(selection.app_version!=='2.6.0'||!validID(selection.installation_id)||!validSHA(selection.app_manifest_sha256)||!validSHA(selection.data_manifest_sha256)||!/^20[2-9][0-9]-(0[1-9]|1[0-2])$/.test(selection.release)){error.value='地域任务的应用实例或签名摘要无效，请刷新';return;}
  if(pending.value&&JSON.stringify(pending.value.selection)!==JSON.stringify(selection)){error.value='上一次提交回执未核对，请先使用原键重试；不新建另一份任务';return;}
  pending.value??={selection:{...selection},key:crypto.randomUUID()};busy.value=true;error.value='';
  try{const result=await props.api<{job_id:string}>('/software/website-statistics-v2/geodata','POST',pending.value.selection,pending.value.key);if(!validID(result?.job_id))throw new Error('提交回执没有有效任务ID，原提交键已保留');pending.value=undefined;await props.onJob(result.job_id);}catch(e){error.value=(e as Error).message;}finally{busy.value=false;}
  if(!pending.value)await refresh();
}
function install(){const p=page.value;if(!p?.available)return;void submit({action:'install',app_version:p.available.app_version,app_manifest_sha256:p.available.app_manifest_sha256,installation_id:p.state.installation_id,release:p.available.manifest.release,data_manifest_sha256:p.available.manifest_sha256});}
function rollback(row:Stored){const p=page.value;if(!p)return;void submit({action:'rollback',app_version:p.state.app_version,app_manifest_sha256:row.app_manifest_sha256,installation_id:p.state.installation_id,release:row.release,data_manifest_sha256:row.manifest_sha256});}
onMounted(refresh);
</script>
<template>
  <section class="geo-workspace" aria-label="统计地域数据管理">
    <h3>离线 IP 地域数据</h3><p>仅管理员可管理。下载和完整校验在限时后台进程中执行；只有原始应用与数据签名、安装实例、字节数和完整库都核对后才切换。失败保留旧库，不改网站或自动安装应用。</p>
    <p>城市及坐标是网络地址近似位置，不是设备定位；历史 IP 使用当前所示月份的库查询，不能作为历史时刻的定位证据。<a href="https://db-ip.com/" target="_blank" rel="noopener noreferrer">IP Geolocation by DB-IP</a> · <a href="https://creativecommons.org/licenses/by/4.0/" target="_blank" rel="noopener noreferrer">CC BY 4.0</a>。</p>
    <el-alert v-if="error" type="error" :title="error" :closable="false" />
    <el-button :loading="busy" @click="refresh">刷新数据与原任务状态</el-button>
    <el-button v-if="pending" type="warning" :disabled="busy" @click="submit(pending.selection)">使用原提交键核对</el-button>
    <template v-if="page">
      <el-alert v-if="!page.state.installed||page.state.app_version!=='2.6.0'" type="info" title="需要明确安装或升级统计2.6；更新面板不会自动升级旧版应用或开启地域数据。" :closable="false" />
      <template v-else>
        <el-alert v-if="page.state.error" type="warning" :title="page.state.error" :closable="false" />
        <p>后台读取：{{page.state.loading?'完整库核对中':'未在读取'}}；报表内存库：{{page.state.metadata.available?page.state.metadata.release:'尚不可用'}}；最近核对：{{page.state.checked_at||'尚未完成'}}。</p>
        <el-alert v-if="page.source_error" type="warning" :title="`最新签名目录待核对：${page.source_error}`" :closable="false" />
        <div v-if="page.available" class="geo-available"><span>已验签数据月份：{{page.available.manifest.release}} · 下载约 {{(page.available.manifest.compressed_bytes/1048576).toFixed(1)}} MiB</span><el-button type="primary" :disabled="busy||!!pending" @click="install">下载或切换已签名城市库</el-button></div>
        <el-table :data="page.state.stored" empty-text="没有已保留副本"><el-table-column prop="release" label="数据月份" /><el-table-column label="当前选择"><template #default="scope">{{scope.row.selected?'是':'否'}}</template></el-table-column><el-table-column label="操作"><template #default="scope"><el-button :disabled="busy||!!pending||scope.row.selected" @click="rollback(scope.row)">核对并回滚到此副本</el-button></template></el-table-column></el-table>
        <p>回滚不会删除较新库或降低防重放记录。内存报表读取可能晚于提交完成；以实际报表的库月份、错误与后台核对状态为准。</p>
      </template>
      <h4>保留的后台任务</h4><el-table :data="page.jobs" empty-text="没有地域后台任务"><el-table-column prop="created_at" label="创建时间" /><el-table-column prop="state" label="状态" /><el-table-column prop="error" label="告警" /><el-table-column label="查看"><template #default="scope"><el-button @click="onJob(scope.row.id)">查看原任务</el-button></template></el-table-column></el-table>
      <StatisticsGeoJobRecords :api="api" :on-job="onJob"/>
    </template>
  </section>
</template>
<style scoped>
.geo-workspace{min-width:0}.geo-workspace p{line-height:1.7;color:var(--el-text-color-secondary);overflow-wrap:anywhere}.geo-workspace .el-alert{margin:12px 0}.geo-available{display:flex;gap:12px;align-items:center;justify-content:space-between;margin:16px 0}.geo-available span{overflow-wrap:anywhere}
@media(max-width:640px){.geo-available{flex-direction:column;align-items:flex-start}}
</style>
