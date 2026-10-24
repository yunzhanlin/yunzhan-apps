<script setup lang="ts">
import {computed,onBeforeUnmount,ref,watch} from "vue";
import {apacheBodyBuildInventory,type ApacheBodyBuild} from "./apacheBodyBuild";
import {apacheBodyPolicyAddSite,apacheBodyPolicySupported,type ApacheBodyPolicyDraft} from "./apacheBodyPolicy";
type API=<T>(path:string,method?:string,body?:unknown,key?:string)=>Promise<T>;
const props=defineProps<{api:API;active:boolean;installed:unknown;version:unknown;implementation:unknown;settings:{body?:ApacheBodyPolicyDraft};sites:{id:string;domain:string;status:string}[];parentBusy:boolean}>();
const emit=defineEmits<{"request-build":[]}>();
const supported=computed(()=>apacheBodyPolicySupported(props.installed,props.version,props.implementation));
const rows=ref<ApacheBodyBuild[]>([]),known=ref(false),reading=ref(false),error=ref(""),selectedSite=ref("");
const ready=computed(()=>known.value?rows.value.filter(row=>row.state==="ready"):[]);
let epoch=0,disposed=false;
async function refresh(){
 if(!props.active || !supported.value || reading.value)return;
 const ticket=epoch;reading.value=true;known.value=false;error.value="";
 try{
  const out=await props.api<unknown>("/software/apache-waf/body-engines");
  if(disposed || !props.active || ticket!==epoch)return;
  if(!apacheBodyBuildInventory(out))throw Error("完整引擎库存无法核实，没有使用缓存或部分列表");
  rows.value=out.entries;known.value=true;
 }catch(e){if(ticket===epoch)error.value=(e as Error).message;}
 finally{if(ticket===epoch)reading.value=false;}
}
function chooseEngine(id:string){
 if(!supported.value || props.parentBusy || !known.value || !ready.value.some(row=>row.job_id===id)){error.value="所选引擎未通过本次完整库存核对，草稿未改变";return;}
 props.settings.body={engine_job_id:id,sites:props.settings.body?.sites.map(s=>({site_id:s.site_id,policy:{...s.policy}})) || []};
}
function addSite(){
 if(!supported.value || props.parentBusy || !known.value || !ready.value.some(row=>row.job_id===props.settings.body?.engine_job_id)){error.value="先核对并选择完整有效的原生引擎";return;}
 try{props.settings.body=apacheBodyPolicyAddSite(props.settings.body,selectedSite.value,props.sites);selectedSite.value="";error.value="";}
 catch(e){error.value=(e as Error).message;}
}
function removeSite(id:string){
 if(!supported.value || props.parentBusy || !props.settings.body)return;
 props.settings.body={engine_job_id:props.settings.body.engine_job_id,sites:props.settings.body.sites.filter(s=>s.site_id!==id)};
}
watch([()=>props.active,supported],()=>{epoch++;known.value=false;rows.value=[];reading.value=false;error.value="";if(props.active&&supported.value)void refresh();},{immediate:true});
onBeforeUnmount(()=>{disposed=true;epoch++;});
</script>

<template>
 <section class="apache-policy">
  <el-alert v-if="!supported" type="warning" :closable="false" title="只有已安装且与面板实现一致的Apache WAF 2.4.0签名应用可配置请求体策略。构建成功或更新面板不能提升元数据2.3应用的能力。"/>
  <template v-else>
   <el-alert type="info" :closable="false" title="仅修改草稿。先核对引擎、明确选择网站、预览，再点击上方“保存并应用”；不会因进入本页、构建或选择引擎而启用。"/>
   <div class="apache-policy-actions"><el-button :loading="reading" :disabled="parentBusy" @click="refresh">核对完整引擎库存</el-button><el-button :disabled="parentBusy" @click="emit('request-build')">前往独立引擎构建</el-button></div>
   <el-alert v-if="error" :title="error" type="error" :closable="false"/>
   <p v-if="!known" role="status">{{reading?'正在核对实际程序、ABI、完整性和编译器回收':'引擎库存未知，不代表没有引擎。当前不能选择引擎或新增启用网站。'}}</p>
   <p v-if="known && !ready.length">已核实：没有符合当前完整契约的引擎。旧版、失败或待核对记录保留，不能作为已就绪引擎。</p>
   <el-form label-position="top">
    <el-form-item label="明确选择已核验的本机Apache引擎"><el-select :model-value="settings.body?.engine_job_id || ''" :disabled="!known || reading || parentBusy" aria-label="Apache 请求体兼容引擎" placeholder="不默认选择或激活" @change="chooseEngine"><el-option v-for="row in ready" :key="row.job_id" :value="row.job_id" :label="`Apache ${row.apache_version} · ${row.architecture} · ${row.job_id.slice(0,12)}`"/></el-select></el-form-item>
   </el-form>
   <el-alert v-if="settings.body?.engine_job_id && !ready.some(row=>row.job_id===settings.body?.engine_job_id)" type="warning" :closable="false" title="原配置引用的引擎尚未通过本次库存核对。保留原标识和草稿，不自动换成另一个程序；服务端仍会重新核验原程序。"/>
   <div class="apache-policy-actions"><el-select v-model="selectedSite" :disabled="parentBusy" filterable aria-label="Apache 请求体网站" placeholder="选择明确启用的网站"><el-option v-for="site in sites" :key="site.id" :value="site.id" :label="site.domain" :disabled="site.status!=='running'"/></el-select><el-button :disabled="parentBusy || !known || !selectedSite" @click="addSite">添加观察策略</el-button></div>
   <el-table :data="settings.body?.sites || []" empty-text="没有网站选择请求体防护；不因安装应用自动启用" max-height="520">
    <el-table-column type="expand"><template #default="{row}"><el-form label-position="top" class="apache-policy-limits">
     <el-form-item label="CRS级别（越高越容易误报）"><el-input-number v-model="row.policy.paranoia_level" :disabled="parentBusy" :min="1" :max="4"/></el-form-item>
     <el-form-item label="入站异常分数阈值"><el-input-number v-model="row.policy.inbound_threshold" :disabled="parentBusy" :min="5" :max="100"/></el-form-item>
     <el-form-item label="请求体上限（KiB）"><el-input-number v-model="row.policy.body_limit_kib" :disabled="parentBusy" :min="64" :max="8192"/></el-form-item>
     <el-form-item label="非文件上限（KiB）"><el-input-number v-model="row.policy.non_file_limit_kib" :disabled="parentBusy" :min="64" :max="Math.min(2048,row.policy.body_limit_kib)"/></el-form-item>
     <el-form-item label="JSON最大深度"><el-input-number v-model="row.policy.json_depth" :disabled="parentBusy" :min="4" :max="128"/></el-form-item>
     <el-form-item label="参数数量上限"><el-input-number v-model="row.policy.argument_limit" :disabled="parentBusy" :min="16" :max="1000"/></el-form-item>
    </el-form></template></el-table-column>
    <el-table-column label="受管Apache网站" min-width="220"><template #default="{row}">{{sites.find(site=>site.id===row.site_id)?.domain || '已失效网站 '+row.site_id}}<small v-if="!sites.some(site=>site.id===row.site_id && site.status==='running')">网站未运行或已失效，不能把原策略当成生效防护</small></template></el-table-column>
    <el-table-column label="草稿模式" min-width="150"><template #default="{row}"><el-select v-model="row.policy.mode" :disabled="parentBusy" aria-label="Apache 请求体站点模式"><el-option value="observe" label="观察（规则不阻断）"/><el-option value="block" label="阻断"/><el-option value="off" label="停用"/></el-select></template></el-table-column>
    <el-table-column label="请求体预算" width="135"><template #default="{row}">{{row.policy.body_limit_kib}} KiB</template></el-table-column>
    <el-table-column width="95"><template #default="{row}"><el-button text type="danger" :disabled="parentBusy" @click="removeSite(row.site_id)">移除策略</el-button></template></el-table-column>
   </el-table>
   <p>新增策略默认观察；全局或站点的停用、观察优先，不能用请求体策略绕过。元数据白名单不跳过请求体检查。移除策略并保存会删除该网站的受管请求体区块，不删除网站、引擎、缓存或日志。</p>
   <p>使用固定开源ModSecurity v2、私有已修补YAJL及OWASP CRS。请求体缓存具有独立硬配额；缓存写入失败返回503，不把截断正文交给网站。观察模式只放行规则匹配，不能绕过服务器原生拒绝、解析上限或存储故障。旧长连接和已接收请求不被强制中断。</p>
   <p>完整配置、规则、安装记录共同备份并原子交接；原生校验、平滑重载和实际加载指纹通过后才确认成功。失败保留原任务和恢复证据。数值规则匹配记录不等于独立请求数或已确认的拦截量；Apache本版不提供CC限速。</p>
  </template>
 </section>
</template>

<style scoped>
.apache-policy{display:grid;gap:14px}.apache-policy p,.apache-policy small{color:#64748b;line-height:1.75}.apache-policy small{display:block}.apache-policy-actions{display:flex;flex-wrap:wrap;gap:10px}.apache-policy-actions .el-button{margin:0}.apache-policy-actions .el-select{min-width:240px;flex:1}.apache-policy-limits{display:grid;grid-template-columns:repeat(3,minmax(160px,1fr));gap:12px}@media(max-width:760px){.apache-policy-limits{grid-template-columns:1fr}}
</style>

