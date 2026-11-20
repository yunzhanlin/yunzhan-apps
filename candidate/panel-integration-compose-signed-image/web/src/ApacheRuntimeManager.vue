<script setup lang="ts">
import {computed,ref} from "vue";
import {parseApacheRuntimeStatus,type ApacheRuntimeStatus as Status} from "./apacheRuntime";
import {randomId} from "./randomId";
import {apacheBodyBuildInventory,type ApacheBodyBuild} from "./apacheBodyBuild";
type API=<T>(path:string,method?:string,body?:unknown,key?:string)=>Promise<T>;
const props=defineProps<{api:API;onJob:(id:string)=>unknown;onInstall:()=>unknown}>();
const visible=ref(false),busy=ref(false),known=ref(false),error=ref(""),status=ref<Status>(),engines=ref<ApacheBodyBuild[]>([]),engine=ref(""),pending=ref("");
const candidates=computed(()=>engines.value.filter(row=>row.state==="ready"&&row.apache_version==="2.4.71"&&(status.value?.waf_version!=="2.5.1"||row.native_cc_version==="1.1.0")));
const selectionReady=computed(()=>status.value?.target_installed&&status.value.service_state==="active"&&status.value.selected_id==="apache-2.4.68"&&status.value.running_id===status.value.selected_id&&(!status.value.native_engine_required||candidates.value.some(row=>row.job_id===engine.value)));

async function refresh(){
 if(busy.value)return;busy.value=true;known.value=false;error.value="";
 try{
  const actual=parseApacheRuntimeStatus(await props.api<unknown>("/runtimes/apache"));
  const next:ApacheBodyBuild[]=[];
  if(actual.native_engine_required){const inventory=await props.api<unknown>("/software/apache-waf/body-engines");if(!apacheBodyBuildInventory(inventory))throw Error("完整兼容引擎库存不能核实");next.push(...inventory.entries)}
  status.value=actual;engines.value=next;known.value=true;
  if(!pending.value&&!candidates.value.some(row=>row.job_id===engine.value))engine.value="";
 }catch(e){error.value=(e as Error).message}finally{busy.value=false}
}
async function open(){visible.value=true;await refresh()}
async function activate(){
 if(busy.value||!known.value||!selectionReady.value)return;
 busy.value=true;error.value="";pending.value ||= randomId();
 try{
  const result=await props.api<{job_id:string}>("/runtimes/apache/switch","POST",{release_id:"apache-2.4.71",engine_job_id:status.value?.native_engine_required?engine.value:""},pending.value);
  if(!result||!/^[a-f0-9]{32}$/.test(result.job_id))throw Error("原任务响应无法核实");
  pending.value="";visible.value=false;await props.onJob(result.job_id);
 }catch(e){error.value=`提交未确认：${(e as Error).message}。再次点击沿用原请求标识核对，不另建切换。`}finally{busy.value=false}
}
defineExpose({open});
</script>
<template>
 <el-dialog v-model="visible" title="Apache · 运行版本" width="min(760px,96vw)" :close-on-click-modal="!busy">
  <div class="apache-runtime-manager">
   <p>安装新版本后，在这里切换共享 Apache 服务。切换会短暂重启 Apache；现有网站文件、PHP 绑定、改写规则、原程序与防护日志保留。</p>
   <el-alert v-if="error" type="error" :title="error" :closable="false"/>
   <p v-if="!known" role="status">{{busy?'正在核对实际可执行程序与配置':'实际运行版本尚未核实'}}</p>
   <template v-if="known&&status">
    <dl><dt>配置选择</dt><dd>{{status.selected_id}}</dd><dt>实际主进程</dt><dd>{{status.running_id||'未运行'}} · {{status.service_state}}</dd><dt>推荐版本</dt><dd>Apache 2.4.71 · {{status.target_installed?'已完整安装':'尚未安装'}}</dd></dl>
    <el-alert :type="status.activation_needed?'warning':'success'" :closable="false" :title="status.activation_needed?'当前网站尚未确认切换到推荐版本；安装记录不能代替实际进程核验':'配置与实际主进程均已使用 Apache 2.4.71'"/>
    <p v-if="!status.target_installed"><el-button :disabled="busy" @click="onInstall">从应用商店安装 Apache 更新</el-button></p>
    <template v-if="status.native_engine_required">
     <p>现有 WAF 使用原生模块。先在 Apache WAF 的引擎构建页构建 2.4.71 兼容引擎，然后明确选择；原引擎、策略和封存副本保留。</p>
     <el-select v-model="engine" aria-label="Apache 2.4.71 兼容引擎" placeholder="选择实际完整性与 ABI 已验证的构建" :disabled="busy||!!pending" style="width:100%"><el-option v-for="row in candidates" :key="row.job_id" :value="row.job_id" :label="`Apache ${row.apache_version} · ${row.native_cc_version||'仅请求体'} · ${row.job_id}`"/></el-select>
     <p v-if="!candidates.length">当前没有匹配的新引擎，未降低原防护能力或复用旧版 ABI。</p>
    </template>
    <p>切换前后核对完整域名、实际二进制、配置与防护生效状态。失败时恢复原程序和完整配置；未完成的原任务保留，读取回执不会再次重启服务。</p>
   </template>
  </div>
  <template #footer><el-button :disabled="busy" @click="visible=false">关闭</el-button><el-button :disabled="busy" @click="refresh">核对实际版本</el-button><el-button type="primary" :loading="busy" :disabled="!known||!selectionReady" @click="activate">{{pending?'核对原切换请求':'切换网站到 2.4.71'}}</el-button></template>
 </el-dialog>
</template>
<style scoped>
.apache-runtime-manager{font-size:14px;line-height:1.7}.apache-runtime-manager p{margin:14px 0}.apache-runtime-manager dl{display:grid;grid-template-columns:110px 1fr;gap:8px;padding:16px;background:#f5f8fb;border-radius:8px}.apache-runtime-manager dt{color:#61758a}.apache-runtime-manager dd{margin:0;overflow-wrap:anywhere}@media(max-width:500px){.apache-runtime-manager dl{grid-template-columns:1fr;gap:2px}.apache-runtime-manager dd{margin-bottom:10px}}
</style>
