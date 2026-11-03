<script setup lang="ts">
import {computed,onBeforeUnmount,ref,watch} from "vue";
import {apacheBodyBuildInventory,type ApacheBodyBuild} from "./apacheBodyBuild";
type API=<T>(path:string,method?:string,body?:unknown,key?:string)=>Promise<T>;
const props=defineProps<{api:API;active:boolean;installed:unknown;version:unknown;implementation:unknown;settings:{apache_cc?:{engine_job_id:string}};parentBusy:boolean}>();
const emit=defineEmits<{"request-build":[]}>();
const supported=computed(()=>props.installed===true&&props.version==="2.5.0"&&props.implementation==="2.5.0");
const rows=ref<ApacheBodyBuild[]>([]),known=ref(false),reading=ref(false),error=ref("");
const ready=computed(()=>known.value?rows.value.filter(row=>row.state==="ready"&&row.native_cc_version==="1.0.0"):[]);
let epoch=0,disposed=false;
async function refresh(){
 if(!props.active||!supported.value||reading.value)return;
 const ticket=epoch;reading.value=true;known.value=false;error.value="";
 try{
  const out=await props.api<unknown>("/software/apache-waf/body-engines");
  if(disposed||!props.active||ticket!==epoch)return;
  if(!apacheBodyBuildInventory(out))throw Error("完整引擎库存无法核实，当前不能选择引擎");
  rows.value=out.entries;known.value=true;
 }catch(e){if(ticket===epoch)error.value=(e as Error).message;}
 finally{if(ticket===epoch)reading.value=false;}
}
function chooseEngine(id:string){
 if(!supported.value||props.parentBusy||reading.value||!known.value||!ready.value.some(row=>row.job_id===id)){error.value="所选引擎尚未通过本次完整核对，草稿保持不变";return;}
 props.settings.apache_cc={engine_job_id:id};error.value="";
}
watch([()=>props.active,supported],()=>{epoch++;known.value=false;rows.value=[];reading.value=false;error.value="";if(props.active&&supported.value)void refresh();},{immediate:true});
onBeforeUnmount(()=>{disposed=true;epoch++;});
</script>

<template>
 <section class="apache-cc-engine">
  <el-alert v-if="!supported" type="warning" :closable="false" title="CC 防护需要已安装的 Apache WAF 2.5.0，并且面板支持对应版本。"/>
  <template v-else>
   <el-alert type="info" :closable="false" title="先核对并选择支持 CC 的本机引擎，再启用限流、预览和保存。选择引擎只修改草稿，不会立即启用。"/>
   <div class="apache-cc-actions"><el-button :loading="reading" :disabled="parentBusy" @click="refresh">核对 CC 引擎</el-button><el-button :disabled="parentBusy" @click="emit('request-build')">构建防护引擎</el-button></div>
   <el-alert v-if="error" :title="error" type="error" :closable="false"/>
   <p v-if="!known" role="status">{{reading?'正在核对本机引擎完整性':'引擎库存尚未核实，保留原选择。'}}</p>
   <p v-else-if="!ready.length" role="status">已核实：尚无可用的 CC 引擎。新构建同时提供请求体检查和 CC 限流；已有仅请求体引擎继续保留。</p>
   <el-form label-position="top"><el-form-item label="支持 CC 的原生引擎"><el-select :model-value="settings.apache_cc?.engine_job_id||''" :disabled="!known||reading||parentBusy" aria-label="Apache CC 引擎" placeholder="明确选择，不自动替换原引擎" @change="chooseEngine"><el-option v-for="row in ready" :key="row.job_id" :value="row.job_id" :label="`Apache ${row.apache_version} · ${row.architecture} · ${row.job_id.slice(0,12)}`"/></el-select></el-form-item></el-form>
   <el-alert v-if="settings.apache_cc?.engine_job_id&&!ready.some(row=>row.job_id===settings.apache_cc?.engine_job_id)" type="warning" :closable="false" title="原选择尚未通过本次核对；不会自动更换。保存时还会重新验证所选引擎。"/>
   <p>每个网站独立计算同一访客和 URL 规则的额度，多进程共享。超限返回 429；观察模式放行并记录。最多同时启用 64 个网站，每站点保留 4,096 个活跃访客与规则组合；空间不足时阻断模式返回 503，日志显示容量原因。</p>
   <p>CC 事件使用独立私有日志，最多 32 MiB；满额后停止记录，防护继续生效。原内容保留，不自动覆盖。</p>
   <p>Apache 位于反向代理后时，请在“可信反代来源”中配置受信来源；未配置时按直接连接地址计数。突发值是正常单次请求之外的额外名额；例如突发值为 2 时，可连续通过 3 次请求，额度按所设速率持续补充。</p>
  </template>
 </section>
</template>

<style scoped>
.apache-cc-engine{display:grid;gap:12px;margin-bottom:18px}.apache-cc-engine p{color:#64748b;line-height:1.7;margin:0}.apache-cc-actions{display:flex;flex-wrap:wrap;gap:10px}.apache-cc-actions .el-button{margin:0}.apache-cc-engine .el-select{width:100%}
</style>
