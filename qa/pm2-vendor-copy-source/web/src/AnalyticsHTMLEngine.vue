<script setup lang="ts">
import { computed, onBeforeUnmount, ref, watch } from "vue";
import { randomId } from "./randomId";
import { analyticsHTMLActiveReady, analyticsHTMLActivationAcknowledged, analyticsHTMLBuildReady, type AnalyticsHTMLActive, type AnalyticsHTMLBuild } from "./analyticsHTMLState";
type API = <T>(path:string, method?:string, body?:unknown, key?:string)=>Promise<T>;
const props = defineProps<{api:API;installed:boolean;supported:boolean}>();
const emit = defineEmits<{ready:[value:boolean]}>();
const entries = ref<AnalyticsHTMLBuild[]>([]), active = ref<AnalyticsHTMLActive>(), job = ref<AnalyticsHTMLBuild>();
const busy = ref(false), error = ref(""), saved = ref(""), inventoryKnown = ref(false);
const chosen = ref("");
const ready = computed(()=>analyticsHTMLActiveReady(active.value));
const candidates = computed(()=>inventoryKnown.value ? entries.value.filter(analyticsHTMLBuildReady) : []);
const running = computed(()=>!!job.value && ["queued","running"].includes(job.value.state));
const selected = computed(()=>candidates.value.find(item=>item.job_id===chosen.value));
const enabled = computed(()=>props.installed && props.supported);
const stateLabel = (state:string)=>({queued:"已排队",running:"构建中",ready:"程序与 ABI 已核验",succeeded:"任务完成",failed:"失败，证据保留",needs_attention:"需要核对"}[state] || "状态未知，需核对");
let timer: ReturnType<typeof setTimeout> | undefined, sequence = 0, disposed = false;
function stopTimer(){if(timer)clearTimeout(timer);timer=undefined;}
function publishReady(){emit("ready",ready.value);}
async function readActive(current:number){
  // Clear the previous success while a fresh worker acknowledgment is pending.
  active.value=undefined;publishReady();
  const out=await props.api<AnalyticsHTMLActive>("/software/website-analytics/html-engine/active");
  if(disposed || current!==sequence)return;
  if(typeof out.active!=="boolean" || typeof out.state!=="string" || (out.active && !analyticsHTMLActiveReady(out)))throw new Error("HTML 引擎工作进程响应无法核验；不会允许自动接入。");
  active.value=out;publishReady();return out;
}
async function readInventory(current:number){
  inventoryKnown.value=false;
  const out=await props.api<{entries:AnalyticsHTMLBuild[];build_only:boolean}>("/software/website-analytics/html-engines");
  if(disposed || current!==sequence)return;
  if(!Array.isArray(out.entries) || out.entries.length>256 || out.build_only!==true || out.entries.some(item=>!item || !/^[a-f0-9]{32}$/.test(item.job_id) || !Array.isArray(item.steps) || item.steps.length>32))throw new Error("HTML 引擎库存无法核验；不是零个引擎。");
  entries.value=out.entries;inventoryKnown.value=true;
  if(!candidates.value.some(item=>item.job_id===chosen.value))chosen.value=candidates.value[0]?.job_id || "";
}
async function poll(id:string,current:number){
  stopTimer();
  try{
    const out=await props.api<AnalyticsHTMLBuild>(`/software/website-analytics/html-engine/jobs/${id}`);
    if(disposed || current!==sequence)return;
    if(out.job_id!==id || out.build_only!==true || !Array.isArray(out.steps) || out.steps.length>32)throw new Error("构建身份或步骤响应无法核验，原任务保留。");
    job.value=out;
    if(["queued","running"].includes(out.state))timer=setTimeout(()=>void poll(id,current),3000);
    else {await readInventory(current);if(out.error)error.value=out.error;}
  }catch(e){if(!disposed && current===sequence)error.value=(e as Error).message;}
}
async function refresh(){
  if(busy.value || !enabled.value)return;
  const current=++sequence;stopTimer();busy.value=true;error.value="";
  try{
    const results=await Promise.allSettled([readActive(current),readInventory(current)]);
    if(disposed || current!==sequence)return;
    const failure=results.find(result=>result.status==="rejected");
    if(failure?.status==="rejected")throw failure.reason;
    const pending=entries.value.find(item=>["queued","running"].includes(item.state));
    if(pending)await poll(pending.job_id,current);
  }catch(e){if(!disposed && current===sequence)error.value=(e as Error).message;}
  finally{if(current===sequence)busy.value=false;}
}
async function build(){
  if(busy.value || running.value || !enabled.value)return;
  const current=++sequence;stopTimer();busy.value=true;error.value="";saved.value="";
  try{
    const out=await props.api<{job_id:string}>("/software/website-analytics/html-engine/build","POST",{},randomId());
    if(!/^[a-f0-9]{32}$/.test(out.job_id))throw new Error("无法核对新建构建任务，请到任务列表核对；不会自动重试。");
    if(disposed || current!==sequence)return;
    await poll(out.job_id,current);
    if(disposed || current!==sequence)return;
    saved.value="构建请求已入队。只安装固定编译依赖并生成隔离模块，不启用网站、不替换 Nginx。";
  }catch(e){if(!disposed && current===sequence)error.value=(e as Error).message;}
  finally{if(current===sequence)busy.value=false;}
}
async function cancel(){
  if(busy.value || !running.value || !job.value || !enabled.value)return;
  const id=job.value.job_id,current=++sequence;stopTimer();busy.value=true;error.value="";saved.value="";
  try{
    await props.api(`/software/website-analytics/html-engine/jobs/${id}/cancel`,"POST",{},randomId());
    await poll(id,current);
    if(disposed || current!==sequence)return;
    if(job.value?.state==="failed")saved.value="构建已停止；原目录、日志和失败记录保留，没有卸载或停用网站。";
    else if(analyticsHTMLBuildReady(job.value))saved.value="构建已在停止前完成；程序保留，尚未因此启用网站。";
    else throw new Error("停止结果尚未核实，请刷新核对；不重复发送停止请求。");
  }catch(e){if(!disposed && current===sequence)error.value=(e as Error).message;}
  finally{if(current===sequence)busy.value=false;}
}
async function activate(){
  if(busy.value || running.value || !enabled.value || !selected.value)return;
  const id=selected.value.job_id,current=++sequence;stopTimer();busy.value=true;error.value="";saved.value="";active.value=undefined;publishReady();
  try{
    const out=await props.api("/software/website-analytics/html-engine/activate","POST",{job_id:id},randomId());
    if(!analyticsHTMLActivationAcknowledged(out,id))throw new Error("加载响应未确认实际工作进程；请刷新核对，不会自动重复加载。");
    const loaded=await readActive(current);
    if(disposed || current!==sequence)return;
    if(!analyticsHTMLActiveReady(loaded) || loaded?.job_id!==id)throw new Error("加载后的实际引擎与所选构建不一致，请核对恢复记录。");
    saved.value="引擎已加载，实际 Nginx 工作进程身份已核对。网站仍需逐站主动开启自动接入，不会批量改动现有网站。";
  }catch(e){if(!disposed && current===sequence)error.value=(e as Error).message;}
  finally{if(current===sequence)busy.value=false;}
}
watch(enabled,()=>{
  ++sequence;stopTimer();active.value=undefined;entries.value=[];job.value=undefined;inventoryKnown.value=false;chosen.value="";busy.value=false;error.value="";saved.value="";publishReady();
  if(enabled.value)void refresh();
},{immediate:true});
onBeforeUnmount(()=>{disposed=true;++sequence;stopTimer();emit("ready",false);});
</script>
<template>
  <section class="analytics-html-engine" data-testid="analytics-html-engine">
    <h4>可选：HTML 自动接入引擎</h4>
    <p>将同源采集脚本插入真实 HTML 的 head 结束位置，不修改网站模板。仅处理有明确 head 的 UTF-8 HTML；压缩上游、下载文件、Range、无 head 或超出解析预算的响应保持原文。不会改写 CSP，也不绕过访客同意机制。</p>
    <el-alert v-if="!enabled" title="自动接入需要已安装且版本可核验的网站分析 2.3.0。未安装或未更新时仍可查看手动接入说明。" type="info" :closable="false" />
    <template v-else>
      <el-alert v-if="error" :title="error" type="error" :closable="false" />
      <el-alert v-if="saved" :title="saved" type="success" :closable="false" />
      <p aria-live="polite">{{ready ? '实际引擎已加载并确认' : active?.state==='not-activated' ? '尚未加载可选引擎' : '实际引擎待核对，不允许开启自动接入'}}{{active?.error ? '：'+active.error : ''}}</p>
      <p>按本机实际 Nginx 和架构编译固定来源的 njs / QuickJS 模块。构建上限：内存 640 MiB、无交换空间、CPU 70%、96 个进程；失败或取消保留证据，不自动删除旧构建。</p>
      <div class="engine-controls">
        <el-button :disabled="busy" @click="refresh">核对引擎与构建</el-button>
        <el-button :disabled="busy || running" @click="build">新建隔离构建</el-button>
        <el-button v-if="running" :disabled="busy" @click="cancel">停止本次构建</el-button>
      </div>
      <template v-if="job"><p>当前任务：{{job.job_id}} · {{stateLabel(job.state)}}</p><ol><li v-for="(step,index) in job.steps" :key="index">{{step.time}} · {{step.message}}</li></ol></template>
      <p v-if="!inventoryKnown">构建库存尚待核验，不显示假零个或可加载选项。</p>
      <el-table v-else :data="entries" empty-text="尚无构建记录"><el-table-column prop="job_id" label="构建标识" show-overflow-tooltip /><el-table-column prop="architecture" label="架构" width="90" /><el-table-column prop="nginx_version" label="Nginx" width="95" /><el-table-column label="状态"><template #default="{row}">{{stateLabel(row.state)}}{{row.error ? '：'+row.error : ''}}</template></el-table-column></el-table>
      <div class="engine-controls">
        <el-select v-model="chosen" aria-label="待加载 HTML 引擎" placeholder="选择完整性和 ABI 已核验的构建" :disabled="busy || running || !candidates.length"><el-option v-for="item in candidates" :key="item.job_id" :value="item.job_id" :label="`${item.nginx_version} / ${item.architecture} · ${item.job_id}`" /></el-select>
        <el-button type="primary" :disabled="busy || running || !selected" @click="activate">加载引擎并核对工作进程</el-button>
      </div>
      <p>加载前保存完整三个文件的恢复记录，执行 nginx -t、重载和实际工作进程确认，失败恢复原配置。加载成功不代表网站自动开启；下方逐站启用。手工修改或未知旧模块不会被覆盖。</p>
    </template>
  </section>
</template>
<style scoped>
.analytics-html-engine{border:1px solid var(--el-border-color);border-radius:8px;padding:16px;margin:16px 0}.engine-controls{display:flex;gap:12px;flex-wrap:wrap;margin:16px 0}.engine-controls .el-select{width:min(100%,480px)}li{overflow-wrap:anywhere}p{line-height:1.6}
</style>
