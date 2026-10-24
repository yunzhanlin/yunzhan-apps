<script setup lang="ts">
import {ref,watch,onBeforeUnmount} from "vue";
import {apacheBodyBuildInventory,apacheBodyBuildRow,apacheBodyQueueReply,type ApacheBodyBuild} from "./apacheBodyBuild";
import {randomId} from "./randomId";
import {formatPanelDateTime} from "./panelTime";
type API=<T>(path:string,method?:string,body?:unknown,key?:string)=>Promise<T>;
const props=defineProps<{api:API;active:boolean;parentBusy:boolean}>();
const rows=ref<ApacheBodyBuild[]>([]),selected=ref<ApacheBodyBuild>(),known=ref(false),reading=ref(false),writing=ref(false);
const error=ref(""),receipt=ref(""),pendingKey=ref("");
let epoch=0,disposed=false,timer:ReturnType<typeof setTimeout>|undefined,observingSince=0;
const current=(ticket:number)=>!disposed && props.active && ticket===epoch;
const label=(state:string)=>({queued:"排队",running:"构建中",ready:"本机程序已验证（未启用）",failed:"失败，证据保留",needs_attention:"需核对，不能启用",retained_unsupported:"旧版程序保留，当前不能启用"}[state] || "状态待核对");
function stopObserving(){if(timer)clearTimeout(timer);timer=undefined;}
async function refresh(){
  if(!props.active || reading.value || writing.value)return;
  const ticket=epoch;reading.value=true;error.value="";known.value=false;
  try{
    const out=await props.api<unknown>("/software/apache-waf/body-engines");
    if(!current(ticket))return;
    if(!apacheBodyBuildInventory(out))throw Error("引擎库存响应不完整或缺少实际验证，未使用缓存库存冒充成功");
    rows.value=out.entries;known.value=true;
    if(selected.value)selected.value=rows.value.find(row=>row.job_id===selected.value?.job_id);
    const running=rows.value.find(row=>["queued","running"].includes(row.state));
    if(running && !timer){selected.value=running;observingSince=Date.now();schedule(running.job_id);}
  }catch(e){if(current(ticket)){error.value=(e as Error).message;known.value=false;}}
  finally{if(current(ticket))reading.value=false;}
}
function schedule(id:string){
  stopObserving();
  if(!props.active || disposed)return;
  if(Date.now()-observingSince>5*60*60*1000){error.value="观察达到 5 小时上限，未宣称成功；服务和证据保留，请主动核对。";return;}
  timer=setTimeout(()=>{timer=undefined;void poll(id);},5000);
}
async function poll(id:string){
  const ticket=epoch;
  try{
    const out=await props.api<unknown>(`/software/apache-waf/body-engine/jobs/${id}`);
    if(!current(ticket))return;
    if(!apacheBodyBuildRow(out,id))throw Error("构建响应身份或四项验证无法核实");
    selected.value=out;
    if(["queued","running"].includes(out.state))schedule(id);
    else{if(out.state==="ready")receipt.value="ABI、完整性、ELF 加固和编译器回收已核实；没有安装应用或启用网站。";await refresh();}
  }catch(e){if(current(ticket)){error.value=`构建结果暂不可核实，未宣称完成：${(e as Error).message}`;stopObserving();}}
}
async function build(){
  if(!props.active || writing.value || reading.value || props.parentBusy || (!known.value && !pendingKey.value) || rows.value.some(row=>["queued","running"].includes(row.state)))return;
  const ticket=epoch;writing.value=true;error.value="";receipt.value="";
  pendingKey.value ||= randomId();
  let queuedID="";
  try{
    const out=await props.api<unknown>("/software/apache-waf/body-engine/build","POST",{},pendingKey.value);
    if(!current(ticket))return;
    if(!apacheBodyQueueReply(out))throw Error("队列响应身份不可核实");
    queuedID=out.job_id;pendingKey.value="";observingSince=Date.now();
  }catch(e){if(current(ticket))error.value=`提交结果未确认：${(e as Error).message}。再次点击将使用同一幂等标识核对，不另建重复任务。`;}
  finally{if(current(ticket))writing.value=false;}
  if(queuedID && current(ticket))await poll(queuedID);
}
async function cancel(){
  const id=selected.value?.job_id;
  if(!id || !props.active || writing.value || props.parentBusy || !["queued","running"].includes(selected.value?.state || ""))return;
  const ticket=epoch;writing.value=true;error.value="";receipt.value="";stopObserving();
  try{
    const out=await props.api<unknown>(`/software/apache-waf/body-engine/jobs/${id}/cancel`,"POST",{},randomId());
    if(!current(ticket))return;
    if(!apacheBodyBuildRow(out,id) || !["failed","ready"].includes(out.state))throw Error("取消回执尚不可核实");
    selected.value=out;receipt.value=out.state==="ready"?"任务已完成验证，没有启用网站。":"专用任务已停止；失败记录、请求和目录保留，同一任务不能覆盖重试。";
  }catch(e){if(current(ticket))error.value=`未确认构建已停止：${(e as Error).message}。请刷新核对，不会显示取消成功。`;}
  finally{if(current(ticket))writing.value=false;}
  if(current(ticket))await refresh();
}
watch(()=>props.active,active=>{epoch++;stopObserving();reading.value=false;writing.value=false;known.value=false;receipt.value="";if(active)void refresh();},{immediate:true});
onBeforeUnmount(()=>{disposed=true;epoch++;stopObserving();});
</script>

<template>
  <section class="apache-build">
    <el-alert type="info" :closable="false" title="只构建独立本机程序，不加载模块、不安装应用、不修改网站。固定 ModSecurity v2、私有静态 YAJL 与 OWASP CRS；必须已有受管 Apache 2.4.68。"/>
    <p>固定单路编译，85% CPU / 640 MiB 内存、576 MiB 回收水位，最长 4 小时；可能等待全局构建锁。不会自动安装 Apache、扩大资源预算或删除失败证据。启用策略还需要明确安装对应的2.4.0签名应用，并在“请求体站点策略”选择网站、预览及保存；本构建页不启用防护。</p>
    <p>数值事件单独保存在受保护的目录，不修改系统日志目录权限。检测模式不因规则匹配拦截请求；缓存写入不可用时仍应返回 503，不能把已截断的请求体送入网站。此异常行为需通过真实缓存耗尽验收，不以构建成功代替。</p>
    <p>升级后旧版 YZ4 不会被标成新版或自动启用。仅在原程序、规则和许可仍完整时显示“旧版程序保留”；损坏则显示需核对。新构建使用新任务标识，不覆盖原证据。</p>
    <div class="apache-build-actions"><el-button :loading="writing" :disabled="parentBusy || reading || (!known && !pendingKey) || rows.some(row=>['queued','running'].includes(row.state))" @click="build">{{pendingKey?'核对本次构建请求':'构建 Apache 兼容引擎'}}</el-button><el-button :loading="reading" :disabled="writing" @click="refresh">核对完整库存</el-button><el-button v-if="selected && ['queued','running'].includes(selected.state)" type="warning" :disabled="parentBusy || writing" @click="cancel">停止专用构建并保留证据</el-button></div>
    <el-alert v-if="error" type="error" :title="error" :closable="false"/>
    <el-alert v-if="receipt && known" type="info" :title="receipt" :closable="false"/>
    <p v-if="!known" role="status">{{reading?'正在核对完整引擎库存':'库存尚不可核实（不是零个引擎）'}}</p>
    <el-table v-if="known" :data="rows" max-height="320" empty-text="已核实：没有本机 Apache 请求体构建记录" @row-click="(row:ApacheBodyBuild)=>selected=row">
      <el-table-column prop="job_id" label="任务标识" min-width="210" show-overflow-tooltip/>
      <el-table-column label="程序" min-width="200"><template #default="{row}">Apache {{row.apache_version || '待核对'}} / {{row.architecture || '待核对'}}<small>ModSecurity {{row.engine_version || '待核对'}} · YAJL {{row.yajl_version || '待核对'}} · CRS {{row.crs_version || '待核对'}}</small></template></el-table-column>
      <el-table-column label="状态" min-width="230"><template #default="{row}">{{label(row.state)}}<small v-if="row.error">{{row.error}}</small></template></el-table-column>
    </el-table>
    <template v-if="selected && known"><h4>{{label(selected.state)}} · {{selected.job_id}}</h4><ol v-if="selected.steps.length"><li v-for="(step,index) in selected.steps" :key="index">{{formatPanelDateTime(step.time)}} · {{step.message}}</li></ol></template>
    <p>失败和中断任务不会被“重试”覆盖。单个命名空间最多保留 64 份控制/任务记录，最多 16 份独立程序；达到限额拒绝继续，不自动删除证据。当前日志和网站策略不因构建或取消而改变。</p>
  </section>
</template>

<style scoped>
.apache-build{font-size:13px;color:#30475b}.apache-build p{line-height:1.7}.apache-build small{display:block;color:#73869b;margin-top:5px;overflow-wrap:anywhere}.apache-build-actions{display:flex;flex-wrap:wrap;gap:8px;margin:15px 0}.apache-build-actions :deep(.el-button){margin-left:0}.apache-build h4,.apache-build li{overflow-wrap:anywhere}.apache-build ol{max-height:300px;overflow:auto;padding-left:25px}.apache-build :deep(.el-alert){margin:12px 0}
</style>
