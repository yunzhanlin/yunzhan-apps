<script setup lang="ts">
import {ref,watch,onBeforeUnmount} from "vue";
import {apacheBodyReportURL,apacheBodyReportValid,type ApacheBodyReport} from "./apacheBodyReport";
import {formatPanelDateTime} from "./panelTime";
type API=<T>(path:string,method?:string,body?:unknown,key?:string)=>Promise<T>;
const props=defineProps<{api:API;active:boolean;sites:{id:string;domain:string}[]}>();
const report=ref<ApacheBodyReport>(),busy=ref(false),error=ref(""),page=ref(1),range=ref<[Date,Date]>();
const filter=ref({site_id:"",rule:"",phase:""});
let epoch=0,disposed=false;
const current=(ticket:number)=>!disposed && props.active && ticket===epoch;
const utc=(d?:Date)=>d?d.toISOString().replace(/\.\d{3}Z$/,"Z"):"";
async function refresh(reset=false){
  if(!props.active || busy.value)return;
  if(reset)page.value=1;
  const ticket=epoch;busy.value=true;report.value=undefined;error.value="";
  try{
    const url=apacheBodyReportURL({...filter.value,from:utc(range.value?.[0]),to:utc(range.value?.[1])},page.value);
    const out=await props.api<unknown>(url);
    if(!current(ticket))return;
    if(!apacheBodyReportValid(out,page.value))throw Error("报告身份、隐私字段或统计范围无法核实，未显示缓存记录");
    report.value=out;
  }catch(e){if(current(ticket))error.value=`记录读取未完成（不是零匹配）：${(e as Error).message}`;}
  finally{if(current(ticket))busy.value=false;}
}
function exportPage(){
  if(!report.value || busy.value || !apacheBodyReportValid(report.value,page.value))return;
  const object=URL.createObjectURL(new Blob([JSON.stringify(report.value,null,2)],{type:"application/json;charset=utf-8"}));
  const link=document.createElement("a");link.href=object;link.download="yunzhan-apache-body-rule-matches-page.json";link.click();URL.revokeObjectURL(object);
}
watch(()=>props.active,()=>{epoch++;report.value=undefined;error.value="";busy.value=false;});
watch([filter,range],()=>{epoch++;report.value=undefined;error.value="";busy.value=false;page.value=1;},{deep:true});
onBeforeUnmount(()=>{disposed=true;epoch++;});
</script>

<template>
  <section class="apache-events">
    <el-alert type="info" :closable="false" title="只读数值规则匹配记录，不启用请求体防护。匹配记录不等于独立 HTTP 请求数或已确认的拦截量。"/>
    <p>仅管理员可查询。固定 YZ5 日志不包含 IP、URI、Cookie、请求体、文件内容或规则原文。日志存在也不证明当前应用已启用或运行健康。</p>
    <el-form label-position="top" class="apache-event-filters">
      <el-form-item label="网站"><el-select v-model="filter.site_id" :disabled="busy" filterable aria-label="Apache 数值记录网站"><el-option label="全部网站标识" value=""/><el-option v-for="site in sites" :key="site.id" :value="site.id" :label="site.domain"/></el-select></el-form-item>
      <el-form-item label="数字规则号"><el-input v-model="filter.rule" :disabled="busy" aria-label="Apache 数字规则号" placeholder="如 941100"/></el-form-item>
      <el-form-item label="处理阶段"><el-select v-model="filter.phase" :disabled="busy" aria-label="Apache 数值记录处理阶段"><el-option label="全部阶段" value=""/><el-option v-for="n in 5" :key="n" :value="String(n)" :label="`阶段 ${n}`"/></el-select></el-form-item>
      <el-form-item label="时间范围（浏览器本地时间，查询转换为 UTC）"><el-date-picker v-model="range" :disabled="busy" type="datetimerange" start-placeholder="开始时间" end-placeholder="结束时间" aria-label="Apache 数值记录时间范围"/></el-form-item>
    </el-form>
    <div class="apache-event-actions"><el-button :loading="busy" @click="refresh(true)">查询数值记录</el-button><el-button :disabled="!report || busy" @click="exportPage">导出当前筛选页 JSON</el-button></div>
    <el-alert v-if="error" type="error" :title="error" :closable="false"/>
    <p v-if="!report" role="status">{{busy?'正在读取实际固定日志':'尚未取得可核验报告，不代表零匹配。'}}</p>
    <template v-else>
      <el-descriptions :column="3" border><el-descriptions-item label="筛选内规则匹配">{{report.rule_matches}}</el-descriptions-item><el-descriptions-item label="本次扫描记录">{{report.scanned}} / 5000</el-descriptions-item><el-descriptions-item label="实际日志字节">{{report.log_bytes}} / {{report.max_bytes}}</el-descriptions-item></el-descriptions>
      <el-alert v-if="report.partial" type="warning" :closable="false" title="当前为部分、尽力记录：尾部扫描、记录上限、容量耗尽或被拒绝行均可能影响统计，不代表全部攻击。"/>
      <p v-if="!report.available">已核对固定路径：日志尚不存在，没有创建日志或启用防护。</p>
      <p v-if="report.capacity_near_limit">32 MiB 日志容量接近上限，后续事件可能无法记入。此状态不改变防护决策，本页不会自动清空日志。</p>
      <p>拒绝的行：{{report.rejected_lines}} · {{formatPanelDateTime(report.from)}} 至 {{formatPanelDateTime(report.to)}}</p>
      <el-table :data="report.events" max-height="450" empty-text="本次已核验筛选窗口内没有数值匹配记录">
        <el-table-column label="时间" min-width="170"><template #default="{row}">{{formatPanelDateTime(row.time)}}</template></el-table-column>
        <el-table-column prop="site_id" label="网站标识" min-width="210" show-overflow-tooltip/>
        <el-table-column prop="rule_id" label="规则号" width="110"/>
        <el-table-column prop="phase" label="阶段" width="75"/>
        <el-table-column prop="severity" label="严重度" width="85"/>
        <el-table-column label="记录模式" width="100"><template #default="{row}">{{row.mode==='block'?'阻断模式':'观察模式'}}</template></el-table-column>
        <el-table-column label="规则拦截标记" min-width="145"><template #default="{row}">{{row.intercepted_mark?'已标记（非请求计数）':'未标记'}}</template></el-table-column>
      </el-table>
      <el-pagination v-model:current-page="page" :disabled="busy" :page-size="50" :total="report.rule_matches" layout="total, prev, pager, next" @current-change="refresh()"/>
    </template>
    <p>默认查询最近 24 小时，时间范围最多 90 天。每次最多读取当前日志尾部 4 MiB / 5000 条完整记录。写入采用非阻塞锁，锁忙和容量耗尽可能丢失记录；报告不包含历史归档，也不会修改现有配置、重载服务或删除日志。</p>
  </section>
</template>

<style scoped>
.apache-events{display:grid;gap:14px}.apache-events p{margin:0;color:#64748b;line-height:1.7}.apache-event-filters{display:grid;grid-template-columns:repeat(3,minmax(160px,1fr));gap:12px}.apache-event-filters .el-form-item:last-child{grid-column:1/-1}.apache-event-actions{display:flex;gap:10px;flex-wrap:wrap}.apache-event-actions .el-button{margin:0}@media(max-width:760px){.apache-event-filters{grid-template-columns:1fr}.apache-event-filters .el-form-item:last-child{grid-column:auto}}
</style>
