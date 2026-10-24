<script setup lang="ts">
import {computed} from 'vue';
import {dailySummary} from './dailyReportView';
const props=defineProps<{report:Record<string,unknown>}>();
const summary=computed(()=>dailySummary(props.report));
const bytes=(n:number)=>{let v=n,i=0;const units=['B','KiB','MiB','GiB','TiB'];while(v>=1024&&i<4){v/=1024;i++}return `${v.toFixed(i?2:0)} ${units[i]}`;};
</script>
<template>
 <section class="daily-summary" aria-label="保存的每日运维报告">
  <p class="daily-asof">保存时刻：{{summary.createdAt || '未记录'}}。以下为保存快照，不是当前实时状态。</p>
  <el-alert v-if="summary.counts.some(v=>v.value===null)" type="warning" :closable="false" :title="`此日报未记录或无法核对：${summary.counts.filter(v=>v.value===null).map(v=>v.label).join('、')}。缺失数据不表示零值，不据此认定系统正常。`" />
  <div class="report-metrics daily-counts">
   <article v-for="item in summary.counts" :key="item.key" :class="{attention:item.value!==null&&item.value>0&&['failed_site_jobs','failed_runtime_jobs','certificates_due_14_days'].includes(item.key)}"><span>{{item.label}}</span><strong>{{item.value===null?'未记录':item.value}}</strong></article>
  </div>
  <section aria-label="保存时的资源使用率"><h4>资源使用率</h4>
   <div class="daily-resources"><article v-for="item in summary.metrics" :key="item.key"><span>{{item.label}}</span><strong>{{item.value===null?'待核对':`${item.value.toFixed(1)}%`}}</strong><el-progress v-if="item.value!==null" :percentage="item.value" :show-text="false" :status="item.value>=90?'exception':undefined" /><p v-else>未取得有效采样，不按 0% 展示</p></article></div>
  </section>
  <section aria-label="保存的访问流量"><h4>访问流量</h4>
   <el-alert v-if="summary.trafficFailed || !summary.trafficDays" type="warning" :closable="false" title="流量来源未采集或无法核对，不代表没有访问或零流量。" />
   <template v-else><el-alert v-if="summary.trafficPartial" type="warning" :closable="false" title="访问日志采样不完整；下方仅是已读取范围，不能当作全量访问。" /><el-table :data="summary.trafficDays" max-height="280"><el-table-column prop="date" label="日期" /><el-table-column prop="requests" label="已采集请求" /><el-table-column label="已采集流量"><template #default="{row}">{{bytes(row.bytes)}}</template></el-table-column></el-table><p v-if="!summary.trafficDays.length">保存的采集结果为空；不据此认定所有站点都没有访问。</p></template>
  </section>
  <section aria-label="保存的软件检查"><h4>软件状态检查</h4><p>安装或状态检查通过不等于已开启防护，也不代表所有威胁均已排除。</p>
   <el-alert v-if="summary.securityFailed || !summary.security" type="warning" :closable="false" title="软件检查来源未采集或无法核对；未据此认定安全防护正常。" />
   <el-table v-else :data="summary.security" max-height="280"><el-table-column prop="id" label="软件标识" /><el-table-column prop="state" label="保存时的检查结果" /></el-table>
  </section>
 </section>
</template>
<style scoped>
.daily-summary{display:grid;gap:16px;min-width:0}.daily-asof,.daily-summary p{color:var(--muted);overflow-wrap:anywhere}.daily-counts,.daily-resources{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:12px}.daily-counts article,.daily-resources article{display:grid;gap:8px;padding:16px;border:1px solid var(--border);border-radius:8px;min-width:0}.daily-counts strong,.daily-resources strong{font-size:24px}.daily-counts .attention{border-color:#f2c7a4;background:#fff9f3}.daily-counts span,.daily-resources span{color:var(--muted)}h4{margin:0 0 12px;font-size:16px}@media(max-width:640px){.daily-counts,.daily-resources{grid-template-columns:repeat(2,minmax(0,1fr))}.daily-resources article:last-child{grid-column:1 / -1}}
</style>
