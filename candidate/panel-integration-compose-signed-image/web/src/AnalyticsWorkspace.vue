<script setup lang="ts">
import { computed, onBeforeUnmount, ref, watch } from "vue";
import AnalyticsHTMLEngine from "./AnalyticsHTMLEngine.vue";
import AnalyticsPerformanceReport from "./AnalyticsPerformanceReport.vue";
import AnalyticsPeriodComparison from "./AnalyticsPeriodComparison.vue";
import AnalyticsHeatmapOverlay from "./AnalyticsHeatmapOverlay.vue";
import type {AnalyticsPerformancePages} from "./analyticsPerformance";
import { analyticsCollectorEnabled } from "./analyticsHTMLState";
import { randomId } from "./randomId";
import { browserAnalyticsQuery, browserAnalyticsQueryParams, browserAnalyticsReportMatches, browserAnalyticsQueryFence } from "./browserAnalyticsQuery";
import type { BrowserAnalyticsQueryTicket } from "./browserAnalyticsQuery";
type API = <T>(path:string,method?:string,body?:unknown,idempotencyKey?:string)=>Promise<T>;
interface Settings {site_id:string;key:string;enabled:boolean;clicks:boolean;retention_days:number;revision:number;proxy_endpoint?:string;auto_inject_html?:boolean;geography?:boolean;client_address_mode?:string}
interface Dimension {name:string;count:number}
interface Session {id:string;visitor:string;entry:string;exit:string;source:string;first:number;last:number;pages:number;duration:number;journey:string[];page_order_source?:string;page_order_uncertain?:boolean}
interface Funnel {source:string;from:string;to:string;ordering_uncertain_sessions?:number;window_minutes:number;sampled_pageviews:number;unique_pageviews:number;partial:boolean;completed_sessions:number;duration_seconds:Record<string,number>;steps:{path:string;sessions:number;overall_rate:number;previous_rate:number;drop_off:number}[];limitations:string[]}
interface HeatPoint {path:string;x:number;y:number;count:number}
const heatViewports = [
  {value:"narrow",label:"窄屏（小于 768 px）"},
  {value:"medium",label:"中屏（768–1199 px）"},
  {value:"wide",label:"宽屏（1200 px 起）"},
  {value:"unknown",label:"未知屏宽"},
] as const;
type HeatViewport = (typeof heatViewports)[number]["value"];
interface Report {
  source:string;from:string;to:string;partial:boolean;sampled_events:number;ordering_uncertain_sessions?:number;
  overview:{pv:number;uv:number;sessions:number;active_visitors:number;clicks:number;bounce_rate:number;avg_engagement_seconds:number;unique_network_peers:number};
  pages:Dimension[];sources:Dimension[];browsers:Dimension[];devices:Dimension[];entry_pages:Dimension[];exit_pages:Dimension[];hours:Dimension[];campaigns:Dimension[];
  sessions:Session[];heatmap:HeatPoint[];heatmap_layouts?:{points:(HeatPoint & {viewport:HeatViewport})[];partial:boolean};
  performance:Record<string,{samples:number;p75?:number}>;performance_pages?:AnalyticsPerformancePages;limitations:string[];
  client_addresses?:{unique_addresses:number;known_pageviews:number;unknown_pageviews:number;legacy_pageviews:number;sources:Dimension[]};
  geography?:{countries:Dimension[];statuses:Dimension[];data_releases:Dimension[];partial:boolean;attribution?:string;attribution_url?:string;license_url?:string};
}
const props=defineProps<{api:API;installed:boolean;installedVersion?:string;sites:{id:string;name:string;domain:string}[]}>();
const selected=ref(""),tab=ref("overview"),busy=ref(false),error=ref(""),saved=ref("");
const settings=ref<Settings>(),reportValue=ref<Report>();
const htmlEngineReady=ref(false);
const htmlSupported=computed(()=>props.installed && ["2.3.0","2.3.1","2.3.2","2.4.0","2.4.1","2.4.2","2.4.3","2.4.4","2.4.5"].includes(props.installedVersion||""));
const rangeStart=ref<Date|null>(),rangeEnd=ref<Date|null>(),heatPath=ref(""),heatPage=ref(1),heatViewport=ref<HeatViewport>();
const query=computed(()=>browserAnalyticsQuery(selected.value,rangeStart.value,rangeEnd.value));
const reportFence=browserAnalyticsQueryFence(),reportTicket=ref<BrowserAnalyticsQueryTicket>();
const report=computed(()=>reportTicket.value && reportFence.current(reportTicket.value,query.value.key) && !query.value.problem ? reportValue.value : undefined);
const funnelSteps=ref("/\n/checkout\n/success"),funnelWindow=ref(30),funnelBusy=ref(false),funnelError=ref(""),funnelValue=ref<Funnel>(),funnelKey=ref("");
const funnelQueryKey=computed(()=>JSON.stringify([query.value.key,funnelSteps.value.split(/\r?\n/).map(s=>s.trim()).filter(Boolean),funnelWindow.value]));
const funnel=computed(()=>funnelKey.value===funnelQueryKey.value && !query.value.problem ? funnelValue.value : undefined);
let funnelSequence=0;
let sequence=0;
let disposed=false;
const site=computed(()=>props.sites.find(s=>s.id===selected.value));
const geographySupported = computed(() => props.installedVersion === "2.4.5");
const geographyStatus: Record<string, string> = {
  located: "已定位", non_public: "非公网地址", unverified: "地址未核实", unavailable: "地理库暂不可用",
  not_found: "地理库无匹配", not_collected: "未采集地理分布",
};
const regionNames = typeof Intl.DisplayNames === "function" ? new Intl.DisplayNames(["zh-CN"], {type: "region"}) : undefined;
function regionName(code: string): string {
  if (!/^[A-Z]{2}$/.test(code)) return code;
  if (code === "TW") return "中国台湾";
  if (code === "HK") return "中国香港";
  if (code === "MO") return "中国澳门";
  return regionNames?.of(code) || code;
}
const layoutHeat = computed(() => (props.installedVersion === "2.4.4" || geographySupported.value) ? report.value?.heatmap_layouts : undefined);
const heatPaths=computed(()=>[...new Set((layoutHeat.value?.points ?? report.value?.heatmap ?? []).map(p=>p.path))]);
const viewportOptions=computed(()=>heatViewports.filter(option=>layoutHeat.value?.points.some(
  point=>point.path===heatPath.value && point.viewport===option.value,
)));
const heat=computed(()=>{
  const rows = layoutHeat.value
    ? layoutHeat.value.points.filter(p=>p.path===heatPath.value && p.viewport===heatViewport.value)
    : report.value?.heatmap.filter(p=>p.path===heatPath.value) ?? [];
  return rows.sort((a,b)=>b.count-a.count||a.x-b.x||a.y-b.y);
});
watch(heatPaths,paths=>{
  if(!paths.includes(heatPath.value)) heatPath.value=paths[0] ?? "";
});
watch(viewportOptions,options=>{
  if(!options.some(option=>option.value===heatViewport.value)) heatViewport.value=options[0]?.value;
});
const heatClicks=computed(()=>heat.value.reduce((total,p)=>total+p.count,0));
const heatRows=computed(()=>heat.value.slice((heatPage.value-1)*20,heatPage.value*20));
watch([heatPath,heatViewport,report],()=>{heatPage.value=1;},{flush:"sync"});
const snippet=computed(()=>settings.value?.key ? `<script defer src="/__yunzhan/analytics/tracker.js?site=${settings.value.site_id}&amp;key=${settings.value.key}"><\/script>` : "先保存采集配置，再生成代码。");
async function load(){
  const current=++sequence,selection=query.value,id=selected.value;
  reportTicket.value=undefined;reportValue.value=undefined;settings.value=undefined;saved.value="";error.value="";
  if(!selected.value)return;busy.value=true;
  const ticket=selection.problem ? undefined : reportFence.capture(selection.key);
  try {
    const [cfg,out]=await Promise.all([props.api<Settings>(`/analytics/sites/${id}/config`),ticket ? props.api<Report>(reportURL(selection)) : Promise.resolve(undefined)]);
    if(disposed||current!==sequence)return;
    settings.value=cfg;
    if(ticket && out && reportFence.current(ticket,query.value.key)){
      if(!browserAnalyticsReportMatches(selection,out))throw new Error("统计返回的时间范围与查询不一致，未显示或导出。");
      reportValue.value=out;reportTicket.value=ticket;heatPath.value=out.heatmap[0]?.path||"";
    }
  }
  catch(e){if(!disposed&&current===sequence&&(!ticket||reportFence.current(ticket,query.value.key)))error.value=(e as Error).message;}
  finally{if(current===sequence)busy.value=false;}
}
function reportURL(selection=query.value){return `/analytics/sites/${selection.site}/report?${browserAnalyticsQueryParams(selection)}`;}
async function refresh(){
  if(!selected.value||busy.value||query.value.problem)return;
  const current=sequence,selection=query.value,ticket=reportFence.capture(selection.key);
  reportTicket.value=undefined;reportValue.value=undefined;busy.value=true;error.value="";
  try{
    const out=await props.api<Report>(reportURL(selection));
    if(disposed||current!==sequence||!reportFence.current(ticket,query.value.key))return;
    if(!browserAnalyticsReportMatches(selection,out))throw new Error("统计返回的时间范围与查询不一致，未显示或导出。");
    reportValue.value=out;reportTicket.value=ticket;
    if(!out.heatmap.some(p=>p.path===heatPath.value))heatPath.value=out.heatmap[0]?.path||"";
  }catch(e){if(!disposed&&current===sequence&&reportFence.current(ticket,query.value.key))error.value=(e as Error).message;}
  finally{if(current===sequence)busy.value=false;}
}
function setEnabled(value:string|number|boolean){if(!settings.value)return;settings.value=analyticsCollectorEnabled(settings.value,value===true);void save();}
async function save(){
  if(!settings.value||busy.value||!props.installed)return;
  busy.value=true;error.value="";saved.value="";
  const id=selected.value,current=sequence;
  try{
    const payload=analyticsCollectorEnabled(settings.value,settings.value.enabled);
    if (geographySupported.value && !payload.enabled) payload.geography = false;
    if (!geographySupported.value) delete payload.geography;
    const queued=await props.api<{job_id:string}>(`/analytics/sites/${id}/config`,"POST",payload,randomId());
    let completed=false;
    for(let attempt=0;attempt<120;attempt++){
      if(disposed||current!==sequence)return;
      const job=await props.api<{state:string;error?:string}>(`/jobs/${queued.job_id}`);
      if(job.state==="succeeded"){completed=true;break;}
      if(["failed","needs_attention"].includes(job.state))throw new Error(job.error||"配置应用失败；请在任务列表核对回滚结果。");
      await new Promise(resolve=>setTimeout(resolve,500));
    }
    if(!completed)throw new Error("配置任务仍在执行，请到任务列表核对；此处不会提前报告成功。");
    const applied=await props.api<Settings>(`/analytics/sites/${id}/config`);
    if(disposed||current!==sequence)return;
    if(applied.enabled!==payload.enabled || !!applied.auto_inject_html!==!!payload.auto_inject_html || (payload.geography !== undefined && applied.geography !== payload.geography))throw new Error("任务完成后的采集设置与提交值不匹配，请核对配置。");
    settings.value=applied;
    saved.value=applied.enabled ? applied.auto_inject_html ? "已启用：采集代理与 HTML 自动接入已写入对应网站，Nginx 校验和应用成功。" : "采集代理已启用，HTML 自动接入关闭。请使用网站模板中的手动采集标签。" : "已停用：对应网站的采集代理和 HTML 自动接入均已移除，Nginx 校验和应用成功；历史报告保留。";
  }catch(e){if(disposed||current!==sequence)return;error.value=(e as Error).message;try{const actual=await props.api<Settings>(`/analytics/sites/${id}/config`);if(!disposed&&current===sequence)settings.value=actual;}catch{/* Keep the failure visible; never claim an unverified configuration was saved. */}}
  finally{if(current===sequence)busy.value=false;}
}
function exportJSON(){if(!report.value)return;const url=URL.createObjectURL(new Blob([JSON.stringify(report.value,null,2)],{type:"application/json"}));const link=document.createElement("a");link.href=url;link.download=`website-analytics-${selected.value}.json`;link.click();URL.revokeObjectURL(url);}
async function computeFunnel(){
  if(!selected.value || funnelBusy.value || query.value.problem)return;
  const steps=funnelSteps.value.split(/\r?\n/).map(s=>s.trim()).filter(Boolean);
  if(steps.length<2 || steps.length>8){funnelError.value="请输入 2–8 个页面路径，每行一步。";return;}
  const current=++funnelSequence,selection=query.value,key=funnelQueryKey.value,q=browserAnalyticsQueryParams(selection);for(const step of steps)q.append("step",step);
  const windowMinutes=funnelWindow.value;q.set("window_minutes",String(windowMinutes));
  const id=selected.value;funnelBusy.value=true;funnelError.value="";funnelValue.value=undefined;funnelKey.value="";
  try{
    const out=await props.api<Funnel>(`/analytics/sites/${id}/funnel?${q}`);
    if(disposed||current!==funnelSequence||key!==funnelQueryKey.value)return;
    if(!browserAnalyticsReportMatches(selection,out)||out.window_minutes!==windowMinutes||!Array.isArray(out.steps)||out.steps.length!==steps.length||out.steps.some((s,i)=>s.path!==steps[i]))throw new Error("漏斗返回的时间、页面或时限与查询不一致，未显示或导出。");
    funnelValue.value=out;funnelKey.value=key;
  }
  catch(e){if(!disposed&&current===funnelSequence&&key===funnelQueryKey.value)funnelError.value=(e as Error).message;}
  finally{if(current===funnelSequence)funnelBusy.value=false;}
}
function exportFunnel(){if(!funnel.value)return;const url=URL.createObjectURL(new Blob([JSON.stringify(funnel.value,null,2)],{type:"application/json"}));const link=document.createElement("a");link.href=url;link.download=`website-funnel-${selected.value}.json`;link.click();URL.revokeObjectURL(url);}
watch(()=>query.value.key,()=>{reportFence.invalidate();reportTicket.value=undefined;reportValue.value=undefined;error.value="";},{flush:"sync"});
watch([selected,rangeStart,rangeEnd,funnelSteps,funnelWindow],()=>{++funnelSequence;funnelValue.value=undefined;funnelKey.value="";funnelError.value="";funnelBusy.value=false;},{deep:true,flush:"sync"});
watch(selected,()=>void load());
watch([()=>props.installed,htmlSupported],()=>{if(!props.installed||!htmlSupported.value)htmlEngineReady.value=false;});
onBeforeUnmount(()=>{disposed=true;++sequence;++funnelSequence;reportFence.invalidate();});
const metrics=[{key:"pv",label:"浏览量 PV"},{key:"uv",label:"浏览器访客 UV"},{key:"sessions",label:"访问会话"},{key:"active_visitors",label:"5 分钟活跃访客"}] as const;
const dimensions=[{key:"pages",label:"访问页面"},{key:"entry_pages",label:"入口页面"},{key:"exit_pages",label:"离开页面"},{key:"sources",label:"来源域名"},{key:"campaigns",label:"推广活动"},{key:"browsers",label:"浏览器"},{key:"devices",label:"设备"}] as const;
</script>
<template>
  <section class="analytics-workspace" data-testid="analytics-workspace" v-loading="busy">
    <div class="analytics-toolbar">
      <el-select v-model="selected" placeholder="选择需要分析的网站" filterable :disabled="busy" aria-label="统计网站"><el-option v-for="s in sites" :key="s.id" :value="s.id" :label="`${s.name} · ${s.domain}`" /></el-select>
      <div class="analytics-date-field"><label for="analytics-report-from">开始时间（本地）</label><el-date-picker id="analytics-report-from" v-model="rangeStart" type="datetime" placeholder="未指定" :disabled="busy" aria-label="统计开始时间" /></div>
      <div class="analytics-date-field"><label for="analytics-report-to">结束时间（本地）</label><el-date-picker id="analytics-report-to" v-model="rangeEnd" type="datetime" placeholder="未指定" :disabled="busy" aria-label="统计结束时间" /></div>
      <el-button :disabled="!selected || busy || !!query.problem" @click="refresh">刷新统计</el-button>
      <el-button :disabled="!report || busy" @click="exportJSON">导出统计</el-button>
    </div>
    <el-alert v-if="error" :title="error" type="error" :closable="false" />
    <el-alert v-if="selected && query.problem" :title="query.problem" type="error" :closable="false" />
    <p v-if="selected && !report && !busy && !query.problem" class="analytics-query-status" role="status">请刷新统计，获取当前时间范围的报告。</p>
    <p v-if="report" class="analytics-query-status" role="status">已查询范围（UTC）：{{report.from}} → {{report.to}}</p>
    <el-alert v-if="saved" :title="saved" type="success" :closable="false" />
    <el-alert v-if="report?.partial" title="报告达到 20000 条事件或 8 MiB 原始数据上限，仅包含部分结果；请缩短时间范围。" type="warning" :closable="false" />
    <el-tabs v-model="tab" tab-position="left">
      <el-tab-pane label="网站概览" name="overview">
        <p class="analytics-intro">真实浏览器采集，与服务器日志请求统计分开；未接入时保持空数据，不生成演示指标。</p>
        <template v-if="report">
          <div class="analytics-metrics"><article v-for="m in metrics" :key="m.key"><span>{{m.label}}</span><strong>{{report.overview[m.key]}}</strong></article></div>
          <el-descriptions :column="2" border><el-descriptions-item label="平均前台停留">{{report.overview.avg_engagement_seconds.toFixed(1)}} 秒</el-descriptions-item><el-descriptions-item label="跳出率">{{report.overview.bounce_rate.toFixed(1)}}%</el-descriptions-item><el-descriptions-item label="实际采样事件">{{report.sampled_events}}</el-descriptions-item><el-descriptions-item label="采集状态">{{settings?.enabled ? '已开启，等待/接收浏览器事件' : '未开启'}}</el-descriptions-item></el-descriptions>
          <AnalyticsPeriodComparison v-if="installedVersion === '2.4.3' || installedVersion === '2.4.4' || geographySupported" :api="api" :site="selected" :from="report.from" :to="report.to" />
          <section v-if="report.client_addresses" class="analytics-client-addresses" aria-label="客户端连接地址统计">
            <h4>客户端连接地址</h4>
            <p>从直接连接或受保护的本机采集代理取得，只保存按网站隔离的地址摘要。连接地址可能属于 NAT、CDN 或其它代理，不能用来认定真实人数；旧记录和未核实来源单独列出。</p>
            <el-descriptions :column="2" border>
              <el-descriptions-item label="已取得地址的不同摘要">{{report.client_addresses.known_pageviews ? report.client_addresses.unique_addresses : '无样本'}}</el-descriptions-item>
              <el-descriptions-item label="含地址的浏览记录">{{report.client_addresses.known_pageviews}} / {{report.overview.pv}}</el-descriptions-item>
              <el-descriptions-item label="地址未核实的浏览记录">{{report.client_addresses.unknown_pageviews}}</el-descriptions-item>
              <el-descriptions-item label="其中旧版本记录">{{report.client_addresses.legacy_pageviews}}</el-descriptions-item>
            </el-descriptions>
          </section>
          <h4>UTC 小时趋势</h4><el-table :data="[...report.hours].sort((a,b)=>a.name.localeCompare(b.name))" empty-text="尚无浏览器浏览数据"><el-table-column prop="name" label="小时" /><el-table-column prop="count" label="浏览量" /></el-table>
        </template>
        <el-empty v-else :description="selected ? '刷新统计后查看当前范围的真实指标。' : '请选择网站；接入采集后查看真实指标'" />
      </el-tab-pane>
      <el-tab-pane label="页面与来源" name="dimensions">
        <template v-if="report"><section v-for="d in dimensions" :key="d.key" class="analytics-dimension"><h4>{{d.label}}</h4><el-table :data="report[d.key]" empty-text="尚无数据" max-height="230"><el-table-column prop="name" label="项目" show-overflow-tooltip /><el-table-column prop="count" label="浏览量" width="100" /></el-table></section></template>
        <el-empty v-else :description="selected ? '刷新统计后查看当前范围的分布。' : '选择网站后查看分布'" />
      </el-tab-pane>
      <el-tab-pane label="访客与会话" name="sessions">
        <el-alert v-if="(report?.ordering_uncertain_sessions||0)>0" title="部分会话缺少访问序号或序号存在冲突，这些旅程按服务端接收顺序估计；旧记录保留原样。" type="warning" :closable="false" />
        <p>标识经服务端按网站隔离后哈希。浏览器标识不等于真实人数，原始 IP 不保留。</p>
        <el-table :data="report?.sessions || []" empty-text="尚无会话数据" max-height="480"><el-table-column type="expand"><template #default="{row}"><p>访问旅程：{{row.journey.join(' → ')}}</p><p>旅程顺序：{{row.page_order_source==='browser-navigation-sequence' && row.page_order_uncertain===false ? '浏览器报告顺序' : '接收顺序（待核对）'}}。接收时间不等于页面发生时间。</p><p>会话标识：{{row.id}}</p></template></el-table-column><el-table-column prop="entry" label="入口" show-overflow-tooltip /><el-table-column prop="exit" label="离开" show-overflow-tooltip /><el-table-column prop="source" label="来源" /><el-table-column prop="pages" label="浏览页数" width="100" /><el-table-column label="前台停留（秒）" width="150"><template #default="{row}">{{row.duration.toFixed(1)}}</template></el-table-column></el-table>
      </el-tab-pane>
      <el-tab-pane label="点击热图" name="heatmap">
        <p>需在采集设置单独开启。使用文档百分比坐标，支持按采集时的屏宽查看。</p>
        <template v-if="report">
          <div class="analytics-toolbar">
            <el-select v-model="heatPath" :disabled="!heatPaths.length" placeholder="选择页面" aria-label="热图页面"><el-option v-for="p in heatPaths" :key="p" :value="p" :label="p" /></el-select>
            <el-select v-if="layoutHeat" v-model="heatViewport" :disabled="!viewportOptions.length" placeholder="选择屏宽" aria-label="热图屏宽"><el-option v-for="option in viewportOptions" :key="option.value" :value="option.value" :label="option.label" /></el-select>
          </div>
          <el-alert v-if="layoutHeat?.partial" title="点击热图达到采样或容量上限，请缩短统计时间范围。" type="warning" :closable="false" />
          <dl class="analytics-heat-summary" aria-label="当前页面点击热图摘要" role="status">
            <div><dt>记录点击</dt><dd data-testid="heatmap-clicks">{{heatClicks}}</dd></div>
            <div><dt>有点击的网格</dt><dd data-testid="heatmap-cells">{{heat.length}}</dd></div>
          </dl>
          <template v-if="heat.length">
            <p class="analytics-intro">位置为文档百分比范围，圆点大小表示该网格记录的点击次数。</p>
            <svg class="analytics-heatmap" viewBox="0 0 100 100" role="img" :aria-label="`${heatPath} 点击坐标分布，共 ${heatClicks} 次点击，${heat.length} 个网格`"><rect width="100" height="100" fill="#f3f6fa"/><circle v-for="(p,i) in heat" :key="i" :cx="p.x+2.5" :cy="p.y+2.5" :r="Math.min(5,1+Math.log2(1+p.count))" fill="#f97316" fill-opacity="0.55"><title>水平 {{p.x}}–{{Math.min(100,p.x+5)}}%，垂直 {{p.y}}–{{Math.min(100,p.y+5)}}%：{{p.count}} 次点击</title></circle></svg>
            <AnalyticsHeatmapOverlay v-if="layoutHeat && heatViewport && heatViewport!=='unknown'"
              :key="JSON.stringify([query.key,heatPath,heatViewport])" :points="heat" :page="heatPath" />
            <h4>坐标明细</h4>
            <el-table :data="heatRows" max-height="300" aria-label="点击坐标明细" class="analytics-heat-details">
              <el-table-column label="水平位置" min-width="88"><template #default="{row}">{{row.x}}–{{Math.min(100,row.x+5)}}%</template></el-table-column>
              <el-table-column label="垂直位置" min-width="88"><template #default="{row}">{{row.y}}–{{Math.min(100,row.y+5)}}%</template></el-table-column>
              <el-table-column prop="count" label="点击次数" min-width="88" align="right" />
            </el-table>
            <el-pagination v-if="heat.length>20" v-model:current-page="heatPage" :page-size="20" :total="heat.length" :pager-count="5" layout="prev, pager, next" small class="analytics-heat-pages" aria-label="点击坐标明细分页" />
          </template>
          <el-empty v-else description="当前网站和时间范围没有点击记录。" />
        </template>
        <el-empty v-else :description="selected ? '刷新统计后查看当前范围的点击数据。' : '请选择需要分析的网站。'" />
      </el-tab-pane>
      <el-tab-pane label="转化漏斗" name="funnel">
        <p>每行填写一个本网站页面路径，按顺序分析浏览器会话；精确匹配，不填写域名、查询参数或片段。上方时间范围同时用于漏斗。默认路径只是输入示例，不代表已发生转化。</p>
        <el-form label-position="top"><el-form-item label="顺序页面（2–8 步）"><el-input v-model="funnelSteps" type="textarea" :rows="4" :maxlength="16400" aria-label="漏斗顺序页面" /></el-form-item><el-form-item label="从入口到目标的转化时限（分钟）"><el-input-number v-model="funnelWindow" :min="1" :max="1440" aria-label="漏斗转化时限" /></el-form-item><el-button type="primary" :disabled="!selected || funnelBusy || !!query.problem" :loading="funnelBusy" @click="computeFunnel">计算真实漏斗</el-button><el-button :disabled="!funnel || funnelBusy" @click="exportFunnel">导出漏斗</el-button></el-form>
        <el-alert v-if="funnelError" :title="funnelError" type="error" :closable="false" />
        <el-alert v-if="(funnel?.ordering_uncertain_sessions||0)>0" title="漏斗包含顺序待核对的会话，转化结果仅供估计；缺少或冲突的访问序号、网络延迟均可能影响顺序与时限。" type="warning" :closable="false" />
        <template v-if="funnel"><el-alert v-if="funnel.partial" title="漏斗达到 20000 条页面事件或 8 MiB 上限，早期步骤可能缺失；请缩短时间范围，不可据此认定完整转化率。" type="warning" :closable="false" />
          <p>{{funnel.from}} → {{funnel.to}} · {{funnel.sampled_pageviews}} 条页面事件 · {{funnel.unique_pageviews}} 次去重页面访问 · {{funnel.completed_sessions}} 个完成会话</p>
          <el-table :data="funnel.steps" empty-text="没有匹配页面"><el-table-column type="index" label="步骤" width="70" /><el-table-column prop="path" label="页面路径" show-overflow-tooltip /><el-table-column prop="sessions" label="到达会话" width="105" /><el-table-column label="入口转化率" width="125"><template #default="{row}">{{row.overall_rate.toFixed(1)}}%</template></el-table-column><el-table-column label="上步转化率" width="125"><template #default="{row,$index}">{{$index===0?'—':row.previous_rate.toFixed(1)+'%'}}</template></el-table-column><el-table-column label="到下步流失" width="110"><template #default="{row,$index}">{{$index===funnel.steps.length-1?'—':row.drop_off}}</template></el-table-column></el-table>
          <h4>完成转化的耗时（秒）</h4><el-descriptions v-if="funnel.completed_sessions" :column="2" border><el-descriptions-item v-for="(value,key) in funnel.duration_seconds" :key="key" :label="String(key).toUpperCase()">{{value.toFixed(1)}}</el-descriptions-item></el-descriptions><p v-else>没有完成会话，耗时无样本；不显示假零值。</p>
          <ul><li v-for="note in funnel.limitations" :key="note">{{note}}</li></ul>
        </template><el-empty v-else-if="!funnelBusy" description="选择网站并输入业务路径后计算；不会生成演示结果" />
      </el-tab-pane>
      <el-tab-pane v-if="geographySupported" label="地理分布" name="geography">
        <template v-if="report?.geography">
          <p>根据已核实连接的 IP 估算国家或地区。报告按浏览量统计，只保留国家代码和所用数据版本。</p>
          <el-alert v-if="report.geography.partial" title="当前范围只统计已读取的样本。" type="warning" :closable="false" />
          <el-table :data="report.geography.countries" empty-text="当前时间范围没有已定位的浏览记录" aria-label="国家或地区浏览量">
            <el-table-column label="国家或地区"><template #default="{row}">{{regionName(row.name)}}</template></el-table-column>
            <el-table-column label="浏览量" prop="count" width="95" align="right" />
          </el-table>
          <el-table :data="report.geography.statuses" empty-text="当前时间范围没有浏览记录" aria-label="地理分布采集结果">
            <el-table-column label="采集结果"><template #default="{row}">{{geographyStatus[row.name] || row.name}}</template></el-table-column>
            <el-table-column label="浏览量" prop="count" width="95" align="right" />
          </el-table>
          <p v-if="report.geography.data_releases.length && report.geography.attribution_url === 'https://db-ip.com/' && report.geography.license_url === 'https://creativecommons.org/licenses/by/4.0/'">
            数据版本 {{report.geography.data_releases.map(row => row.name).join('、')}}。
            <a :href="report.geography.attribution_url" target="_blank" rel="noopener noreferrer">{{report.geography.attribution}}</a>
            · <a :href="report.geography.license_url" target="_blank" rel="noopener noreferrer">CC BY 4.0</a>
          </p>
        </template>
        <el-empty v-else description="选择网站和统计时间范围后刷新。" />
      </el-tab-pane>
      <el-tab-pane label="页面性能" name="performance">
        <AnalyticsPerformanceReport v-if="report" :document-metrics="report.performance" :pages="report.performance_pages" />
      </el-tab-pane>
      <el-tab-pane label="采集设置" name="settings">
        <el-alert v-if="settings?.enabled && settings.client_address_mode==='legacy_proxy'" title="当前网站仍使用旧采集代理。保存采集配置后启用受保护的客户端地址传递；历史记录保持原样。" type="info" :closable="false" />
        <AnalyticsHTMLEngine :api="api" :installed="installed" :supported="htmlSupported" @ready="htmlEngineReady=$event" />
        <template v-if="settings"><el-alert title="采集默认关闭。开启前请按你的网站隐私政策设置访客告知或同意机制；采集器尊重 DNT/GPC，且不采集输入内容。" type="info" :closable="false" />
          <el-form label-position="top" class="analytics-settings"><el-form-item label="启用浏览器采集（立即应用）"><el-switch v-model="settings.enabled" aria-label="启用浏览器采集" :disabled="!installed || busy" @change="setEnabled" /></el-form-item><el-form-item label="HTML 自动接入（立即应用）"><el-switch v-model="settings.auto_inject_html" aria-label="HTML 自动接入" :disabled="!installed || busy || (!settings.auto_inject_html && (!settings.enabled || !htmlSupported || !htmlEngineReady))" @change="save" /></el-form-item><el-form-item label="启用点击坐标（可选）"><el-switch v-model="settings.clicks" :disabled="!installed || busy" /></el-form-item><el-form-item v-if="geographySupported" label="统计访客国家或地区"><el-switch v-model="settings.geography" aria-label="统计访客国家或地区" :disabled="!installed || !settings.enabled || busy" /><p>保存后从网站统计 v2 已验签的地理库读取。旧记录保持原样。</p></el-form-item><el-form-item label="事件保留天数（1–90）"><el-input-number v-model="settings.retention_days" :min="1" :max="90" :disabled="!installed || busy" /></el-form-item><el-button type="primary" :disabled="!installed || busy" @click="save">保存采集设置</el-button></el-form>
          <p>缩短保留天数会在后续采集时清理过期事件，不能恢复；导出统计只包含聚合结果，不是原始事件备份。</p>
          <h4>同源采集代理（自动管理）</h4><p>开启立即自动添加到对应网站配置，关闭立即移除；执行器先备份，再校验 Nginx 并应用，失败恢复旧配置。仅允许 tracker.js、auto.js 和 event，不代理面板管理接口。</p><p>访客入口：{{site?.domain}}/__yunzhan/analytics/ → 本机采集服务。{{settings.proxy_endpoint ? `已应用的内部上游：http://${settings.proxy_endpoint}/collect/analytics/` : '当前没有已应用的受管采集代理。'}}</p>
          <h4>{{settings.auto_inject_html ? '已选择 HTML 自动接入' : '手动添加 JS 采集标签'}}</h4><p v-if="settings.auto_inject_html">无需修改模板。仅本网站启用，关闭自动接入会从 Nginx 配置撤掉响应过滤器，模板文件始终保持原样。已经手动加入的同一采集器会去重，不重复计数。</p><p v-else>将下列代码加入 {{site?.domain}} 的 HTML 模板；或先加载可选引擎，再开启本网站的 HTML 自动接入。</p><p>浏览器始终使用当前网站的域名与协议；内部上游不应换成网站域名，否则可能循环代理。严格 CSP、压缩上游或缺少明确 head 的页面可能需要手动接入；自动接入不改写这些页面。</p><pre v-if="!settings.auto_inject_html">{{snippet}}</pre>
          <h4>能力与边界</h4><ul><li v-for="note in report?.limitations || []" :key="note">{{note}}</li><li>全机最多保留 200000 条事件；每个面板进程每秒最多接收 100 个请求。已核实的客户端地址每分钟最多接收 1200 个通过格式校验的采集请求；未核实地址的旧代理采集按网站和浏览器访客标识分别计数，每个面板进程每分钟最多核准 6000 次采集处理，独立限额表最多保留 6000 个当分钟计数项；跨分钟的延迟请求会重新核对当前总限额。达到上限会拒绝新采集，不伪造统计。</li></ul>
        </template><el-empty v-else description="先选择网站" />
      </el-tab-pane>
      <el-tab-pane label="版本与更新" name="version"><slot name="version" /></el-tab-pane>
    </el-tabs>
  </section>
</template>
<style scoped>
.analytics-toolbar{display:flex;gap:12px;flex-wrap:wrap;margin:10px 0 20px}.analytics-toolbar .el-select{width:280px}.analytics-metrics{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:12px;margin:18px 0}.analytics-metrics article{border:1px solid var(--el-border-color);border-radius:8px;padding:16px}.analytics-metrics span{display:block;color:var(--el-text-color-secondary);font-size:12px}.analytics-metrics strong{display:block;font-size:28px;margin-top:8px}.analytics-dimension{margin-bottom:24px}.analytics-heatmap{display:block;width:100%;max-width:450px;height:auto;aspect-ratio:1;margin:20px auto}.analytics-settings{display:flex;gap:20px;align-items:end;flex-wrap:wrap;margin-top:16px}pre{padding:16px;background:var(--el-fill-color-light);overflow-x:auto;white-space:pre-wrap;overflow-wrap:anywhere;font-size:12px}li{margin-bottom:8px}.analytics-intro{color:var(--el-text-color-secondary)}@media(max-width:650px){.analytics-metrics{grid-template-columns:repeat(2,minmax(0,1fr))}.analytics-workspace :deep(.el-tabs--left){display:block}.analytics-workspace :deep(.el-tabs__header){float:none}}
</style>
<style scoped>
.analytics-workspace :deep(.el-tabs__content){min-width:0}
.analytics-toolbar{align-items:flex-end}
.analytics-date-field{flex:1 1 220px;min-width:220px}
.analytics-date-field label{display:block;margin-bottom:6px;font-size:13px;color:var(--el-text-color-regular)}
.analytics-date-field :deep(.el-date-editor){width:100%;min-width:0}
.analytics-query-status{font-size:13px;overflow-wrap:anywhere;color:var(--el-text-color-secondary)}
.analytics-heat-summary{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:12px;margin:16px 0}.analytics-heat-summary>div{min-width:0;border:1px solid var(--el-border-color);border-radius:8px;padding:12px}.analytics-heat-summary dt{font-size:12px;color:var(--el-text-color-secondary)}.analytics-heat-summary dd{margin:6px 0 0;font-size:24px;font-weight:600;overflow-wrap:anywhere}.analytics-heat-details{width:100%;min-width:0}.analytics-heat-pages{display:flex;justify-content:center;margin-top:12px;max-width:100%}

@media(max-width:650px){
  .analytics-date-field{flex-basis:100%;min-width:0}
  .analytics-workspace :deep(.el-tabs__header.is-left){width:100%;height:auto;margin:0 0 12px}
  .analytics-workspace :deep(.el-tabs__nav-wrap){overflow:visible;margin-bottom:0}
  .analytics-workspace :deep(.el-tabs__nav-wrap::after),
  .analytics-workspace :deep(.el-tabs__active-bar),
  .analytics-workspace :deep(.el-tabs__nav-prev),
  .analytics-workspace :deep(.el-tabs__nav-next){display:none}
  .analytics-workspace :deep(.el-tabs__nav.is-left){display:flex;flex-direction:row;flex-wrap:wrap;float:none;transform:none!important;gap:2px}
  .analytics-workspace :deep(.el-tabs__item.is-left){height:36px;padding:0 10px;justify-content:center;border-radius:4px}
  .analytics-workspace :deep(.el-tabs__item.is-active){background:var(--el-color-primary-light-9)}
}
</style>
