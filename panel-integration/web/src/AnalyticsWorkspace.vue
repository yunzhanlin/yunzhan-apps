<script setup lang="ts">
import { computed, ref, watch } from "vue";
type API = <T>(path:string,method?:string,body?:unknown,idempotencyKey?:string)=>Promise<T>;
interface Settings {site_id:string;key:string;enabled:boolean;clicks:boolean;retention_days:number;revision:number;proxy_endpoint?:string}
interface Dimension {name:string;count:number}
interface Session {id:string;visitor:string;entry:string;exit:string;source:string;first:number;last:number;pages:number;duration:number;journey:string[]}
interface Report {
  source:string;from:string;to:string;partial:boolean;sampled_events:number;
  overview:{pv:number;uv:number;sessions:number;active_visitors:number;clicks:number;bounce_rate:number;avg_engagement_seconds:number;unique_network_peers:number};
  pages:Dimension[];sources:Dimension[];browsers:Dimension[];devices:Dimension[];entry_pages:Dimension[];exit_pages:Dimension[];hours:Dimension[];campaigns:Dimension[];
  sessions:Session[];heatmap:{path:string;x:number;y:number;count:number}[];
  performance:Record<string,{samples:number;p75?:number}>;limitations:string[];
}
const props=defineProps<{api:API;installed:boolean;sites:{id:string;name:string;domain:string}[]}>();
const selected=ref(""),tab=ref("overview"),busy=ref(false),error=ref(""),saved=ref("");
const settings=ref<Settings>(),report=ref<Report>();
const range=ref<[Date,Date]>(),heatPath=ref("");
let sequence=0;
const site=computed(()=>props.sites.find(s=>s.id===selected.value));
const heat=computed(()=>report.value?.heatmap.filter(p=>p.path===heatPath.value)||[]);
const snippet=computed(()=>settings.value?.key ? `<script defer src="/__yunzhan/analytics/tracker.js?site=${settings.value.site_id}&amp;key=${settings.value.key}"><\/script>` : "先保存采集配置，再生成代码。");
async function load(){
  const current=++sequence;report.value=undefined;settings.value=undefined;saved.value="";error.value="";
  if(!selected.value)return;busy.value=true;
  try {const [cfg,out]=await Promise.all([props.api<Settings>(`/analytics/sites/${selected.value}/config`),props.api<Report>(reportURL())]);if(current!==sequence)return;settings.value=cfg;report.value=out;heatPath.value=out.heatmap[0]?.path||"";}
  catch(e){if(current===sequence)error.value=(e as Error).message;}
  finally{if(current===sequence)busy.value=false;}
}
function reportURL(){const q=new URLSearchParams();if(range.value){q.set("from",range.value[0].toISOString());q.set("to",range.value[1].toISOString());}return `/analytics/sites/${selected.value}/report?${q}`;}
async function refresh(){if(!selected.value||busy.value)return;busy.value=true;error.value="";try{report.value=await props.api<Report>(reportURL());if(!report.value.heatmap.some(p=>p.path===heatPath.value))heatPath.value=report.value.heatmap[0]?.path||"";}catch(e){error.value=(e as Error).message;}finally{busy.value=false;}}
async function save(){
  if(!settings.value||busy.value||!props.installed)return;
  busy.value=true;error.value="";saved.value="";
  const id=selected.value;
  try{
    const queued=await props.api<{job_id:string}>(`/analytics/sites/${id}/config`,"POST",settings.value);
    let completed=false;
    for(let attempt=0;attempt<120;attempt++){
      const job=await props.api<{state:string;error?:string}>(`/jobs/${queued.job_id}`);
      if(job.state==="succeeded"){completed=true;break;}
      if(["failed","needs_attention"].includes(job.state))throw new Error(job.error||"配置应用失败；请在任务列表核对回滚结果。");
      await new Promise(resolve=>setTimeout(resolve,500));
    }
    if(!completed)throw new Error("配置任务仍在执行，请到任务列表核对；此处不会提前报告成功。");
    settings.value=await props.api<Settings>(`/analytics/sites/${id}/config`);
    saved.value=settings.value.enabled?"已启用：对应网站的采集代理已自动写入，Nginx 校验和应用成功。HTML 采集标签仍需加入网站模板。":"已停用：对应网站的采集代理已移除，Nginx 校验和应用成功；历史报告保留。";
  }catch(e){error.value=(e as Error).message;try{settings.value=await props.api<Settings>(`/analytics/sites/${id}/config`);}catch{/* Keep the failure visible; never claim an unverified configuration was saved. */}}
  finally{busy.value=false;}
}
function exportJSON(){if(!report.value)return;const url=URL.createObjectURL(new Blob([JSON.stringify(report.value,null,2)],{type:"application/json"}));const link=document.createElement("a");link.href=url;link.download=`website-analytics-${selected.value}.json`;link.click();URL.revokeObjectURL(url);}
watch(selected,()=>void load());
const metrics=[{key:"pv",label:"浏览量 PV"},{key:"uv",label:"浏览器访客 UV"},{key:"sessions",label:"访问会话"},{key:"active_visitors",label:"5 分钟活跃访客"}] as const;
const dimensions=[{key:"pages",label:"访问页面"},{key:"entry_pages",label:"入口页面"},{key:"exit_pages",label:"离开页面"},{key:"sources",label:"来源域名"},{key:"campaigns",label:"推广活动"},{key:"browsers",label:"浏览器"},{key:"devices",label:"设备"}] as const;
</script>
<template>
  <section class="analytics-workspace" data-testid="analytics-workspace" v-loading="busy">
    <div class="analytics-toolbar">
      <el-select v-model="selected" placeholder="选择需要分析的网站" filterable :disabled="busy" aria-label="统计网站"><el-option v-for="s in sites" :key="s.id" :value="s.id" :label="`${s.name} · ${s.domain}`" /></el-select>
      <el-date-picker v-model="range" type="datetimerange" start-placeholder="开始时间" end-placeholder="结束时间" :disabled="busy" />
      <el-button :disabled="!selected || busy" @click="refresh">刷新统计</el-button>
      <el-button :disabled="!report || busy" @click="exportJSON">导出统计</el-button>
    </div>
    <el-alert v-if="error" :title="error" type="error" :closable="false" />
    <el-alert v-if="saved" :title="saved" type="success" :closable="false" />
    <el-alert v-if="report?.partial" title="报告达到 20000 条事件或 8 MiB 原始数据上限，仅包含部分结果；请缩短时间范围。" type="warning" :closable="false" />
    <el-tabs v-model="tab" tab-position="left">
      <el-tab-pane label="网站概览" name="overview">
        <p class="analytics-intro">真实浏览器采集，与服务器日志请求统计分开；未接入时保持空数据，不生成演示指标。</p>
        <template v-if="report">
          <div class="analytics-metrics"><article v-for="m in metrics" :key="m.key"><span>{{m.label}}</span><strong>{{report.overview[m.key]}}</strong></article></div>
          <el-descriptions :column="2" border><el-descriptions-item label="平均前台停留">{{report.overview.avg_engagement_seconds.toFixed(1)}} 秒</el-descriptions-item><el-descriptions-item label="跳出率">{{report.overview.bounce_rate.toFixed(1)}}%</el-descriptions-item><el-descriptions-item label="实际采样事件">{{report.sampled_events}}</el-descriptions-item><el-descriptions-item label="采集状态">{{settings?.enabled ? '已开启，等待/接收浏览器事件' : '未开启'}}</el-descriptions-item></el-descriptions>
          <h4>UTC 小时趋势</h4><el-table :data="[...report.hours].sort((a,b)=>a.name.localeCompare(b.name))" empty-text="尚无浏览器浏览数据"><el-table-column prop="name" label="小时" /><el-table-column prop="count" label="浏览量" /></el-table>
        </template>
        <el-empty v-else description="请选择网站；接入采集后查看真实指标" />
      </el-tab-pane>
      <el-tab-pane label="页面与来源" name="dimensions">
        <template v-if="report"><section v-for="d in dimensions" :key="d.key" class="analytics-dimension"><h4>{{d.label}}</h4><el-table :data="report[d.key]" empty-text="尚无数据" max-height="230"><el-table-column prop="name" label="项目" show-overflow-tooltip /><el-table-column prop="count" label="浏览量" width="100" /></el-table></section></template>
        <el-empty v-else description="选择网站后查看分布" />
      </el-tab-pane>
      <el-tab-pane label="访客与会话" name="sessions">
        <p>标识经服务端按网站隔离后哈希。浏览器标识不等于真实人数，原始 IP 不保留。</p>
        <el-table :data="report?.sessions || []" empty-text="尚无会话数据" max-height="480"><el-table-column type="expand"><template #default="{row}"><p>访问旅程：{{row.journey.join(' → ')}}</p><p>会话标识：{{row.id}}</p></template></el-table-column><el-table-column prop="entry" label="入口" show-overflow-tooltip /><el-table-column prop="exit" label="离开" show-overflow-tooltip /><el-table-column prop="source" label="来源" /><el-table-column prop="pages" label="浏览页数" width="100" /><el-table-column label="前台停留（秒）" width="150"><template #default="{row}">{{row.duration.toFixed(1)}}</template></el-table-column></el-table>
      </el-tab-pane>
      <el-tab-pane label="点击热图" name="heatmap">
        <p>需在采集设置单独开启。只采集百分比坐标，不读取表单、输入内容或网页截图。</p>
        <el-select v-model="heatPath" placeholder="选择页面" aria-label="热图页面"><el-option v-for="p in [...new Set(report?.heatmap.map(p=>p.path)||[])]" :key="p" :value="p" :label="p" /></el-select>
        <svg v-if="heat.length" class="analytics-heatmap" viewBox="0 0 100 100" role="img" :aria-label="`${heatPath} 点击坐标分布`"><rect width="100" height="100" fill="#f3f6fa"/><circle v-for="(p,i) in heat" :key="i" :cx="p.x+2.5" :cy="p.y+2.5" :r="Math.min(5,1+Math.log2(1+p.count))" fill="#f97316" fill-opacity="0.55"><title>{{p.count}} 次点击</title></circle></svg>
        <el-empty v-else description="暂无点击数据；此图不是网页截图覆盖热图" />
      </el-tab-pane>
      <el-tab-pane label="页面性能" name="performance">
        <p>浏览器样本的 p75 指标（毫秒，CLS 除外）。无样本时不显示零分；当前不采集 INP。</p>
        <el-descriptions v-if="report" :column="2" border><el-descriptions-item v-for="(value,key) in report.performance" :key="key" :label="String(key).toUpperCase()">{{value.p75 === undefined ? '无样本' : value.p75.toFixed(3)}} · {{value.samples}} 个样本</el-descriptions-item></el-descriptions>
      </el-tab-pane>
      <el-tab-pane label="采集设置" name="settings">
        <template v-if="settings"><el-alert title="采集默认关闭。开启前请按你的网站隐私政策设置访客告知或同意机制；采集器尊重 DNT/GPC，且不采集输入内容。" type="info" :closable="false" />
          <el-form label-position="top" class="analytics-settings"><el-form-item label="启用浏览器采集（立即应用）"><el-switch v-model="settings.enabled" aria-label="启用浏览器采集" :disabled="!installed || busy" @change="save" /></el-form-item><el-form-item label="启用点击坐标（可选）"><el-switch v-model="settings.clicks" :disabled="!installed || busy" /></el-form-item><el-form-item label="事件保留天数（1–90）"><el-input-number v-model="settings.retention_days" :min="1" :max="90" :disabled="!installed || busy" /></el-form-item><el-button type="primary" :disabled="!installed || busy" @click="save">保存采集设置</el-button></el-form>
          <p>缩短保留天数会在后续采集时清理过期事件，不能恢复；导出统计只包含聚合结果，不是原始事件备份。</p>
          <h4>同源采集代理（自动管理）</h4><p>开启立即自动添加到对应网站配置，关闭立即移除；执行器先备份，再校验 Nginx 并应用，失败恢复旧配置。仅允许 tracker.js 和 event，不代理面板管理接口。</p><p>访客入口：{{site?.domain}}/__yunzhan/analytics/ → 本机采集服务。{{settings.proxy_endpoint ? `已应用的内部上游：http://${settings.proxy_endpoint}/collect/analytics/` : '当前没有已应用的受管采集代理。'}}</p>
          <h4>添加 JS 采集标签</h4><p>将代码加入 {{site?.domain}} 的 HTML 模板。浏览器始终使用当前网站的域名与协议；内部上游不应换成网站域名，否则可能循环代理。</p><pre>{{snippet}}</pre>
          <h4>能力与边界</h4><ul><li v-for="note in report?.limitations || []" :key="note">{{note}}</li><li>全机最多保留 200000 条事件；每秒最多接收 100 个请求，同一网络对端每分钟最多 1200 个请求。达到上限会拒绝新采集，不伪造统计。</li></ul>
        </template><el-empty v-else description="先选择网站" />
      </el-tab-pane>
      <el-tab-pane label="版本与更新" name="version"><slot name="version" /></el-tab-pane>
    </el-tabs>
  </section>
</template>
<style scoped>
.analytics-toolbar{display:flex;gap:12px;flex-wrap:wrap;margin:10px 0 20px}.analytics-toolbar .el-select{width:280px}.analytics-metrics{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:12px;margin:18px 0}.analytics-metrics article{border:1px solid var(--el-border-color);border-radius:8px;padding:16px}.analytics-metrics span{display:block;color:var(--el-text-color-secondary);font-size:12px}.analytics-metrics strong{display:block;font-size:28px;margin-top:8px}.analytics-dimension{margin-bottom:24px}.analytics-heatmap{display:block;width:100%;max-height:450px;margin-top:20px}.analytics-settings{display:flex;gap:20px;align-items:end;flex-wrap:wrap;margin-top:16px}pre{padding:16px;background:var(--el-fill-color-light);overflow-x:auto;white-space:pre-wrap;overflow-wrap:anywhere;font-size:12px}li{margin-bottom:8px}.analytics-intro{color:var(--el-text-color-secondary)}@media(max-width:650px){.analytics-metrics{grid-template-columns:repeat(2,minmax(0,1fr))}.analytics-workspace :deep(.el-tabs--left){display:block}.analytics-workspace :deep(.el-tabs__header){float:none}}
</style>
