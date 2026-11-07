<script setup lang="ts">
import {computed,ref} from "vue";
import {analyticsMetricText,analyticsPerformanceRows,documentPerformanceMetrics,routePerformanceMetrics} from "./analyticsPerformance";
import type {AnalyticsMetric,AnalyticsPerformancePages} from "./analyticsPerformance";
const props=defineProps<{documentMetrics:Record<string,AnalyticsMetric>;pages?:AnalyticsPerformancePages}>();
const kind=ref(""),query=ref("");
const rows=computed(()=>analyticsPerformanceRows(props.pages,kind.value,query.value));
const integration=`// 路径变化后，以网站真实加载和渲染流程作为参数调用。
// 定义包装器不会发送数据；不要用固定延时冒充网站就绪。
async function renderTrackedRoute(loadAndRender) {
  const api = window.yunzhanAnalytics;
  let route = null;
  try {
    if (api?.routePerformanceVersion === 1 &&
        typeof api.currentRoute === "function" &&
        typeof api.routeReady === "function") route = api.currentRoute();
  } catch {} // 统计异常不阻断网站。
  const result = await loadAndRender(); // 失败时不发送就绪耗时。
  try { if (route) api.routeReady(route.id); } catch {}
  return result; // 保留网站自己的加载结果。
}`;
</script>
<template>
  <section class="performance-report" aria-label="页面与路由性能">
    <h4>完整文档性能 · p75</h4>
    <p>标准指标归属最初加载的文档。INP 使用本地 web-vitals；没有可测交互时显示无样本。CLS 无单位，其余为毫秒。</p>
    <dl class="performance-metrics">
      <div v-for="metric in documentPerformanceMetrics" :key="metric.key"><dt>{{metric.label}}</dt><dd>{{analyticsMetricText(documentMetrics[metric.key],metric.key)}}</dd></div>
    </dl>
    <h4>逐页性能</h4>
    <p v-if="pages">窗口内选取 {{pages.sampled_visits}} 次文档或路由访问，按路径和类型分别统计，最多展示 {{pages.group_limit}} 组。相同访问的重复性能更新只保留最后顺序的样本。</p>
    <p v-if="pages?.partial" class="performance-warning" role="status">性能报告达到事件、访问或分组上限，当前为部分结果；请缩短时间范围。</p>
    <div class="performance-filters">
      <label>访问类型<select v-model="kind" aria-label="性能访问类型"><option value="">全部类型</option><option value="document">完整文档</option><option value="spa">SPA 路由</option></select></label>
      <label>页面路径<input v-model="query" type="search" maxlength="2048" placeholder="筛选路径" aria-label="性能页面路径" /></label>
    </div>
    <div v-if="rows.length" class="performance-pages">
      <article v-for="row in rows" :key="`${row.kind}:${row.path}`" class="performance-page">
        <header><strong>{{row.path}}</strong><span>{{row.kind==='spa'?'SPA 路由':'完整文档'}} · {{row.navigations}} 次访问</span></header>
        <dl class="performance-metrics"><div v-for="metric in row.kind==='spa'?routePerformanceMetrics:documentPerformanceMetrics" :key="metric.key"><dt>{{metric.label}} · p75</dt><dd>{{analyticsMetricText(row.metrics[metric.key],metric.key)}}</dd></div></dl>
      </article>
    </div>
    <p v-else role="status">{{pages?'当前范围及筛选条件下没有性能样本。':'当前服务未提供逐页性能，请核对面板版本；已有完整文档指标保留。'}}</p>
    <details class="performance-integration"><summary>接入 SPA 路由就绪耗时</summary>
      <p>采集启用后，在网站自己的路由视图就绪流程中接入。耗时从 pathname 变化到网站显式确认就绪；不包含路径变化前的请求，不代表路由的 LCP 或 INP。采集器不会猜测数据已加载或页面已绘制。</p>
      <pre>{{integration}}</pre>
      <p>示例包装器需要接收你的网站真实加载和渲染函数；未调用不发送数据。本次标识应在异步工作开始前保存，传回同一个标识。一次访问只尝试发送一次；重复调用、快速跳转后的旧标识、切后台或恢复的页面、超过五分钟的测量均不发送。routeReady 返回 true 表示已尝试发送，不保证服务端接收。只发送路径与数值，不发送本次临时标识、页面 DOM、输入内容、URL 查询或片段。</p>
      <p>未接入、采集关闭、DNT/GPC 或浏览器不允许时不生成路由耗时。仅 query/hash 改变不作为新路由；原完整文档的性能与访问旅程保持分开。</p>
    </details>
  </section>
</template>
<style scoped>
.performance-report{min-width:0}.performance-report p{line-height:1.7;color:var(--el-text-color-secondary)}.performance-metrics{display:grid;grid-template-columns:repeat(auto-fit,minmax(min(160px,100%),1fr));gap:10px;margin:14px 0}.performance-metrics div{padding:12px;border:1px solid var(--el-border-color);border-radius:6px;min-width:0}.performance-metrics dt{font-size:12px;color:var(--el-text-color-secondary)}.performance-metrics dd{margin:6px 0 0;overflow-wrap:anywhere}.performance-filters{display:flex;gap:12px;flex-wrap:wrap;margin:16px 0}.performance-filters label{display:flex;gap:8px;align-items:center;min-width:0}.performance-filters input,.performance-filters select{box-sizing:border-box;min-width:0;max-width:100%;height:34px;padding:4px 10px;border:1px solid var(--el-border-color);border-radius:4px;background:var(--el-bg-color);color:var(--el-text-color-primary);font:inherit}.performance-pages{display:grid;gap:12px}.performance-page{padding:14px;border:1px solid var(--el-border-color);border-radius:8px;min-width:0}.performance-page header{display:flex;gap:8px;justify-content:space-between;flex-wrap:wrap}.performance-page strong{overflow-wrap:anywhere;min-width:0}.performance-page header span{color:var(--el-text-color-secondary);font-size:12px}.performance-warning{padding:12px;background:var(--el-color-warning-light-9);border-radius:6px}.performance-integration{margin-top:20px}.performance-integration summary{cursor:pointer;color:var(--el-color-primary)}pre{white-space:pre-wrap;overflow-wrap:anywhere;padding:12px;background:var(--el-fill-color-light);font-size:12px}@media(max-width:650px){.performance-filters{display:grid}.performance-filters label{display:grid;grid-template-columns:70px minmax(0,1fr)}.performance-filters input,.performance-filters select{width:100%}}
</style>
