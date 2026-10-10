<script setup lang="ts">
import {computed} from "vue";
import {analyticsLatencyView, latencySampleLimit, latencySecondsLabel} from "./analyticsLatency";
const props = defineProps<{report: unknown}>();
const view = computed(() => analyticsLatencyView(props.report));
</script>
<template>
  <section class="latency-report" aria-label="请求耗时分布">
    <h4>请求耗时分布</h4>
    <p>来自 Nginx 请求总耗时，包含向客户端发送响应的时间；不是后端执行耗时、TTFB 或浏览器 Web Vitals。分位数采用最近秩法，上界计入对应区间。</p>
    <el-alert v-if="!view" type="warning" title="耗时报告格式或数量不一致，未显示猜测值；请刷新并核对面板版本。" :closable="false" />
    <template v-else>
      <el-alert v-if="view.partial" type="warning" title="只覆盖本次读取的有效请求，不能代表全量网站性能。" :closable="false" />
      <el-alert v-if="!view.available" type="info" :title="view.limited ? `有效请求超过 ${latencySampleLimit} 条，精确分位数不可用；未使用前段样本冒充完整分位数。区间计数仍覆盖本次有效请求。` : '当前筛选没有有效请求，分位数不可用；不显示为零耗时。'" :closable="false" />
      <div class="latency-quantiles">
        <div v-for="q in view.quantiles" :key="q.label"><span>{{q.label}}</span><strong>{{latencySecondsLabel(q.seconds)}}</strong></div>
      </div>
      <p class="latency-population">本次有效请求：{{view.requests}} 条</p>
      <table>
        <caption>非累计耗时区间，计数总和为本次有效请求数</caption>
        <thead><tr><th scope="col">耗时区间</th><th scope="col">请求数</th><th scope="col">占比</th></tr></thead>
        <tbody><tr v-for="b in view.buckets" :key="b.range"><th scope="row">{{b.range}}</th><td>{{b.requests}}</td><td class="latency-percent"><meter :value="b.percent" min="0" max="100" :aria-label="`${b.range} 请求占比`" /> <span>{{b.percent.toFixed(2)}}%</span></td></tr></tbody>
      </table>
    </template>
  </section>
</template>
<style scoped>
.latency-report {margin:20px 0; border:1px solid var(--el-border-color-lighter); border-radius:8px; padding:16px; min-width:0}
.latency-report h4 {margin:0 0 8px}
.latency-report p,.latency-report caption {color:var(--el-text-color-secondary); font-size:13px; line-height:1.6; text-align:left}
.latency-quantiles {display:grid; grid-template-columns:repeat(4,minmax(0,1fr)); gap:12px; margin:12px 0}
.latency-quantiles div {background:var(--el-fill-color-light); border-radius:6px; padding:12px; display:flex; flex-direction:column; gap:8px}
.latency-quantiles span {font-size:12px; color:var(--el-text-color-secondary)}
.latency-quantiles strong {font-variant-numeric:tabular-nums; overflow-wrap:anywhere}
.latency-report table {width:100%; border-collapse:collapse; table-layout:fixed; font-size:13px}
.latency-report th,.latency-report td {text-align:left; padding:9px 6px; border-bottom:1px solid var(--el-border-color-lighter); overflow-wrap:anywhere}
.latency-percent {display:flex; align-items:center; gap:8px}
.latency-percent meter {width:100%; min-width:0; max-width:160px}
.latency-percent span {font-variant-numeric:tabular-nums; white-space:nowrap}
@media(max-width:640px) {.latency-quantiles {grid-template-columns:repeat(2,minmax(0,1fr))} .latency-percent {flex-direction:column; align-items:flex-start; gap:3px} .latency-report {padding:12px}}
</style>
