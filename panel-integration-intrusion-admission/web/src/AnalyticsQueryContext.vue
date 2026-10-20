<script setup lang="ts">
import { computed } from "vue";
import { analyticsQueryContext } from "./analyticsQueryContext";
const props=defineProps<{report:unknown}>();
const query=computed(()=>analyticsQueryContext(props.report));
</script>
<template>
  <section class="analytics-query-context" aria-label="已返回报告的查询范围">
    <h4>已返回报告的查询范围</h4>
    <el-alert v-if="!query" type="warning" :closable="false" title="该报告未提供可核对的完整查询范围。请明确选择网站和条件后刷新，不将旧报告视为当前筛选结果。" />
    <dl v-else>
      <div><dt>网站 ID</dt><dd>{{ query.site_id }}</dd></div>
      <div><dt>时间范围（UTC）</dt><dd>{{ query.from_time || '保留范围起点' }} → {{ query.to_time || '查询时刻' }}</dd></div>
      <div><dt>路径或 IP</dt><dd>{{ query.search || '未筛选' }}</dd></div>
      <div><dt>HTTP 状态</dt><dd>{{ query.status_code || '全部' }}</dd></div>
      <div><dt>请求类型</dt><dd>{{ query.only_bots ? '仅爬虫' : '全部有效请求' }}</dd></div>
      <div><dt>慢请求阈值</dt><dd>{{ query.min_seconds || 1 }} 秒（不筛除其他请求）</dd></div>
    </dl>
  </section>
</template>
<style scoped>
.analytics-query-context{border:1px solid var(--panel-border,#dce5ed);border-radius:8px;padding:14px;margin:12px 0}
h4{margin:0 0 10px}dl{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:10px;margin:0}dt{color:var(--panel-muted,#61738d);font-size:12px}dd{margin:4px 0 0;overflow-wrap:anywhere;font-size:13px}
@media(max-width:640px){dl{grid-template-columns:1fr}}
</style>
