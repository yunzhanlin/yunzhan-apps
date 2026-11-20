<script setup lang="ts">
import {computed} from 'vue';
import {statisticsCoverage} from './statisticsHistory';
const props=defineProps<{report:Record<string,unknown>}>();
const coverage=computed(()=>statisticsCoverage(props.report));
const descriptions={
 partial:'本次报告有覆盖缺口。当前记录可供核对，零条也不能证明没有访问。',
 unknown:'缺少可核对的历史范围或采集记录，无法确认本次覆盖。',
 empty:'在当前筛选与已保留的数据中没有匹配请求。',
 matched:'已显示当前筛选与保留范围内匹配的请求。',
} as const;
const bytes=(n:number|undefined)=>{
 if(n===undefined)return '未核对';
 if(n<1024)return n+' B';
 if(n<1024*1024)return (n/1024).toFixed(1)+' KiB';
 return (n/(1024*1024)).toFixed(1)+' MiB';
};
</script>
<template>
  <section v-if="coverage" class="coverage" aria-label="访问历史覆盖">
    <h4>访问历史覆盖</h4>
    <p role="status" :class="{attention:coverage.state==='partial'||coverage.state==='unknown'}">{{descriptions[coverage.state]}}</p>
    <dl>
      <div><dt>本次匹配请求</dt><dd>{{coverage.count===undefined?'未核对':coverage.count}}</dd></div>
      <div><dt>此站已保留记录（UTC）</dt><dd>{{coverage.first ? coverage.first+' 至 '+coverage.last : '没有可显示的时间范围'}}</dd></div>
      <div><dt>本次日志核对（UTC）</dt><dd>{{coverage.checkedAt||'未核对'}}</dd></div>
      <div><dt>待采集日志</dt><dd>{{bytes(coverage.backlog)}}</dd></div>
      <div><dt>达到上限后退役的历史</dt><dd>{{coverage.evicted===undefined?'未核对':coverage.evicted+' 条'}}</dd></div>
      <div><dt>后台采集最近核对（UTC）</dt><dd>{{coverage.worker==='fresh'?'状态正常':coverage.worker==='stale'?'状态过期或有异常':'状态未核对'}}<br v-if="coverage.workerCheckedAt">{{coverage.workerCheckedAt}}</dd></div>
    </dl>
    <p v-if="coverage.beforeRetention">查询起点早于历史保留范围，较早的访问未计入。</p>
  </section>
</template>
<style scoped>
.coverage{margin:12px 0;padding:14px;border:1px solid var(--panel-border,#dce5ed);border-radius:8px;overflow-wrap:anywhere}
h4{margin:0 0 8px}
p{margin:8px 0}
.attention{color:var(--el-color-warning-dark-2,#805300)}
dl{display:grid;grid-template-columns:repeat(auto-fit,minmax(min(100%,180px),1fr));gap:10px;margin:0}
dt{color:var(--panel-muted,#61738d);font-size:12px}
dd{margin:4px 0 0}
</style>
