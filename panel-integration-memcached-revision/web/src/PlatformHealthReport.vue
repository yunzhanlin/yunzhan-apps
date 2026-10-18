<script setup lang="ts">
import {computed,onBeforeUnmount,onMounted,ref} from 'vue';
import {platformFleetView,platformHostFilter} from './platformHealthView';
const props=defineProps<{report:unknown}>();
const emit=defineEmits<{select:[row:Record<string,any>]}>();
const now=ref(Date.now()),query=ref(''),state=ref('all');
let timer:ReturnType<typeof setInterval>|undefined;
onMounted(()=>{timer=setInterval(()=>{now.value=Date.now();},30000);});
onBeforeUnmount(()=>{if(timer)clearInterval(timer);});
const view=computed(()=>platformFleetView(props.report,now.value));
const hosts=computed(()=>view.value?platformHostFilter(view.value.hosts,query.value,state.value):[]);
</script>
<template>
  <section class="platform-health-report" aria-label="多主机健康快照">
    <h4>主机健康</h4>
    <p class="fleet-scope">健康仅表示本次可信 HTTPS 与健康协议通过，不等于网站、业务或全部告警正常。指标未知不显示为零；此处是快照，不会自动发起网络检查。</p>
    <el-alert v-if="!view" type="warning" :closable="false" title="主机清单或指标无法完整核对，未显示猜测值或部分清单。请手动刷新报告。" />
    <template v-else>
      <p class="fleet-checked">检查时间（UTC）：<time :datetime="view.checkedAt">{{view.checkedAt}}</time></p>
      <el-alert v-if="view.stale" type="warning" :closable="false" title="这是较早的快照，或检查时间与本机时钟不一致，不能据此认定当前健康；请手动刷新报告。" />
      <dl class="fleet-summary">
        <div><dt>登记主机</dt><dd>{{view.hosts.length}}</dd></div>
        <div><dt>协议通过</dt><dd>{{view.passed}}</dd></div>
        <div><dt>检查未通过</dt><dd>{{view.failed}}</dd></div>
        <div><dt>指标不完整</dt><dd>{{view.unknownMetrics}}</dd></div>
      </dl>
      <p v-if="!view.hosts.length" role="status">尚未登记主机。请在“登记主机”中填写 HTTPS 地址和只读健康授权；不会自动扫描网络。</p>
      <template v-else>
        <div class="fleet-filters">
          <label>筛选当前快照<input v-model="query" aria-label="筛选当前快照" type="search" maxlength="128" placeholder="标识、地址、主机名或系统" /></label>
          <label>检查状态<select v-model="state" aria-label="检查状态"><option value="all">全部主机</option><option value="failed">检查未通过</option><option value="unknown">指标不完整</option></select></label>
        </div>
        <p role="status" class="fleet-filter-count">显示 {{hosts.length}} / {{view.hosts.length}} 台 · 保持登记顺序，仅筛选当前快照</p>
        <p v-if="!hosts.length">没有符合筛选条件的主机。</p>
        <article v-for="host in hosts" :key="host.id" class="fleet-host" :aria-label="`主机 ${host.id}`">
          <header class="fleet-host-heading">
            <div class="fleet-identity"><h5>{{host.id}}</h5><p>{{host.url}}</p><p v-if="host.hostname || host.system" class="fleet-system">{{host.hostname}}<span v-if="host.hostname && host.system"> · </span>{{host.system}}</p></div>
            <el-tag :type="host.passed?'success':'danger'">{{host.passed?'本次协议通过':'本次检查未通过'}}</el-tag>
          </header>
          <p v-if="!host.passed" class="fleet-error" role="note">{{host.error}}<span v-if="host.status">（HTTP {{host.status}}）</span></p>
          <div class="fleet-metrics">
            <div v-for="metric in host.metrics" :key="metric.label" class="fleet-metric">
              <div><span>{{metric.label}}</span><strong>{{metric.percent===null?'未知':`${metric.percent.toFixed(1)}%`}}</strong></div>
              <meter v-if="metric.percent!==null" :value="metric.percent" min="0" max="100" :aria-label="`${host.id} ${metric.label}使用率`" />
              <small>{{metric.capacity || (metric.percent===null?'本次未取得可用指标':'本次有效采样')}}</small>
            </div>
          </div>
          <footer class="fleet-host-footer">
            <span>Nginx：{{host.nginx}}</span>
            <button type="button" class="fleet-select" :aria-label="`填入主机表单：${host.id}`" @click="emit('select',host.source)">填入主机表单<span class="fleet-visually-hidden">：{{host.id}}</span></button>
          </footer>
          <details class="fleet-details"><summary>配置摘要与采样时间</summary><dl><dt>配置 SHA-256（只读）</dt><dd>{{host.source.expected_sha}}</dd><dt>健康报告时间（UTC）</dt><dd>{{host.reportAt || '未取得'}}</dd><dt>指标采样时间（UTC）</dt><dd>{{host.sampledAt || '未取得'}}</dd></dl><p>填入表单不会提交修改；实际更新或移除仍需使用本条主机的配置摘要核对。</p></details>
        </article>
      </template>
    </template>
  </section>
</template>
<style scoped>
.platform-health-report {min-width:0; margin:18px 0; color:var(--el-text-color-primary)}
.platform-health-report h4 {margin:0 0 8px; font-size:16px}
.fleet-scope,.fleet-checked,.fleet-filter-count,.fleet-system,.fleet-details {font-size:13px; line-height:1.6; color:var(--el-text-color-regular)}
.fleet-checked time,.fleet-details dd {overflow-wrap:anywhere}
.fleet-summary {display:grid; grid-template-columns:repeat(4,minmax(0,1fr)); gap:10px; margin:16px 0}
.fleet-summary div {padding:12px; background:var(--el-fill-color-light); border-radius:8px}
.fleet-summary dt {font-size:13px; color:var(--el-text-color-regular)}
.fleet-summary dd {margin:6px 0 0; font-size:24px; font-weight:600; font-variant-numeric:tabular-nums}
.fleet-filters {display:grid; grid-template-columns:minmax(0,2fr) minmax(0,1fr); gap:12px}
.fleet-filters label {display:flex; flex-direction:column; gap:6px; min-width:0; font-size:13px}
.fleet-filters input,.fleet-filters select {box-sizing:border-box; width:100%; min-width:0; min-height:42px; padding:8px 10px; font:inherit; border:1px solid var(--el-border-color); border-radius:6px; background:var(--el-bg-color); color:var(--el-text-color-primary)}
.fleet-host {border:1px solid var(--el-border-color); border-radius:8px; padding:16px; margin:12px 0; min-width:0}
.fleet-host-heading {display:flex; gap:12px; justify-content:space-between; align-items:flex-start}
.fleet-identity {min-width:0; overflow-wrap:anywhere}
.fleet-identity h5 {margin:0; font-size:15px}
.fleet-identity p {margin:6px 0; font-size:13px; line-height:1.5}
.fleet-host-heading .el-tag {flex-shrink:0}
.fleet-error {font-size:13px; line-height:1.6; color:var(--el-color-danger-dark-2); background:var(--el-color-danger-light-9); border-radius:6px; padding:10px; overflow-wrap:anywhere}
.fleet-metrics {display:grid; grid-template-columns:repeat(3,minmax(0,1fr)); gap:16px; margin:14px 0}
.fleet-metric {min-width:0}
.fleet-metric > div {display:flex; justify-content:space-between; align-items:center; gap:6px; font-size:13px}
.fleet-metric strong {font-size:17px; font-variant-numeric:tabular-nums}
.fleet-metric meter {display:block; width:100%; height:12px; margin:5px 0; accent-color:var(--el-color-primary)}
.fleet-metric small {display:block; font-size:12px; color:var(--el-text-color-regular); overflow-wrap:anywhere; margin-top:5px; line-height:1.6}
.fleet-host-footer {display:flex; align-items:center; justify-content:space-between; gap:12px; font-size:13px}
.fleet-select {font:inherit; min-height:44px; padding:8px 12px; border:1px solid var(--el-border-color); border-radius:6px; color:var(--el-color-primary); background:var(--el-bg-color); cursor:pointer}
.fleet-select:focus-visible,.fleet-filters input:focus-visible,.fleet-filters select:focus-visible,.fleet-details summary:focus-visible {outline:2px solid var(--el-color-primary); outline-offset:3px}
.fleet-details {margin-top:12px; border-top:1px solid var(--el-border-color-lighter); padding-top:10px}
.fleet-details summary {cursor:pointer; padding:4px 0}
.fleet-details dl {display:grid; grid-template-columns:170px minmax(0,1fr); gap:6px; margin:10px 0}
.fleet-details dd {margin:0}
.fleet-visually-hidden {position:absolute; width:1px; height:1px; padding:0; margin:-1px; overflow:hidden; clip-path:inset(50%); white-space:nowrap; border:0}
@media(max-width:640px) {.fleet-summary {grid-template-columns:repeat(2,minmax(0,1fr))} .fleet-filters {grid-template-columns:minmax(0,1fr)} .fleet-host {padding:12px} .fleet-host-heading {flex-direction:column; gap:6px} .fleet-metrics {grid-template-columns:minmax(0,1fr); gap:12px} .fleet-metric {padding-top:8px; border-top:1px solid var(--el-border-color-lighter)} .fleet-details dl {grid-template-columns:minmax(0,1fr)} .fleet-host-footer {flex-wrap:wrap}}
</style>
