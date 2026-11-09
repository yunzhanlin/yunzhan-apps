<script setup lang="ts">
import {computed} from 'vue';
import {analyticsGeographyView} from './analyticsGeography';
const props=defineProps<{report:unknown}>();
const view=computed(()=>analyticsGeographyView(props.report));
</script>
<template>
  <section class="geography-report" aria-label="IP 网络地域统计">
    <h4>IP 网络地域统计</h4>
    <p>离线查询，不向外部服务上传访客 IP。国家、地区、城市和坐标仅为网络地址的近似位置，不代表访客或设备的实际位置；VPN、代理、CDN 和共享出口可能影响结果。</p>
    <el-alert v-if="!view" type="warning" title="地域报告格式或数量不一致，未显示猜测结果。" :closable="false" />
    <template v-else>
      <el-alert v-if="!view.available" type="info" title="尚无可用的已验签城市库；公网地址报告为不可用，不填成未知城市或默认国家。" :closable="false" />
      <el-alert v-if="view.partial" type="warning" title="仅覆盖当前读取和筛选后的有效请求，不能代表全量访问。" :closable="false" />
      <el-alert v-if="view.stale" type="warning" title="城市库构建时间超过 90 天，历史库仍可查询，但结果可能过时。" :closable="false" />
      <p>本次筛选：{{view.requests}} 个请求；独立地址查询：{{view.lookups}} / 5000。城市榜最多展示 100 项，其余及未覆盖城市保留计数。</p>
      <p v-if="view.available">数据月份：{{view.release}} · <a href="https://db-ip.com/" target="_blank" rel="noopener noreferrer">IP Geolocation by DB-IP</a> · <a href="https://creativecommons.org/licenses/by/4.0/" target="_blank" rel="noopener noreferrer">CC BY 4.0</a> · Lite 数据覆盖和准确度有限。</p>
      <div class="geography-tables">
        <table><caption>地域查询覆盖（请求数）</caption><thead><tr><th scope="col">结果</th><th scope="col">数量</th></tr></thead><tbody><tr v-for="row in view.counts" :key="row.status"><th scope="row">{{row.label}}</th><td>{{row.requests}}</td></tr></tbody></table>
        <table><caption>国家/地区排名（近似）</caption><thead><tr><th scope="col">国家/地区</th><th scope="col">请求数</th></tr></thead><tbody><tr v-for="row in view.countries" :key="row.countryCode"><th scope="row">{{row.country||row.countryCode}} ({{row.countryCode}})</th><td>{{row.requests}}</td></tr><tr v-if="!view.countries.length"><td colspan="2">没有可定位的请求</td></tr></tbody></table>
      </div>
      <table><caption>城市排名（近似，不是设备定位）</caption><thead><tr><th scope="col">国家/地区</th><th scope="col">区域</th><th scope="col">城市</th><th scope="col">请求数</th></tr></thead><tbody><tr v-for="row in view.cities" :key="JSON.stringify([row.countryCode,row.region,row.city])"><td>{{row.country||row.countryCode}}</td><td>{{row.region||'—'}}</td><th scope="row">{{row.city}}</th><td>{{row.requests}}</td></tr><tr><th scope="row" colspan="3">有国家记录但没有城市</th><td>{{view.cityUnknown}}</td></tr><tr><th scope="row" colspan="3">其他城市（未进入当前榜单或超出聚合预算）</th><td>{{view.cityOther}}</td></tr></tbody></table>
    </template>
  </section>
</template>
<style scoped>
.geography-report{margin:20px 0;padding:16px;border:1px solid var(--el-border-color-lighter);border-radius:8px;min-width:0}
.geography-report h4{margin:0 0 8px}.geography-report p,.geography-report caption{font-size:13px;line-height:1.6;color:var(--el-text-color-secondary);text-align:left}
.geography-tables{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));align-items:start;gap:16px;margin:16px 0}
.geography-report table{width:100%;table-layout:fixed;border-collapse:collapse;font-size:13px}.geography-report td,.geography-report th{padding:9px 6px;border-bottom:1px solid var(--el-border-color-lighter);text-align:left;overflow-wrap:anywhere}
.geography-report td{font-variant-numeric:tabular-nums}
@media(max-width:640px){.geography-tables{grid-template-columns:1fr}.geography-report{padding:12px}}
</style>
