<script setup lang="ts">
import { computed } from "vue";
const props = defineProps<{report: Record<string, any>}>();
const states: Record<string,string> = {"not-prepared":"未准备原生引擎","not-configured":"尚未配置采集接口","not-running":"采集已停止",observing:"被动采集计数正常",unknown:"尚无新鲜完整计数",stale:"计数已过期","capture-drops":"检测到内核丢包","capture-checksum-errors":"检测到校验处理异常","capture-incomplete":"检测到重组缺口或内存丢弃","alert-overflow":"告警队列溢出","output-incomplete":"日志结果不完整","runtime-error":"原生程序来源异常","configuration-error":"配置或单元身份异常","rules-error":"规则完整性异常","account-error":"采集账户异常","process-error":"采集进程异常","output-error":"日志读取异常","preparation-error":"原生准备核对失败"};
states["history-error"] = "历史归档核对失败";
states["engine-unsupported"] = "引擎维护状态不符合要求";
states["runtime-upgrade-pending"] = "引擎迁移中断，等待核对恢复";
const label=computed(()=>states[String(props.report.capture_state)] || "未知采集状态");
const safe=computed(()=>props.report.capture_state==="observing" && props.report.process_verified===true && props.report.engine_support?.supported===true && props.report.preparation_required!==true);
const events=computed(()=>props.report.events || {});
const stats=computed(()=>events.value.capture_stats || {});
const retention=computed(()=>props.report.retention);
const counters:Record<string,string>={kernel_packets:"内核收包",kernel_drops:"内核丢包",decoded_packets:"解码包数",invalid_tcp_checksums:"TCP 校验异常",reassembly_gaps:"重组缺口",stream_memcap_drops:"流内存丢弃",alert_queue_overflow:"告警溢出"};
function count(value:unknown){return typeof value==="string" && /^\d+$/.test(value) ? value : "未知";}
</script>
<template>
  <section aria-label="真实被动 IDS 采集结果" class="ids-report">
    <div class="ids-heading"><h3>{{ label }}</h3><el-tag :type="safe ? 'success' : 'warning'">{{safe ? '进程与新鲜计数已核对' : '未宣称采集正常'}}</el-tag></div>
    <el-alert v-if="report.error" :title="String(report.error)" type="error" :closable="false" />
    <el-alert v-if="report.preparation_required" :title="String(report.preparation_error || '受管单元仍使用旧代次；请先显式停止并关闭开机采集，再重新准备原生组件。报表未自动迁移、停止或启动。')" type="warning" :closable="false" />
    <p class="ids-scope">原生包版本：{{report.engine_support?.package_version || '未核对'}} · 安全版本下限：{{report.engine_support?.minimum_engine_version || '未知'}} · 维护审核期限：{{report.engine_support?.review_deadline || '未知'}}。来源验签、进程核对与版本下限是不同检查，不代表没有漏洞或已取得安全认证。</p>
    <el-alert v-if="events.partial" title="这是有界或不完整日志结果，不能据此认定没有威胁。" type="warning" :closable="false" />
    <p class="ids-scope">被动检测，不自动封禁，不解密 HTTPS；实际规则来源、版本和许可见规则配置，不等同于完整商业威胁情报库。日志只保留告警元数据与数值计数，不记录 Cookie、凭据、请求正文或原始数据包。</p>
    <el-alert v-if="report.capture_state==='history-error'" title="历史归档未核对完整；没有将未知或缺失记录当作零告警。" type="error" :closable="false" />
    <p v-if="retention" class="ids-scope">已核对归档 {{retention.archives}} 份 · {{retention.archive_bytes}} 字节 · 最多 {{retention.archive_limit}} 份 / 每份 {{retention.archive_byte_limit}} 字节 · 每次合计最多扫描 {{retention.record_limit}} 条。仅退役完整身份和摘要匹配的最旧归档，保留最近 {{retention.retired_digests}} 份退役摘要。{{retention.pending ? '轮转尚待恢复；查询不完整。' : '这是有界历史窗口，不是永久审计存储。'}}</p>
    <p v-else class="ids-scope">历史归档状态尚未核对；未将未知状态显示为零。</p>
    <dl class="ids-config"><dt>已核对原生程序</dt><dd>{{report.runtime_ready ? '是' : '否'}}</dd><dt>进程身份已核对</dt><dd>{{report.process_verified ? '是' : '否'}}</dd><dt>采集接口</dt><dd>{{report.configuration?.interface || '未配置'}}</dd><dt>本机网段</dt><dd>{{(report.configuration?.home_networks || []).join(', ') || '未配置'}}</dd><dt>配置修订</dt><dd>{{report.configuration?.revision ?? '未配置'}}</dd><dt>真实启动时间</dt><dd>{{report.started_at || '未知 / 未运行'}}</dd><dt>开机启动</dt><dd>{{report.boot_enabled === true ? '已启用' : report.boot_enabled === false ? '未启用' : '未知'}}</dd><dt>统计时间</dt><dd>{{stats.timestamp || '未知'}}</dd></dl>
    <div class="ids-counters"><article v-for="(name,key) in counters" :key="key"><span>{{name}}</span><strong>{{count(stats[key])}}</strong></article></div>
    <p>匹配告警 {{events.matching_alerts ?? '未知'}} · 已扫描记录 {{events.scanned_records ?? '未知'}} · 无效记录 {{events.invalid_records ?? '未知'}} · 每次读取与展示有固定上限</p>
    <el-table :data="events.alerts || []" border max-height="480" empty-text="当前查询窗口未返回告警；不代表没有风险">
      <el-table-column prop="timestamp" label="时间（UTC）" min-width="205" />
      <el-table-column prop="severity" label="等级" width="65" />
      <el-table-column prop="signature_id" label="规则 ID" min-width="100" />
      <el-table-column prop="signature" label="检测指标" min-width="260" />
      <el-table-column prop="category" label="类别" min-width="130" />
      <el-table-column prop="source_ip" label="源 IP" min-width="140" />
      <el-table-column prop="source_port" label="源端口" width="85" />
      <el-table-column prop="destination_ip" label="目标 IP" min-width="140" />
      <el-table-column prop="destination_port" label="目标端口" width="85" />
      <el-table-column prop="protocol" label="协议" width="80" />
      <el-table-column label="事件动作" min-width="110"><template #default="{row}">{{row.action === 'allowed' ? '记录 / 未阻断' : row.action}}</template></el-table-column>
    </el-table>
    <p v-if="events.page_limited" class="ids-scope">本页仅显示部分匹配告警；可修改分页起点继续查询。</p>
  </section>
</template>
<style scoped>
.ids-report{display:grid;gap:14px;min-width:0}.ids-heading{display:flex;align-items:center;gap:12px;flex-wrap:wrap}.ids-heading h3{margin:0}.ids-scope{color:#62718b;line-height:1.65;overflow-wrap:anywhere}.ids-config{display:grid;grid-template-columns:150px minmax(0,1fr);gap:10px;margin:0}.ids-config dt{color:#62718b}.ids-config dd{margin:0;overflow-wrap:anywhere}.ids-counters{display:grid;grid-template-columns:repeat(auto-fit,minmax(135px,1fr));gap:12px}.ids-counters article{padding:14px;background:#f6f8fb;border-radius:8px;display:grid;gap:8px}.ids-counters span{color:#62718b}.ids-counters strong{overflow-wrap:anywhere}@media(max-width:600px){.ids-config{grid-template-columns:1fr}.ids-config dd{margin-bottom:8px}}
</style>
