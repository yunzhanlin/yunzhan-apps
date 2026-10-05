<script setup lang="ts">
import { computed } from "vue";
const props = defineProps<{ id: string; report: Record<string, any> }>();
const emit = defineEmits<{ select: [row: Record<string, any>] }>();
const names: Record<string, string> = {
  requests: "请求数",
  unique_ips: "独立 IP",
  bytes: "流量 / 大小",
  errors: "错误请求",
  bots: "爬虫请求",
  slow_count: "慢请求",
  average_seconds: "平均响应（秒）",
  max_seconds: "最大响应（秒）",
  qps_last_minute: "最近一分钟 QPS",
  total_bytes: "总占用",
  files: "文件数",
  scanned_php: "扫描 PHP 文件",
  pid: "PID",
  name: "名称",
  cpu_percent: "CPU %",
  memory: "内存",
  read_rate: "读取 / 秒",
  write_rate: "写入 / 秒",
  state: "状态",
  managed: "受管",
  can_terminate: "允许终止",
  start_time: "进程身份",
  path: "路径",
  line: "行号",
  rule: "风险规则",
  severity: "风险等级",
  evidence: "代码命中",
  time: "时间",
  ip: "IP",
  method: "方法",
  status: "状态码",
  seconds: "耗时（秒）",
  browser: "浏览器",
  device: "设备",
  domain: "域名",
  port: "端口",
  entry: "程序入口",
  id: "标识",
  site_id: "网站 ID",
  username: "用户名",
  role: "角色",
  site_ids: "网站范围",
  sessions: "有效会话",
  totp_enabled: "两步验证",
  source: "源 / 导出路径",
  read_only: "只读",
  address: "节点地址",
  healthy: "健康",
  weight: "权重",
  backup: "备用节点",
  kind: "变更类型",
  before: "基线摘要",
  after: "当前摘要",
  created_at: "创建时间",
  ok: "成功",
  url: "HTTPS 地址",
  total_seconds: "总响应时间",
  not_after: "到期时间",
  issuer: "签发者",
  checked_at: "检查时间",
  invalid_lines: "跳过无效日志",
  partial: "结果不完整",
  copied: "已复制",
  skipped: "未变化",
  conflicts: "目标冲突",
  restored: "已恢复",
  findings: "风险命中",
  processes: "真实进程",
  users: "账户",
  apps: "PM2 项目",
  mounts: "NFS 挂载",
  hosts: "主机",
  nodes: "上游节点",
  changes: "文件变化",
  largest_files: "最大文件",
  directories: "目录占用",
  children: "一级目录 / 文件占用",
  extensions: "扩展名占用",
  paths: "访问页面",
  status_codes: "状态码",
  hours: "小时趋势（UTC）",
  referers: "访问来源",
  browsers: "浏览器",
  devices: "设备",
  methods: "HTTP 方法",
  spiders: "爬虫",
  visitors: "访客 IP",
  error_requests: "错误请求明细",
  slow_requests: "慢请求明细",
  alerts: "网络变化",
  dns: "DNS 解析",
  http: "HTTP 入口",
  nginx: "Nginx 配置",
  tls_certificate: "TLS 证书",
  enabled: "启用",
  valid: "有效",
  output: "检查输出",
  error: "错误",
  signal: "信号",
  sites: "网站数",
  running_sites: "运行网站",
  certificates_due_14_days: "14 天内到期证书",
  failed_site_jobs: "失败网站任务",
  failed_runtime_jobs: "失败运行时任务",
  audit_events_24h: "24 小时审计事件",
};
const analytics = computed(() =>
  ["website-analytics", "website-statistics-v2"].includes(props.id),
);
const metrics = computed(() =>
  Object.entries(props.report).filter(
    ([key, value]) =>
      typeof value === "number" &&
      [
        "requests",
        "unique_ips",
        "bytes",
        "errors",
        "bots",
        "slow_count",
        "average_seconds",
        "qps_last_minute",
        "total_bytes",
        "files",
        "scanned_php",
        "sites",
        "running_sites",
        "certificates_due_14_days",
        "failed_site_jobs",
        "failed_runtime_jobs",
        "audit_events_24h",
      ].includes(key),
  ),
);
const groups = computed(() =>
  Object.entries(props.report).filter(
    ([key, value]) => Array.isArray(value) && key !== "site_ids",
  ),
);
const distributions = computed(() =>
  Object.entries(props.report).filter(
    ([key, value]) =>
      value &&
      typeof value === "object" &&
      !Array.isArray(value) &&
      Object.keys(value).length &&
      Object.values(value).every((v) => typeof v === "number") &&
      key !== "filters",
  ),
);
const info = computed(() =>
  Object.entries(props.report).filter(
    ([key, value]) =>
      value !== null &&
      value !== undefined &&
      !["scope", "site_id", "filters", "token"].includes(key) &&
      typeof value !== "object" &&
      !metrics.value.some(([k]) => k === key),
  ),
);
function format(key: string, value: unknown) {
  if (typeof value === "boolean") return value ? "是" : "否";
  if (typeof value === "number") {
    if (/bytes|memory|rate/.test(key)) {
      const units = ["B", "KiB", "MiB", "GiB", "TiB"];
      let n = value,
        i = 0;
      while (n >= 1024 && i < 4) {
        n /= 1024;
        i++;
      }
      return `${n.toFixed(i ? 2 : 0)} ${units[i]}${key.endsWith("_rate") ? "/s" : ""}`;
    }
    return Number.isInteger(value) ? String(value) : value.toFixed(3);
  }
  if (Array.isArray(value)) return value.join(", ");
  return String(value ?? "—");
}
function rows(values: any[]): Record<string, any>[] {
  return values.slice(0, 200).map((v) => {
    if (v === null || typeof v !== "object") return { path: String(v) };
    return {
      ...(v.app || v.mount || {}),
      ...Object.fromEntries(
        Object.entries(v).filter(
          ([, value]) =>
            !value || typeof value !== "object" || Array.isArray(value),
        ),
      ),
    };
  });
}
function columns(values: any[]) {
  return [...new Set(rows(values).flatMap((v) => Object.keys(v)))]
    .filter(
      (k) =>
        ![
          "password",
          "token",
          "start_time",
          "site_ids",
          "before",
          "after",
          "can_drill",
          "directory",
        ].includes(k),
    )
    .slice(0, 14);
}
function choose(row: Record<string, any>) {
  if ("can_terminate" in row && !row.can_terminate) return;
  if (props.id === "disk-analysis") {
    if (row.can_drill === false) return;
    const path = row.directory === "." ? "" : row.directory;
    emit("select", { path, drill: true });
    return;
  }
  emit("select", { ...row, resource_id: row.id, site_ids: row.site_ids });
}
function chartRows(values: any, key: string) {
  return Object.entries(values)
    .map(([name, value]) => ({ name, value }))
    .sort((a, b) =>
      key === "hours"
        ? a.name.localeCompare(b.name)
        : Number(b.value) - Number(a.value),
    )
    .slice(0, 100);
}
function directory(name: string) {
  if (name === ".") name = "";
  const base = props.report.path;
  emit("select", { path: [base, name].filter(Boolean).join("/"), drill: true });
}
</script>
<template>
  <div class="functional-report">
    <el-alert
      v-if="report.partial"
      type="warning"
      title="这是有界扫描的部分结果，不能据此认定全量数据已统计或网站没有风险。"
      :closable="false"
    />
    <p v-if="report.scope" class="report-scope">{{ report.scope }}</p>
    <div v-if="metrics.length" class="report-metrics">
      <div v-for="[key, value] in metrics" :key="key">
        <span>{{ names[key] || key }}</span
        ><strong>{{ format(key, value) }}</strong>
      </div>
    </div>
    <template v-if="report.checks">
      <section
        v-for="(value, key) in report.checks"
        :key="key"
        class="diagnosis-check"
      >
        <h4>
          {{ names[String(key)] || key }}
          <el-tag
            v-if="
              typeof value.ok === 'boolean' || typeof value.valid === 'boolean'
            "
            :type="(value.ok ?? value.valid) ? 'success' : 'danger'"
            >{{ (value.ok ?? value.valid) ? "通过" : "需处理" }}</el-tag
          >
        </h4>
        <dl>
          <template v-for="(v, k) in value" :key="k"
            ><dt>{{ names[String(k)] || k }}</dt>
            <dd>{{ format(String(k), v) }}</dd></template
          >
        </dl>
      </section>
    </template>
    <el-tabs
      v-if="analytics || distributions.length"
      class="report-distributions"
    >
      <el-tab-pane
        v-for="[key, values] in distributions"
        :key="key"
        :label="names[key] || key"
      >
        <el-table
          :data="chartRows(values, key)"
          max-height="340"
          stripe
          @row-click="
            (row: any) =>
              id === 'disk-analysis' && key === 'directories'
                ? directory(row.name)
                : undefined
          "
          ><el-table-column
            prop="name"
            :label="key === 'directories' ? '目录（点击下钻）' : '项目'"
            min-width="230"
          /><el-table-column label="数量 / 大小" width="150"
            ><template #default="{ row }">{{
              format(id === "disk-analysis" ? "bytes" : "count", row.value)
            }}</template></el-table-column
          ></el-table
        >
      </el-tab-pane>
    </el-tabs>
    <section v-for="[key, values] in groups" :key="key" class="report-group">
      <h4>
        {{ names[key] || key }}
        <small
          >{{ values.length }} 项{{
            values.length > 200 ? "，只展示前 200 项" : ""
          }}</small
        >
      </h4>
      <p v-if="!values.length">暂无记录。</p>
      <template
        v-else-if="
          key === 'sites' && typeof values[0] === 'object' && values[0].changes
        "
        ><section v-for="site in values" :key="site.site_id">
          <p>网站 {{ site.site_id }}</p>
          <AppModuleReport
            :id="id"
            :report="{ changes: site.changes, restored: site.restored || [] }"
            @select="(row) => emit('select', { ...row, site_id: site.site_id })"
          /></section
      ></template>
      <el-table
        v-else
        :data="rows(values)"
        stripe
        max-height="370"
        @row-click="choose"
      >
        <el-table-column
          v-for="column in columns(values)"
          :key="column"
          :prop="column"
          :label="names[column] || column"
          :sortable="
            [
              'cpu_percent',
              'memory',
              'read_rate',
              'write_rate',
              'bytes',
              'requests',
              'seconds',
            ].includes(column)
          "
          :min-width="
            ['path', 'evidence', 'url', 'source'].includes(column) ? 220 : 100
          "
          show-overflow-tooltip
          ><template #default="{ row }">{{
            format(column, row[column])
          }}</template></el-table-column
        >
        <el-table-column
          v-if="
            [
              'processes',
              'users',
              'apps',
              'mounts',
              'hosts',
              'changes',
              'largest_files',
              'nodes',
            ].includes(key)
          "
          label="选择操作"
          fixed="right"
          width="110"
          ><template #default="{ row }"
            ><el-button
              size="small"
              :disabled="
                (key === 'processes' && !row.can_terminate) ||
                row.can_drill === false
              "
              @click.stop="choose(row)"
              >{{
                key === "processes"
                  ? "选择终止"
                  : id === "disk-analysis"
                    ? "查看目录"
                    : "填入表单"
              }}</el-button
            ></template
          ></el-table-column
        >
      </el-table>
    </section>
    <dl v-if="info.length" class="report-info">
      <template v-for="[key, value] in info" :key="key"
        ><dt>{{ names[key] || key }}</dt>
        <dd>{{ format(key, value) }}</dd></template
      >
    </dl>
    <el-alert
      v-if="report.token"
      type="warning"
      title="只读令牌仅在生成时显示。请妥善保存，不要分享截图或报告。"
      :closable="false"
    />
    <el-input
      v-if="report.token"
      :model-value="report.token"
      type="password"
      show-password
      readonly
      aria-label="新生成的只读令牌"
    />
    <details v-if="!report.token">
      <summary>查看原始诊断数据</summary>
      <pre>{{ JSON.stringify(report, null, 2) }}</pre>
    </details>
  </div>
</template>
<style scoped>
.report-metrics {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(130px, 1fr));
  gap: 10px;
  margin: 14px 0;
}
.report-metrics > div {
  padding: 14px;
  border: 1px solid #e2e8f0;
  border-radius: 8px;
  background: #f8fafc;
}
.report-metrics span {
  display: block;
  color: #657181;
  font-size: 12px;
}
.report-metrics strong {
  display: block;
  margin-top: 6px;
  font-size: 20px;
  color: #243247;
}
.report-scope {
  font-size: 12px;
  color: #657181;
}
.report-group,
.diagnosis-check {
  margin-top: 18px;
}
.report-group small {
  font-weight: normal;
  color: #758094;
}
h4 {
  font-size: 14px;
  margin: 12px 0;
}
.report-info,
dl {
  display: grid;
  grid-template-columns: 140px 1fr;
  gap: 6px;
  font-size: 12px;
}
dt {
  color: #657181;
}
dd {
  margin: 0;
  white-space: pre-wrap;
  overflow-wrap: anywhere;
  max-height: 220px;
  overflow: auto;
}
details {
  margin-top: 20px;
  color: #657181;
  font-size: 12px;
}
pre {
  max-height: 300px;
  overflow: auto;
  white-space: pre-wrap;
  overflow-wrap: anywhere;
  background: #f5f7fa;
  padding: 12px;
}
.functional-report {
  min-width: 0;
}
.report-distributions {
  max-width: 100%;
}
@media (max-width: 600px) {
  .report-info,
  dl {
    grid-template-columns: 1fr;
  }
  .report-metrics {
    grid-template-columns: 1fr 1fr;
  }
}
</style>
