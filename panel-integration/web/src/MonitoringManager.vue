<script setup lang="ts">
import { formatPanelDateTime } from "./panelTime";
import { computed, onMounted, onUnmounted, ref } from "vue";
import { ElMessage } from "element-plus";
import { Box, Coin, Connection, Cpu, DataLine, RefreshRight } from "@element-plus/icons-vue";
interface Point {
  sampled_at: number;
  samples: number;
  failures: number;
  cpu_percent: number | null;
  memory_percent: number | null;
  disk_percent: number | null;
  disk_read_rate: number | null;
  disk_write_rate: number | null;
  network_rx_rate: number | null;
  network_tx_rate: number | null;
  load_1: number | null;
}
interface Settings {
  retention_days: number;
  cpu_threshold: number;
  memory_threshold: number;
  disk_threshold: number;
  trigger_seconds: number;
  recovery_seconds: number;
  revision: number;
  updated_at: string;
}
interface Alert {
  id: string;
  metric: string;
  state: string;
  started_at: number;
  last_observed_at: number;
  resolved_at?: number;
  peak: number;
  threshold: number;
  acknowledged_at?: number;
}
interface Event {
  id: number;
  alert_id: string;
  kind: string;
  value: number;
  created_at: number;
}
interface ServiceStatus {
  kind: string;
  resource_id: string;
  label: string;
  expected_state: "active" | "inactive";
  actual_state: "active" | "inactive" | "failed" | "unknown";
  detail: string;
  checked_at: number;
}
interface MonitorProcess {
  pid: number;
  name: string;
  cpu_percent: number;
  memory: number;
  read_rate: number;
  write_rate: number;
  state: string;
}
const props = defineProps<{
  api: <T>(path: string, method?: string, body?: unknown) => Promise<T>;
}>();
const points = ref<Point[]>([]),
  settings = ref<Settings>(),
  draft = ref<Settings>(),
  alerts = ref<Alert[]>([]),
  events = ref<Event[]>([]),
  services = ref<ServiceStatus[]>([]),
  processes = ref<MonitorProcess[]>([]),
  processListOpen = ref(false),
  processDetailOpen = ref(false),
  processDetail = ref<MonitorProcess | null>(null),
  processDetailAt = ref(0),
  processDetailStale = ref(false),
  tcpConnections = ref<number | null>(null),
  processSort = ref<"cpu" | "memory" | "disk">("cpu"),
  hoverIndex = ref<number | null>(null),
  hoverChart = ref<"cpu" | "memory" | "disk" | "network" | null>(null),
  range = ref("1h"),
  error = ref(""),
  busy = ref(false),
  settingsOpen = ref(false);
const primaryRanges = [["1h", "1小时"], ["24h", "24小时"], ["7d", "7天"]];
const extraRanges = [["6h", "6小时"], ["30d", "30天"]];
const metricNames: Record<string, string> = {
  cpu: "CPU 使用率",
  memory: "内存使用率",
  disk: "数据盘使用率",
  collector: "指标采集服务",
};
const eventNames: Record<string, string> = {
  triggered: "触发告警",
  resolved: "恢复正常",
  acknowledged: "管理员已确认",
};
const activeAlerts = computed(() =>
  alerts.value.filter((v) => v.state === "active"),
);
const serviceProblems = computed(() =>
  services.value.filter(
    (v) => v.actual_state === "unknown" || v.actual_state !== v.expected_state,
  ),
);
const serviceGroups = computed(() =>
  ["nginx", "php", "mysql"].map((kind) => ({
    kind,
    label: { nginx: "Nginx", php: "PHP-FPM", mysql: "MySQL" }[kind],
    items: services.value.filter((v) => v.kind === kind),
  })),
);
const latest = computed(() =>
  [...points.value].reverse().find((v) => v.samples > v.failures),
);
const hoverPoint = computed(() => hoverIndex.value == null ? null : points.value[hoverIndex.value] || null);
const hoverX = computed(() => {
  if (!hoverPoint.value || points.value.length < 2) return 0;
  return 760 * (hoverPoint.value.sampled_at - points.value[0].sampled_at) / Math.max(1, points.value.at(-1)!.sampled_at - points.value[0].sampled_at);
});
const hoverStyle = computed(() => ({ left: `${Math.min(77, Math.max(18, hoverX.value / 760 * 100))}%` }));
function chartHover(event: PointerEvent, chart: "cpu" | "memory" | "disk" | "network") {
  if (points.value.length < 2) return;
  hoverChart.value = chart;
  const target = event.currentTarget as SVGElement;
  const rect = target.getBoundingClientRect();
  const fraction = Math.max(0, Math.min(1, (event.clientX - rect.left) / rect.width));
  const start = points.value[0].sampled_at;
  const targetTime = start + fraction * (points.value.at(-1)!.sampled_at - start);
  hoverIndex.value = points.value.reduce((best, point, index) =>
    Math.abs(point.sampled_at - targetTime) < Math.abs(points.value[best].sampled_at - targetTime) ? index : best, 0);
}
function axisTime(index: number) {
  if (points.value.length < 2) return "";
  const start = points.value[0].sampled_at;
  const seconds = start + (points.value.at(-1)!.sampled_at - start) * index / 5;
  return formatPanelDateTime(seconds * 1000, range.value === "1h" || range.value === "6h" || range.value === "24h"
    ? { hour: "2-digit", minute: "2-digit", hour12: false }
    : { month: "2-digit", day: "2-digit", hour12: false });
}
const failureCount = computed(() =>
  points.value.reduce((n, v) => n + v.failures, 0),
);
const rankedProcesses = computed(() => processes.value.slice().sort((a, b) =>
  processSort.value === "memory" ? b.memory - a.memory :
    processSort.value === "disk" ? b.read_rate + b.write_rate - a.read_rate - a.write_rate : b.cpu_percent - a.cpu_percent,
));
const sortedProcesses = computed(() => rankedProcesses.value.slice(0, 5));
const memorySize = (value: number) => value >= 1073741824 ? (value / 1073741824).toFixed(1) + " GiB" : value >= 1048576 ? (value / 1048576).toFixed(1) + " MiB" : value >= 1024 ? (value / 1024).toFixed(1) + " KiB" : value + " B";
const processState = (value: string) => value === "R" ? "运行中" : value === "S" || value === "I" ? "休眠" : value === "D" ? "等待 IO" : value === "Z" ? "僵尸" : value;
function showProcess(process: MonitorProcess) {
  processListOpen.value = false;
  processDetail.value = { ...process };
  processDetailAt.value = Date.now();
  processDetailStale.value = false;
  processDetailOpen.value = true;
}
function setProcessSort(value: string) {
  if (value === "cpu" || value === "memory" || value === "disk") processSort.value = value;
}
const bytes = (v: number | null | undefined) => {
  const n = v || 0;
  return n >= 1048576
    ? (n / 1048576).toFixed(1) + " MiB/s"
    : n >= 1024
      ? (n / 1024).toFixed(1) + " KiB/s"
      : n.toFixed(0) + " B/s";
};
const percent = (v: number | null | undefined) =>
  v == null ? "—" : Math.max(0, Math.min(100, v)).toFixed(1) + "%";
const serviceState = (value: string) =>
  ({ active: "运行中", inactive: "已停止", failed: "失败", unknown: "未知" })[
    value
  ] || value;
function metricName(metric: string) {
  if (!metric.startsWith("service:")) return metricNames[metric] || metric;
  const service = services.value.find(
    (v) => `service:${v.kind}:${v.resource_id}` === metric,
  );
  return service ? `${service.label} 状态` : "受管服务状态";
}
const percentMetric = (metric: string) =>
  ["cpu", "memory", "disk"].includes(metric);
const date = (seconds: number) =>
  formatPanelDateTime(seconds * 1000, {
    month: "2-digit",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
    hour12: false,
  });
function paths(field: keyof Point, scale: number) {
  if (points.value.length < 2) return [];
  const first = points.value[0].sampled_at,
    last = points.value.at(-1)!.sampled_at,
    span = Math.max(1, last - first),
    lines: string[] = [];
  let current: string[] = [],
    previous = 0;
  for (const point of points.value) {
    const value = point[field] as number | null;
    const gap =
      previous && point.sampled_at - previous > Math.max(45, span / 100);
    if (value == null || point.failures === point.samples || gap) {
      if (current.length > 1) lines.push(current.join(" "));
      current = [];
    }
    if (value != null && point.failures < point.samples) {
      current.push(
        `${((point.sampled_at - first) / span) * 760},${190 - Math.min(scale, Math.max(0, value)) * (160 / scale)}`,
      );
    }
    previous = point.sampled_at;
  }
  if (current.length > 1) lines.push(current.join(" "));
  return lines;
}
function areas(field: keyof Point, scale: number) {
  return paths(field, scale).map((line) => {
    const coords = line.split(" ");
    const firstX = coords[0].split(",")[0];
    const lastX = coords.at(-1)!.split(",")[0];
    return `M ${firstX},190 L ${coords.join(" L ")} L ${lastX},190 Z`;
  });
}
const networkScale = computed(() =>
  Math.max(
    1024,
    ...points.value.flatMap((v) => [
      v.network_rx_rate || 0,
      v.network_tx_rate || 0,
    ]),
  ),
);
const diskIOScale = computed(() => Math.max(1024, ...points.value.flatMap((point) => [point.disk_read_rate || 0, point.disk_write_rate || 0])));
function sparkline(field: "cpu_percent" | "memory_percent" | "disk_percent" | "load_1", scale: number) {
  const recent = points.value.filter((point) => point[field] !== null).slice(-24);
  if (recent.length < 2) return "";
  return recent.map((point, index) => `${index * 100 / (recent.length - 1)},${29 - Math.min(scale, Math.max(0, point[field] || 0)) * 26 / scale}`).join(" ");
}
async function refresh() {
  try {
    const [history, alertData, serviceData, processData] = await Promise.all([
      props.api<{ points: Point[]; settings: Settings }>(
        `/monitor/history?range=${range.value}`,
      ),
      props.api<{ alerts: Alert[]; events: Event[] }>("/monitor/alerts"),
      props.api<{ services: ServiceStatus[] }>("/monitor/services"),
      props.api<{ processes: MonitorProcess[]; tcp_connections: number | null }>("/monitor/processes"),
    ]);
    points.value = history.points;
    settings.value = history.settings;
    alerts.value = alertData.alerts;
    events.value = alertData.events;
    services.value = serviceData.services;
    processes.value = processData.processes;
    if (processDetailOpen.value && processDetail.value) {
      const current = processData.processes.find(item => item.pid === processDetail.value?.pid && item.name === processDetail.value?.name);
      processDetailStale.value = !current;
      if (current) {
        processDetail.value = { ...current };
        processDetailAt.value = Date.now();
      }
    }
    tcpConnections.value = processData.tcp_connections;
    error.value = "";
  } catch (e) {
    error.value = (e as Error).message;
  }
}
function editSettings() {
  draft.value = settings.value ? { ...settings.value } : undefined;
  settingsOpen.value = true;
}
function chooseRange(value: string) {
  range.value = value;
  void refresh();
}
async function saveSettings() {
  if (!draft.value || busy.value) return;
  busy.value = true;
  try {
    settings.value = await props.api<Settings>(
      "/monitor/settings",
      "PUT",
      draft.value,
    );
    settingsOpen.value = false;
    await refresh();
    ElMessage.success("监控阈值和保留周期已保存");
  } catch (e) {
    ElMessage.error((e as Error).message);
  } finally {
    busy.value = false;
  }
}
async function acknowledge(alert: Alert) {
  try {
    await props.api(`/monitor/alerts/${alert.id}/acknowledge`, "POST", {});
    await refresh();
  } catch (e) {
    ElMessage.error((e as Error).message);
  }
}
let timer: ReturnType<typeof setInterval>;
onMounted(() => {
  refresh();
  timer = setInterval(refresh, 30000);
});
onUnmounted(() => clearInterval(timer));
defineExpose({ refresh });
</script>

<template>
  <div class="monitor-page">
    <el-alert
      v-if="error"
      :title="error"
      type="error"
      :closable="false"
      show-icon
    />
    <section class="panel-card monitor-toolbar">
      <div>
        <h2>资源历史</h2>
        <p>
          后台每 15 秒采集，关闭浏览器后仍持续记录；折线断开表示没有可信样本。
        </p>
      </div>
      <div class="monitor-actions">
        <div class="monitor-range-tabs" role="group" aria-label="历史范围">
          <button v-for="item in primaryRanges" :key="item[0]" type="button"
            :class="{ active: range === item[0] }" :aria-pressed="range === item[0]"
            @click="chooseRange(item[0])">{{ item[1] }}</button>
        </div>
        <el-dropdown trigger="click" @command="chooseRange">
          <button type="button" class="monitor-more-range" aria-label="更多历史范围">{{ extraRanges.find(item => item[0] === range)?.[1] || "更多范围" }}⌄</button>
          <template #dropdown><el-dropdown-menu>
            <el-dropdown-item v-for="item in extraRanges" :key="item[0]" :command="item[0]">{{ item[1] }}</el-dropdown-item>
          </el-dropdown-menu></template>
        </el-dropdown>
        <span class="monitor-auto-refresh"><el-icon><RefreshRight /></el-icon> 自动刷新：30 秒</span>
      </div>
    </section>
    <div class="monitor-summary">
      <article class="panel-card">
        <span class="monitor-summary-icon green"
          ><el-icon><Cpu /></el-icon
        ></span>
        <div>
          <small>CPU 使用率</small
          ><strong>{{ percent(latest?.cpu_percent) }}</strong
          ><span>持续阈值 {{ settings?.cpu_threshold || 80 }}%</span>
        </div>
        <svg class="monitor-sparkline" viewBox="0 0 100 31" preserveAspectRatio="none" aria-hidden="true"><polyline :points="sparkline('cpu_percent', 100)" fill="none" stroke="#08a856" stroke-width="1.3" vector-effect="non-scaling-stroke"/></svg>
      </article>
      <article class="panel-card">
        <span class="monitor-summary-icon blue"
          ><el-icon><Coin /></el-icon
        ></span>
        <div>
          <small>内存使用率</small
          ><strong>{{ percent(latest?.memory_percent) }}</strong
          ><span>持续阈值 {{ settings?.memory_threshold || 85 }}%</span>
        </div>
        <svg class="monitor-sparkline" viewBox="0 0 100 31" preserveAspectRatio="none" aria-hidden="true"><polyline :points="sparkline('memory_percent', 100)" fill="none" stroke="#1975e8" stroke-width="1.3" vector-effect="non-scaling-stroke"/></svg>
      </article>
      <article class="panel-card">
        <span class="monitor-summary-icon purple"
          ><el-icon><Box /></el-icon
        ></span>
        <div>
          <small>磁盘使用率</small
          ><strong>{{ percent(latest?.disk_percent) }}</strong
          ><span>持续阈值 {{ settings?.disk_threshold || 90 }}%</span>
        </div>
        <svg class="monitor-sparkline" viewBox="0 0 100 31" preserveAspectRatio="none" aria-hidden="true"><polyline :points="sparkline('disk_percent', 100)" fill="none" stroke="#823de2" stroke-width="1.3" vector-effect="non-scaling-stroke"/></svg>
      </article>
      <article class="panel-card">
        <span class="monitor-summary-icon orange"
          ><el-icon><DataLine /></el-icon
        ></span>
        <div>
          <small>系统负载</small
          ><strong>{{ latest?.load_1?.toFixed(2) || "—" }}</strong
          ><span>1 分钟平均负载</span>
        </div>
        <svg class="monitor-sparkline" viewBox="0 0 100 31" preserveAspectRatio="none" aria-hidden="true"><polyline :points="sparkline('load_1', 4)" fill="none" stroke="#f16a24" stroke-width="1.3" vector-effect="non-scaling-stroke"/></svg>
      </article>
      <article class="panel-card">
        <span class="monitor-summary-icon green"
          ><el-icon><Connection /></el-icon
        ></span>
        <div>
          <small>在线连接数</small
          ><strong>{{ tcpConnections ?? "—" }}</strong
          ><span>TCP 已建立连接</span>
        </div>
      </article>
    </div>
    <section class="panel-card monitor-chart-card cpu-chart-card">
      <div class="chart-heading">
        <div>
          <h2>CPU 使用率</h2>
          <p>单位：%，缺失或重启边界不会补零。</p>
        </div>
        <div class="legend">
          <span class="cpu">总使用率</span>
        </div>
      </div>
      <div v-if="points.length < 2" class="chart-empty">
        正在积累后台样本，请稍后查看。
      </div>
      <svg
        v-else
        viewBox="0 0 760 210"
        preserveAspectRatio="none"
        aria-label="CPU 使用率历史折线"
        @pointermove="chartHover($event, 'cpu')"
        @pointerleave="hoverIndex = null; hoverChart = null"
      >
        <defs><linearGradient id="monitor-cpu-fill" x1="0" y1="0" x2="0" y2="1"><stop offset="0%" stop-color="#08a856" stop-opacity=".22"/><stop offset="100%" stop-color="#08a856" stop-opacity=".02"/></linearGradient></defs>
        <line v-for="x in [0, 152, 304, 456, 608, 760]" :key="'cx' + x" :x1="x" y1="30" :x2="x" y2="190" stroke="#e6edf4" />
        <line
          v-for="y in [30, 110, 190]"
          :key="y"
          x1="0"
          :y1="y"
          x2="760"
          :y2="y"
          stroke="#e8eeeb"
          stroke-dasharray="4 4"
        />
        <path v-for="(area, i) in areas('cpu_percent', 100)" :key="'ca' + i" :d="area" fill="url(#monitor-cpu-fill)" />
        <line v-if="hoverChart === 'cpu' && hoverPoint" :x1="hoverX" y1="30" :x2="hoverX" y2="190" stroke="#9aacc2" stroke-dasharray="3 3" />
        <polyline
          v-for="(line, i) in paths('cpu_percent', 100)"
          :key="'c' + i"
          :points="line"
          class="line cpu-line"
        />
      </svg>
      <div v-if="hoverChart === 'cpu' && hoverPoint" class="monitor-chart-tooltip" :style="hoverStyle"><b>{{ date(hoverPoint.sampled_at) }}</b><span>CPU：{{ percent(hoverPoint.cpu_percent) }}</span></div>
      <div v-if="points.length" class="chart-axis"><span v-for="index in 6" :key="index">{{ axisTime(index - 1) }}</span></div>
    </section>
    <section class="panel-card monitor-chart-card memory-chart-card">
      <div class="chart-heading">
        <div>
          <h2>内存使用趋势</h2>
          <p>单位：%，展示真实后台采样。</p>
        </div>
        <div class="legend"><span class="memory">已使用</span></div>
      </div>
      <div v-if="points.length < 2" class="chart-empty">
        正在积累后台样本，请稍后查看。
      </div>
      <svg
        v-else
        viewBox="0 0 760 210"
        preserveAspectRatio="none"
        aria-label="内存使用率历史折线"
        @pointermove="chartHover($event, 'memory')"
        @pointerleave="hoverIndex = null; hoverChart = null"
      >
        <defs><linearGradient id="monitor-memory-fill" x1="0" y1="0" x2="0" y2="1"><stop offset="0%" stop-color="#08a856" stop-opacity=".22"/><stop offset="100%" stop-color="#08a856" stop-opacity=".02"/></linearGradient></defs>
        <line v-for="x in [0, 152, 304, 456, 608, 760]" :key="'mx' + x" :x1="x" y1="30" :x2="x" y2="190" stroke="#e6edf4" />
        <line
          v-for="y in [30, 110, 190]"
          :key="y"
          x1="0"
          :y1="y"
          x2="760"
          :y2="y"
          stroke="#e8eeeb"
          stroke-dasharray="4 4"
        />
        <path v-for="(area, i) in areas('memory_percent', 100)" :key="'ma' + i" :d="area" fill="url(#monitor-memory-fill)" />
        <line v-if="hoverChart === 'memory' && hoverPoint" :x1="hoverX" y1="30" :x2="hoverX" y2="190" stroke="#9aacc2" stroke-dasharray="3 3" />
        <polyline
          v-for="(line, i) in paths('memory_percent', 100)"
          :key="'m' + i"
          :points="line"
          class="line memory-line"
        />
      </svg>
      <div v-if="hoverChart === 'memory' && hoverPoint" class="monitor-chart-tooltip" :style="hoverStyle"><b>{{ date(hoverPoint.sampled_at) }}</b><span>已使用：{{ percent(hoverPoint.memory_percent) }}</span></div>
      <div v-if="points.length" class="chart-axis"><span v-for="index in 6" :key="index">{{ axisTime(index - 1) }}</span></div>
    </section>
    <section class="panel-card monitor-chart-card disk-chart-card">
      <div class="chart-heading">
        <div>
          <h2>磁盘 IO</h2>
          <p>单位：MB/s，块设备读取与写入速率。</p>
        </div>
        <div class="legend"><span class="disk-read">读取 {{ bytes(latest?.disk_read_rate) }}</span><span class="disk-write">写入 {{ bytes(latest?.disk_write_rate) }}</span></div>
      </div>
      <div v-if="points.length < 2" class="chart-empty">
        正在积累后台样本，请稍后查看。
      </div>
      <svg
        v-else
        viewBox="0 0 760 210"
        preserveAspectRatio="none"
        aria-label="磁盘读取和写入速率历史折线"
        @pointermove="chartHover($event, 'disk')"
        @pointerleave="hoverIndex = null; hoverChart = null"
      >
        <defs><linearGradient id="monitor-disk-read-fill" x1="0" y1="0" x2="0" y2="1"><stop offset="0%" stop-color="#08a856" stop-opacity=".18"/><stop offset="100%" stop-color="#08a856" stop-opacity=".01"/></linearGradient><linearGradient id="monitor-disk-write-fill" x1="0" y1="0" x2="0" y2="1"><stop offset="0%" stop-color="#1975e8" stop-opacity=".18"/><stop offset="100%" stop-color="#1975e8" stop-opacity=".01"/></linearGradient></defs>
        <line v-for="x in [0, 152, 304, 456, 608, 760]" :key="'dx' + x" :x1="x" y1="30" :x2="x" y2="190" stroke="#e6edf4" />
        <line
          v-for="y in [30, 110, 190]"
          :key="y"
          x1="0"
          :y1="y"
          x2="760"
          :y2="y"
          stroke="#e8eeeb"
          stroke-dasharray="4 4"
        />
        <path v-for="(area, i) in areas('disk_read_rate', diskIOScale)" :key="'dra' + i" :d="area" fill="url(#monitor-disk-read-fill)" />
        <path v-for="(area, i) in areas('disk_write_rate', diskIOScale)" :key="'dwa' + i" :d="area" fill="url(#monitor-disk-write-fill)" />
        <line v-if="hoverChart === 'disk' && hoverPoint" :x1="hoverX" y1="30" :x2="hoverX" y2="190" stroke="#9aacc2" stroke-dasharray="3 3" />
        <polyline
          v-for="(line, i) in paths('disk_read_rate', diskIOScale)"
          :key="'dr' + i"
          :points="line"
          class="line disk-read-line"
        />
        <polyline
          v-for="(line, i) in paths('disk_write_rate', diskIOScale)"
          :key="'dw' + i"
          :points="line"
          class="line disk-write-line"
        />
      </svg>
      <div v-if="hoverChart === 'disk' && hoverPoint" class="monitor-chart-tooltip" :style="hoverStyle"><b>{{ date(hoverPoint.sampled_at) }}</b><span>读取：{{ bytes(hoverPoint.disk_read_rate) }}</span><span>写入：{{ bytes(hoverPoint.disk_write_rate) }}</span></div>
      <div v-if="points.length" class="chart-axis"><span v-for="index in 6" :key="index">{{ axisTime(index - 1) }}</span></div>
    </section>
    <section class="panel-card monitor-chart-card network-chart-card">
      <div class="chart-heading">
        <div>
          <h2>网络速率</h2>
          <p>由 Linux 累计字节与真实采样间隔计算。</p>
        </div>
        <div class="legend">
          <span class="rx">接收 {{ bytes(latest?.network_rx_rate) }}</span
          ><span class="tx">发送 {{ bytes(latest?.network_tx_rate) }}</span>
        </div>
      </div>
      <div v-if="points.length < 2" class="chart-empty">
        第一个样本不计算速率。
      </div>
      <svg
        v-else
        viewBox="0 0 760 210"
        preserveAspectRatio="none"
        aria-label="网络接收和发送速率历史折线"
        @pointermove="chartHover($event, 'network')"
        @pointerleave="hoverIndex = null; hoverChart = null"
      >
        <defs><linearGradient id="monitor-network-rx-fill" x1="0" y1="0" x2="0" y2="1"><stop offset="0%" stop-color="#08a856" stop-opacity=".18"/><stop offset="100%" stop-color="#08a856" stop-opacity=".01"/></linearGradient><linearGradient id="monitor-network-tx-fill" x1="0" y1="0" x2="0" y2="1"><stop offset="0%" stop-color="#1975e8" stop-opacity=".18"/><stop offset="100%" stop-color="#1975e8" stop-opacity=".01"/></linearGradient></defs>
        <line v-for="x in [0, 152, 304, 456, 608, 760]" :key="'nx' + x" :x1="x" y1="30" :x2="x" y2="190" stroke="#e6edf4" />
        <line
          v-for="y in [30, 110, 190]"
          :key="y"
          x1="0"
          :y1="y"
          x2="760"
          :y2="y"
          stroke="#e8eeeb"
          stroke-dasharray="4 4"
        />
        <path v-for="(area, i) in areas('network_rx_rate', networkScale)" :key="'nra' + i" :d="area" fill="url(#monitor-network-rx-fill)" />
        <path v-for="(area, i) in areas('network_tx_rate', networkScale)" :key="'nta' + i" :d="area" fill="url(#monitor-network-tx-fill)" />
        <line v-if="hoverChart === 'network' && hoverPoint" :x1="hoverX" y1="30" :x2="hoverX" y2="190" stroke="#9aacc2" stroke-dasharray="3 3" />
        <polyline
          v-for="(line, i) in paths('network_rx_rate', networkScale)"
          :key="'r' + i"
          :points="line"
          class="line rx-line"
        />
        <polyline
          v-for="(line, i) in paths('network_tx_rate', networkScale)"
          :key="'t' + i"
          :points="line"
          class="line tx-line"
        />
      </svg>
      <div v-if="hoverChart === 'network' && hoverPoint" class="monitor-chart-tooltip" :style="hoverStyle"><b>{{ date(hoverPoint.sampled_at) }}</b><span>接收：{{ bytes(hoverPoint.network_rx_rate) }}</span><span>发送：{{ bytes(hoverPoint.network_tx_rate) }}</span></div>
      <div v-if="points.length" class="chart-axis"><span v-for="index in 6" :key="index">{{ axisTime(index - 1) }}</span></div>
    </section>
    <section class="panel-card monitor-threshold-card">
      <div class="chart-heading"><div><h2>告警阈值</h2></div><button class="monitor-text-button" @click="editSettings">设置 ›</button></div>
      <div class="monitor-threshold-list">
        <div><span>CPU 使用率</span><b>&gt; {{ settings?.cpu_threshold || 80 }}%</b><em :class="activeAlerts.some((a) => a.metric === 'cpu') ? 'alarm' : ''">{{ activeAlerts.some((a) => a.metric === 'cpu') ? '告警' : '正常' }}</em></div>
        <div><span>内存使用率</span><b>&gt; {{ settings?.memory_threshold || 85 }}%</b><em :class="activeAlerts.some((a) => a.metric === 'memory') ? 'alarm' : ''">{{ activeAlerts.some((a) => a.metric === 'memory') ? '告警' : '正常' }}</em></div>
        <div><span>磁盘使用率</span><b>&gt; {{ settings?.disk_threshold || 90 }}%</b><em :class="activeAlerts.some((a) => a.metric === 'disk') ? 'alarm' : ''">{{ activeAlerts.some((a) => a.metric === 'disk') ? '告警' : '正常' }}</em></div>
        <div><span>受管服务</span><b>期望状态</b><em :class="serviceProblems.length ? 'alarm' : ''">{{ serviceProblems.length ? `${serviceProblems.length} 项异常` : '正常' }}</em></div>
        <div><span>指标采集</span><b>15 秒/次</b><em :class="failureCount ? 'alarm' : ''">{{ failureCount ? `${failureCount} 次异常` : '正常' }}</em></div>
      </div>
    </section>
    <section class="panel-card monitor-process-card">
      <div class="monitor-process-heading"><h2>进程排行</h2><div><button v-for="item in [{ id: 'cpu', label: '按 CPU' }, { id: 'memory', label: '按内存' }, { id: 'disk', label: '按磁盘' }]" :key="item.id" :class="{ active: processSort === item.id }" @click="setProcessSort(item.id)">{{ item.label }}</button><button class="monitor-text-button" @click="processListOpen = true">查看更多 ›</button></div></div>
      <table class="monitor-process-table"><thead><tr><th>#</th><th>进程名</th><th>PID</th><th>CPU 使用率</th><th>内存使用</th><th>读取/写入</th><th>状态</th><th>操作</th></tr></thead><tbody><tr v-for="(process, index) in sortedProcesses" :key="process.pid"><td>{{ index + 1 }}</td><td>{{ process.name }}</td><td>{{ process.pid }}</td><td><span class="monitor-cpu-bar"><i :style="{ width: `${Math.min(100, process.cpu_percent)}%` }"></i></span>{{ process.cpu_percent.toFixed(1) }}%</td><td>{{ memorySize(process.memory) }}</td><td>{{ bytes(process.read_rate) }} / {{ bytes(process.write_rate) }}</td><td>{{ processState(process.state) }}</td><td><button @click="showProcess(process)">查看</button></td></tr><tr v-if="!sortedProcesses.length"><td colspan="8" class="monitor-process-empty">正在读取进程数据</td></tr></tbody></table>
    </section>
    <section class="panel-card service-card">
      <div class="chart-heading">
        <div>
          <h2>受管服务</h2>
          <p>核对面板期望状态与实际 systemd 状态，主动停用不会误报。</p>
        </div>
        <el-tag :type="serviceProblems.length ? 'danger' : 'success'">{{
          serviceProblems.length
            ? serviceProblems.length + " 项需核对"
            : services.length + " 项状态一致"
        }}</el-tag>
      </div>
      <div v-if="!services.length" class="chart-empty">正在读取服务状态。</div>
      <template v-else>
        <details
          v-for="group in serviceGroups"
          v-show="group.items.length"
          :key="group.kind"
          class="service-group"
          :open="
            group.kind === 'nginx' ||
            group.items.some(
              (v) =>
                v.actual_state === 'unknown' ||
                v.actual_state !== v.expected_state,
            )
          "
        >
          <summary>
            <strong>{{ group.label }}</strong
            ><span>{{ group.items.length }} 项</span>
          </summary>
          <div
            v-for="service in group.items"
            :key="service.resource_id"
            class="service-row"
          >
            <div>
              <strong>{{ service.label }}</strong
              ><small
                >{{ service.detail }} · {{ date(service.checked_at) }}</small
              >
            </div>
            <span>期望 {{ serviceState(service.expected_state) }}</span>
            <el-tag
              :type="
                service.actual_state === 'unknown'
                  ? 'warning'
                  : service.actual_state === service.expected_state
                    ? 'success'
                    : 'danger'
              "
              >实际 {{ serviceState(service.actual_state) }}</el-tag
            >
          </div>
        </details>
      </template>
    </section>
    <section class="panel-card alert-card">
      <div class="chart-heading">
        <div>
          <h2>最近监控告警</h2>
          <p>持续超过阈值才触发；降到阈值下 5 个百分点并持续后恢复。</p>
        </div>
        <el-tag :type="activeAlerts.length ? 'danger' : 'success'">{{
          activeAlerts.length ? activeAlerts.length + " 个活动告警" : "当前正常"
        }}</el-tag>
      </div>
      <div v-if="!alerts.length" class="chart-empty">暂无告警记录。</div>
      <article
        v-for="alert in alerts"
        :key="alert.id"
        class="alert-row"
        :class="alert.state"
      >
        <div>
          <strong>{{ metricName(alert.metric) }}</strong
          ><small
            >{{ alert.state === "active" ? "告警中" : "已恢复"
            }}<template v-if="percentMetric(alert.metric)">
              · 峰值 {{ alert.peak.toFixed(1) }}% · 阈值
              {{ alert.threshold.toFixed(1) }}%</template
            ><template v-else-if="alert.metric.startsWith('service:')">
              · 期望状态与实际状态持续不一致</template
            ><template v-else> · 指标执行服务持续无法连接</template></small
          >
        </div>
        <span>{{ date(alert.started_at) }}</span>
        <el-button
          v-if="!alert.acknowledged_at"
          size="small"
          @click="acknowledge(alert)"
          >确认</el-button
        ><el-tag v-else type="info">已确认</el-tag>
      </article>
      <details v-if="events.length" class="alert-events">
        <summary>查看最近事件（{{ events.length }}）</summary>
        <div v-for="event in events.slice(0, 20)" :key="event.id">
          <span>{{ eventNames[event.kind] }}</span
          ><span>{{ date(event.created_at) }}</span
          ><span>{{
            percentMetric(
              alerts.find((v) => v.id === event.alert_id)?.metric || "",
            )
              ? event.value.toFixed(1) + "%"
              : event.value
                ? "异常"
                : "正常"
          }}</span>
        </div>
      </details>
    </section>
  </div>
  <el-dialog v-model="processListOpen" title="进程列表 · 前 20 项" width="min(760px, 96vw)" append-to-body>
    <p class="monitor-process-note">按当前排序展示 Linux 实际进程采样，可点击“查看”读取单项详情。</p>
    <el-table :data="rankedProcesses.slice(0, 20)" max-height="500" empty-text="当前无进程样本">
      <el-table-column prop="name" label="进程名" min-width="130" show-overflow-tooltip />
      <el-table-column prop="pid" label="PID" width="82" />
      <el-table-column label="CPU" width="86"><template #default="scope">{{ scope.row.cpu_percent.toFixed(1) }}%</template></el-table-column>
      <el-table-column label="内存" width="105"><template #default="scope">{{ memorySize(scope.row.memory) }}</template></el-table-column>
      <el-table-column label="状态" width="80"><template #default="scope">{{ processState(scope.row.state) }}</template></el-table-column>
      <el-table-column label="操作" width="70"><template #default="scope"><el-button link type="primary" @click="showProcess(scope.row)">查看</el-button></template></el-table-column>
    </el-table>
    <template #footer><el-button @click="processListOpen = false">关闭</el-button></template>
  </el-dialog>
  <el-dialog v-model="processDetailOpen" :title="processDetail ? `${processDetail.name} · 进程详情` : '进程详情'" width="460px" append-to-body>
    <template v-if="processDetail">
      <el-alert v-if="processDetailStale" title="当前采样中未找到该进程，以下为最后一次记录" type="warning" :closable="false" />
      <dl class="monitor-process-detail">
        <dt>进程名</dt><dd>{{ processDetail.name }}</dd>
        <dt>PID</dt><dd>{{ processDetail.pid }}</dd>
        <dt>状态</dt><dd>{{ processState(processDetail.state) }}</dd>
        <dt>CPU 使用率</dt><dd>{{ processDetail.cpu_percent.toFixed(1) }}%</dd>
        <dt>内存占用</dt><dd>{{ memorySize(processDetail.memory) }} · {{ processDetail.memory.toLocaleString('zh-CN') }} B</dd>
        <dt>磁盘读取</dt><dd>{{ bytes(processDetail.read_rate) }}</dd>
        <dt>磁盘写入</dt><dd>{{ bytes(processDetail.write_rate) }}</dd>
        <dt>采样时间</dt><dd>{{ formatPanelDateTime(processDetailAt) }}</dd>
      </dl>
      <p class="monitor-process-note">CPU 与磁盘速率来自 Linux 进程两次采样，数值可能随刷新变化。</p>
    </template>
    <template #footer><el-button @click="processDetailOpen = false">关闭</el-button><el-button type="primary" @click="refresh">刷新采样</el-button></template>
  </el-dialog>
  <el-dialog
    v-model="settingsOpen"
    title="监控阈值与保留周期"
    width="580px"
    class="monitor-settings-dialog"
    destroy-on-close
  >
    <div v-if="draft" class="monitor-settings">
      <el-alert
        title="缩短保留周期后，超出新周期的旧样本会立即清理。"
        type="warning"
        :closable="false"
      />
      <label
        >历史保留天数
        <el-input-number v-model="draft.retention_days" :min="1" :max="30"
      /></label>
      <label
        >CPU 阈值
        <el-input-number v-model="draft.cpu_threshold" :min="1" :max="100" />
        %</label
      >
      <label
        >内存阈值
        <el-input-number v-model="draft.memory_threshold" :min="1" :max="100" />
        %</label
      >
      <label
        >数据盘阈值
        <el-input-number v-model="draft.disk_threshold" :min="1" :max="100" />
        %</label
      >
      <label
        >持续触发
        <el-input-number
          v-model="draft.trigger_seconds"
          :min="15"
          :max="3600"
          :step="15"
        />
        秒</label
      >
      <label
        >持续恢复
        <el-input-number
          v-model="draft.recovery_seconds"
          :min="15"
          :max="3600"
          :step="15"
        />
        秒</label
      >
    </div>
    <template #footer
      ><el-button :disabled="busy" @click="settingsOpen = false">取消</el-button
      ><el-button type="primary" :loading="busy" @click="saveSettings"
        >保存设置</el-button
      ></template
    >
  </el-dialog>
</template>

<style scoped>
.monitor-page {
  position: relative;
  display: grid;
  grid-template-columns: minmax(0, 1fr) minmax(0, 1fr) 420px;
  grid-template-rows: auto 230px 200px 175px auto;
  gap: 12px;
}
.monitor-page > .el-alert,
.monitor-toolbar,
.monitor-summary {
  grid-column: 1 / -1;
}
.monitor-chart-card {
  grid-column: span 1;
}
.cpu-chart-card {
  grid-column: 1;
  grid-row: 2;
}
.memory-chart-card {
  grid-column: 2;
  grid-row: 2;
}
.disk-chart-card {
  grid-column: 1;
  grid-row: 3;
}
.network-chart-card {
  grid-column: 2;
  grid-row: 3;
}
.service-card {
  grid-column: 1 / -1;
  grid-row: 5;
}
.alert-card {
  grid-column: 3;
  grid-row: 3 / span 2;
}
.monitor-threshold-card { grid-column: 3; grid-row: 2; overflow: hidden; }
.monitor-process-card { grid-column: 1 / 3; grid-row: 4; overflow: hidden; }
.monitor-threshold-card .chart-heading { padding: 10px 16px; border-bottom: 1px solid #e9eef5; }
.monitor-threshold-card .chart-heading h2 { margin: 0; font-size: 15px; }
.monitor-text-button { border: 0; background: transparent; color: #617591; font-size: 12px; cursor: pointer; }
.monitor-threshold-list { padding: 4px 12px; }
.monitor-threshold-list > div { min-height: 32px; display: grid; grid-template-columns: 1fr 90px 60px; align-items: center; gap: 8px; border-bottom: 1px solid #e9eef5; color: #344760; font-size: 12px; }
.monitor-threshold-list b { font-weight: 400; }.monitor-threshold-list em { font-style: normal; color: #08a856; text-align: center; border-radius: 5px; background: #e8f8ef; padding: 3px 4px; }
.monitor-threshold-list em.alarm { color: #d93838; background: #ffebeb; }
.monitor-process-heading { min-height: 40px; padding: 5px 14px; display: flex; justify-content: space-between; align-items: center; border-bottom: 1px solid #e9eef5; }
.monitor-process-heading h2 { margin: 0; font-size: 15px; }.monitor-process-heading > div { display: flex; gap: 4px; }
.monitor-process-heading > div button:not(.monitor-text-button) { border: 1px solid #e4eaf2; background: #f5f8fc; color: #506481; padding: 5px 11px; font-size: 11px; border-radius: 4px; }
.monitor-process-heading > div button.active { background: #08a856; color: white; border-color: #08a856; }
.monitor-process-table { width: 100%; border-collapse: collapse; font-size: 11px; color: #344760; }
.monitor-process-table th { background: #f7faff; height: 25px; text-align: left; font-weight: 550; }.monitor-process-table td { height: 21px; border-top: 1px solid #e9eef5; }
.monitor-process-table th,.monitor-process-table td { padding: 0 8px; white-space: nowrap; }.monitor-process-table button { color: #0aa359; border: 0; background: transparent; cursor: pointer; }
.monitor-process-table .monitor-process-empty { text-align: center; color: #8191a5; height: 65px; }
.monitor-process-detail { display: grid; grid-template-columns: 105px minmax(0, 1fr); margin: 12px 0 0; border: 1px solid #e7edf4; border-radius: 6px; overflow: hidden; }
.monitor-process-detail dt, .monitor-process-detail dd { display: flex; align-items: center; min-height: 37px; margin: 0; padding: 6px 11px; border-bottom: 1px solid #e9eef4; font-size: 12px; }
.monitor-process-detail dt { color: #71829a; background: #f8fbfe; }
.monitor-process-detail dd { color: #263b56; overflow-wrap: anywhere; }
.monitor-process-detail dt:nth-last-child(2), .monitor-process-detail dd:last-child { border-bottom: 0; }
.monitor-process-note { margin: 8px 0 0; color: #71829a; font-size: 12px; line-height: 1.5; }
.monitor-cpu-bar { display: inline-block; vertical-align: middle; width: 55px; height: 8px; border-radius: 4px; background: #e8eef5; overflow: hidden; margin-right: 6px; }.monitor-cpu-bar i { display: block; height: 100%; background: #0aa65a; border-radius: 4px; }
.monitor-toolbar,
.chart-heading {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 20px;
  padding: 20px 22px;
}
.monitor-toolbar {
  position: absolute;
  inset: 0 0 auto;
  z-index: 3;
  min-height: 0;
  height: 0;
  padding: 0;
  border: 0;
  box-shadow: none;
  background: transparent;
  overflow: visible;
}
.monitor-toolbar > div:first-child {
  display: none;
}
.monitor-toolbar .monitor-actions {
  position: absolute;
  z-index: 3;
  right: 86px;
  top: -70px;
}
.monitor-toolbar h2,
.chart-heading h2 {
  margin: 0 0 5px;
  font-size: 17px;
}
.monitor-toolbar p,
.chart-heading p {
  margin: 0;
  color: #77837d;
  font-size: 13px;
}
.monitor-actions {
  display: flex;
  align-items: center;
  gap: 10px;
}
.monitor-range-tabs { display: inline-flex; border: 1px solid #dce5f1; border-radius: 5px; overflow: hidden; background: white; }
.monitor-range-tabs button { min-width: 76px; height: 35px; padding: 0 13px; border: 0; border-right: 1px solid #dce5f1; color: #344760; background: white; cursor: pointer; font: inherit; }
.monitor-range-tabs button:last-child { border-right: 0; }
.monitor-range-tabs button.active { color: #009e54; box-shadow: inset 0 0 0 1px #00aa59; border-radius: 4px; font-weight: 600; }
.monitor-more-range { border: 0; background: transparent; color: #53647c; cursor: pointer; font: inherit; white-space: nowrap; }
.monitor-auto-refresh { display: inline-flex; align-items: center; gap: 6px; white-space: nowrap; margin-left: 8px; }
.monitor-auto-refresh .el-icon { font-size: 17px; }
.monitor-summary {
  display: grid;
  grid-template-columns: repeat(5, 1fr);
  gap: 12px;
}
.monitor-summary article {
  position: relative;
  min-height: 144px;
  padding: 15px 16px 40px;
  display: flex;
  align-items: flex-start;
  gap: 12px;
}
.monitor-sparkline { position: absolute; bottom: 8px; left: 15px; width: calc(100% - 30px); height: 30px; }
.monitor-summary article > div {
  display: grid;
  gap: 6px;
}
.monitor-summary-icon {
  width: 60px;
  height: 60px;
  border-radius: 10px;
  display: grid;
  place-items: center;
  flex: none;
  font-size: 30px;
}
.monitor-summary .monitor-summary-icon :deep(.el-icon) { font-size: 32px; }
.monitor-summary-icon.green {
  background: #e4f8ed;
  color: #08ad5b;
}
.monitor-summary-icon.blue {
  background: #e7f2ff;
  color: #2387eb;
}
.monitor-summary-icon.purple {
  background: #f0e9ff;
  color: #8747e8;
}
.monitor-summary-icon.orange {
  background: #fff0e7;
  color: #f27621;
}
.monitor-summary small,
.monitor-summary span {
  color: #7b8982;
  font-size: 12px;
}
.monitor-summary strong {
  font-size: 25px;
  color: #10213a;
  line-height: 1;
}
.monitor-summary .danger {
  color: #c24b48;
}
.monitor-chart-card {
  height: 100%;
  padding-bottom: 10px;
  overflow: hidden;
  position: relative;
}
.monitor-chart-card .chart-heading,
.service-card .chart-heading,
.alert-card .chart-heading {
  padding: 13px 16px 9px;
}
.monitor-chart-card .chart-heading h2,
.service-card .chart-heading h2,
.alert-card .chart-heading h2 {
  font-size: 14px;
}
.monitor-chart-card .chart-heading p,
.service-card .chart-heading p,
.alert-card .chart-heading p {
  font-size: 10px;
}
.monitor-chart-card svg {
  display: block;
  width: calc(100% - 32px);
  height: 126px;
  margin: 0 16px;
}
.disk-chart-card svg,.network-chart-card svg { height: 108px; }
.line {
  fill: none;
  stroke-width: 2.5;
  vector-effect: non-scaling-stroke;
}
.cpu-line {
  stroke: #08a856;
}
.memory-line {
  stroke: #08a856;
}
.disk-line {
  stroke: #d7954e;
}
.disk-read-line { stroke: #08a856; }.disk-write-line { stroke: #1975e8; }
.rx-line {
  stroke: #08a856;
}
.tx-line {
  stroke: #1975e8;
}
.legend {
  display: flex;
  gap: 15px;
  font-size: 12px;
  color: #637069;
}
.legend span:before {
  content: "";
  display: inline-block;
  width: 8px;
  height: 8px;
  border-radius: 50%;
  margin-right: 6px;
}
.legend .cpu:before {
  background: #08a856;
}
.legend .memory:before {
  background: #08a856;
}
.legend .disk:before {
  background: #d7954e;
}
.legend .disk-read:before { background: #08a856; }.legend .disk-write:before { background: #1975e8; }
.legend .rx:before {
  background: #08a856;
}
.legend .tx:before {
  background: #1975e8;
}
.chart-axis {
  display: flex;
  flex-direction: row;
  justify-content: space-between;
  width: auto;
  margin: 0 16px;
  padding: 0;
  color: #8a9690;
  font-family: inherit;
  font-size: 10px;
}
.chart-axis span {
  white-space: nowrap;
}
.monitor-chart-tooltip {
  position: absolute;
  z-index: 2;
  top: 68px;
  display: grid;
  gap: 3px;
  padding: 8px 10px;
  border: 1px solid #dfe7ef;
  border-radius: 5px;
  background: #fff;
  box-shadow: 0 4px 14px #17253b20;
  color: #30435f;
  font-size: 10px;
  pointer-events: none;
}
.monitor-chart-tooltip b { font-size: 10px; }
.chart-empty {
  padding: 38px 22px;
  text-align: center;
  color: #7b8982;
}
.alert-card {
  height: 100%;
  overflow: auto;
  padding-bottom: 12px;
}
.service-card {
  min-height: 180px;
  height: auto;
  overflow: auto;
  padding-bottom: 12px;
}
.service-group {
  border-top: 1px solid #edf0ef;
}
.service-group summary {
  display: flex;
  justify-content: space-between;
  padding: 14px 22px;
  cursor: pointer;
  color: #394b43;
}
.service-group summary span {
  color: #849089;
  font-size: 12px;
}
.service-row {
  display: grid;
  grid-template-columns: 1fr 120px 100px;
  align-items: center;
  gap: 14px;
  margin: 0 22px;
  padding: 11px 0;
  border-top: 1px dashed #edf0ef;
}
.service-row > div {
  display: grid;
  gap: 3px;
}
.service-row small,
.service-row > span {
  color: #7b8982;
  font-size: 12px;
}
.alert-row {
  display: grid;
  grid-template-columns: 1fr auto auto;
  align-items: center;
  gap: 20px;
  padding: 14px 22px;
  border-top: 1px solid #edf0ef;
}
.alert-row > div {
  display: grid;
  gap: 4px;
}
.alert-row small,
.alert-row > span {
  color: #7b8982;
  font-size: 12px;
}
.alert-row.active {
  border-left: 3px solid #d95b57;
}
.alert-events {
  margin: 10px 22px;
  color: #596760;
  font-size: 13px;
}
.alert-events summary {
  cursor: pointer;
}
.alert-events div {
  display: grid;
  grid-template-columns: 1fr 150px 80px;
  padding: 9px 0;
  border-bottom: 1px solid #edf0ef;
}
.monitor-settings {
  display: grid;
  gap: 15px;
}
.monitor-settings label {
  display: grid;
  grid-template-columns: 1fr auto auto;
  align-items: center;
  gap: 8px;
  color: #4b5d54;
}
.monitor-settings .el-alert {
  margin-bottom: 4px;
}
@media (max-width: 760px) {
  .monitor-page {
    grid-template-columns: 1fr;
  }
  .monitor-page > *,
  .monitor-toolbar,
  .monitor-summary,
  .monitor-chart-card,
  .monitor-threshold-card,
  .monitor-process-card,
  .service-card,
  .alert-card {
    grid-column: 1;
    grid-row: auto;
  }
  .monitor-toolbar,
  .chart-heading {
    align-items: flex-start;
    flex-direction: column;
  }
  .monitor-toolbar { position: static; display: flex; height: auto; padding: 10px; border: 1px solid #e4eaf2; background: white; }
  .monitor-toolbar .monitor-actions { position: static; flex-wrap: wrap; }
  .monitor-actions {
    width: 100%;
  }
  .monitor-range-tabs { max-width: 100%; }
  .monitor-range-tabs button { min-width: 0; }
  .monitor-summary {
    grid-template-columns: repeat(2, 1fr);
  }
  .monitor-chart-card svg {
    height: 190px;
    width: calc(100% - 28px);
    margin: 0 14px;
  }
  .legend {
    flex-wrap: wrap;
  }
  .alert-row {
    grid-template-columns: 1fr auto;
  }
  .service-row {
    grid-template-columns: 1fr auto;
    margin: 0 14px;
  }
  .service-row > span {
    display: none;
  }
  .alert-row > span {
    display: none;
  }
  .monitor-settings label {
    grid-template-columns: 1fr auto;
  }
  .monitor-settings label > .el-input-number {
    grid-column: 2;
  }
}
@media (min-width: 761px) and (max-width: 1200px) {
  .monitor-page {
    grid-template-columns: 1fr 1fr;
  }
  .monitor-page > .el-alert,
  .monitor-toolbar,
  .monitor-summary {
    grid-column: 1 / -1;
  }
  .service-card,
  .alert-card,
  .monitor-threshold-card,
  .monitor-process-card {
    grid-column: span 1;
    grid-row: auto;
  }
  .monitor-summary {
    grid-template-columns: repeat(3, 1fr);
  }
}
</style>
