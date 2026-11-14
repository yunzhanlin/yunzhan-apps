<script setup lang="ts">
import { computed, onBeforeUnmount, onMounted, ref } from "vue";
import { formatPanelDateTime } from "./panelTime";

const props = defineProps<{
  api: <T>(path: string) => Promise<T>;
  id: string;
  name: string;
}>();
const emit = defineEmits<{ close: [] }>();

type Sample = {
  id: string;
  observed_at: string;
  cpu_percent: number | null;
  memory_bytes: number | null;
  memory_limit_bytes: number | null;
  network_rx_bytes: number | null;
  network_tx_bytes: number | null;
  block_read_bytes: number | null;
  block_written_bytes: number | null;
  pids: number | null;
};

type Status = "created" | "running" | "paused" | "restarting" | "exited" | "dead" | "removing";
type Health = "none" | "starting" | "healthy" | "unhealthy";
type Policy = "no" | "always" | "unless-stopped" | "on-failure";
type Lifecycle = {
  id: string;
  observed_at: string;
  status: Status;
  started_at: string | null;
  finished_at: string | null;
  exit_code: number | null;
  oom_killed: boolean;
  restart_count: number;
  restart_policy: Policy;
  maximum_retry_count: number;
  health: Health | null;
  health_failure_count: number | null;
};

const statuses: Record<Status, string> = {
  created: "已创建", running: "运行中", paused: "已暂停", restarting: "重启中",
  exited: "已退出", dead: "异常停止", removing: "正在移除",
};
const policies: Record<Policy, string> = {
  no: "手动启动", always: "始终重启", "unless-stopped": "除非手动停止", "on-failure": "退出失败时重启",
};
const healthLabels: Record<Health, string> = {
  none: "未配置", starting: "启动中", healthy: "健康", unhealthy: "不健康",
};

const lifecycle = ref<Lifecycle>();
const sample = ref<Sample>();
const loading = ref(false);
const error = ref("");
const sampleError = ref("");
let active = true;

const number = new Intl.NumberFormat("zh-CN", { maximumFractionDigits: 1 });

function bytes(value: number | null): string {
  if (value === null) return "—";
  const units = ["B", "KiB", "MiB", "GiB", "TiB", "PiB", "EiB"];
  let unit = 0;
  while (value >= 1024 && unit < units.length - 1) {
    value /= 1024;
    unit++;
  }
  return `${number.format(value)} ${units[unit]}`;
}

const rows = computed(() => {
  const value = sample.value;
  if (!value) return [];
  return [
    { label: "CPU 使用率", value: value.cpu_percent === null ? "—" : `${number.format(value.cpu_percent)}%` },
    { label: "内存使用 / 上限", value: `${bytes(value.memory_bytes)} / ${bytes(value.memory_limit_bytes)}` },
    { label: "网络接收 / 发送", value: `${bytes(value.network_rx_bytes)} / ${bytes(value.network_tx_bytes)}` },
    { label: "磁盘读取 / 写入", value: `${bytes(value.block_read_bytes)} / ${bytes(value.block_written_bytes)}` },
    { label: "进程与线程", value: value.pids === null ? "—" : number.format(value.pids) },
  ];
});

const diagnostics = computed(() => {
  const value = lifecycle.value;
  if (!value) return [];
  const time = (stamp: string | null) => stamp ? formatPanelDateTime(stamp) : "—";
  const policy = policies[value.restart_policy];
  const retries = value.restart_policy === "on-failure" && value.maximum_retry_count > 0
    ? `（最多 ${value.maximum_retry_count} 次）` : "";
  return [
    { label: "当前状态", value: statuses[value.status] },
    { label: "最近启动", value: time(value.started_at) },
    { label: "最近结束", value: time(value.finished_at) },
    { label: "退出码", value: value.exit_code === null ? "—" : String(value.exit_code) },
    { label: "内存不足终止", value: value.oom_killed ? "是" : "否" },
    { label: "重启次数", value: number.format(value.restart_count) },
    { label: "重启策略", value: policy + retries },
    { label: "健康检查", value: value.health === null ? "未配置" : healthLabels[value.health] },
    { label: "连续检查失败", value: value.health_failure_count === null ? "—" : number.format(value.health_failure_count) },
  ];
});

const count = (value: number) => Number.isSafeInteger(value) && value >= 0;
const time = (value: string | null) => value === null || (typeof value === "string" && Number.isFinite(Date.parse(value)));
async function load() {
  if (!active || loading.value) return;
  loading.value = true;
  lifecycle.value = undefined;
  sample.value = undefined;
  error.value = "";
  sampleError.value = "";
  try {
    const value = await props.api<Lifecycle>(`/docker/containers/${props.id}/state`);
    if (!active) return;
    if (value.id !== props.id || typeof value.observed_at !== "string" || !time(value.observed_at) ||
        !Object.hasOwn(statuses, value.status) || !Object.hasOwn(policies, value.restart_policy) ||
        !time(value.started_at) || !time(value.finished_at) || typeof value.oom_killed !== "boolean" ||
        !count(value.restart_count) || !count(value.maximum_retry_count) ||
        (value.exit_code !== null && !count(value.exit_code)) ||
        (value.health === null ? value.health_failure_count !== null :
          !Object.hasOwn(healthLabels, value.health) || !count(value.health_failure_count ?? -1))) {
      throw new Error("返回的容器身份或运行状态无法核对。");
    }
    lifecycle.value = value;
    if (value.status === "running") await loadSample();
  } catch (cause) {
    if (active) error.value = cause instanceof Error ? cause.message : String(cause);
  } finally {
    if (active) loading.value = false;
  }
}

async function loadSample() {
  try {
    const value = await props.api<Sample>(`/docker/containers/${props.id}/stats`);
    if (!active) return;
    const readings = [value.cpu_percent, value.memory_bytes, value.memory_limit_bytes,
      value.network_rx_bytes, value.network_tx_bytes, value.block_read_bytes, value.block_written_bytes, value.pids];
    if (value.id !== props.id || !Number.isFinite(Date.parse(value.observed_at)) ||
        readings.some(metric => metric !== null && (!Number.isFinite(metric) || metric < 0))) {
      throw new Error("返回的容器身份或资源采样无法核对。");
    }
    sample.value = value;
  } catch (cause) {
    if (active) sampleError.value = cause instanceof Error ? cause.message : String(cause);
  }
}

onMounted(load);
onBeforeUnmount(() => { active = false; });
</script>

<template>
  <el-dialog :model-value="true" :title="name + ' · 容器诊断'" width="min(600px, 94vw)" append-to-body
    @update:model-value="(value: boolean) => { if (!value) emit('close'); }">
    <p v-if="loading" role="status">正在读取容器状态…</p>
    <el-alert v-if="error" :title="error" type="error" :closable="false" />
    <template v-if="lifecycle">
      <p>状态读取时间 {{ formatPanelDateTime(lifecycle.observed_at) }}</p>
      <dl class="metrics">
        <div v-for="row in diagnostics" :key="row.label">
          <dt>{{ row.label }}</dt>
          <dd>{{ row.value }}</dd>
        </div>
      </dl>
    </template>
    <el-alert v-if="sampleError" :title="sampleError" type="error" :closable="false" />
    <template v-if="sample">
      <h3>资源使用</h3>
      <p>采样时间 {{ formatPanelDateTime(sample.observed_at) }}</p>
      <dl class="metrics">
        <div v-for="row in rows" :key="row.label">
          <dt>{{ row.label }}</dt>
          <dd>{{ row.value }}</dd>
        </div>
      </dl>
      <p class="description">网络与磁盘使用累计计数。Docker 缺少采样的指标显示为 —。</p>
    </template>
    <template #footer>
      <el-button @click="emit('close')">关闭</el-button>
      <el-button type="primary" :loading="loading" @click="load">刷新诊断</el-button>
    </template>
  </el-dialog>
</template>

<style scoped>
.metrics { display: grid; gap: 0; margin: 12px 0; }
.metrics div { display: flex; justify-content: space-between; flex-wrap: wrap; gap: 6px 16px; padding: 9px 0; border-bottom: 1px solid var(--el-border-color-lighter); }
.metrics dd { margin: 0; font-variant-numeric: tabular-nums; }
.description { color: var(--el-text-color-secondary); }
</style>
