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

const sample = ref<Sample>();
const loading = ref(false);
const error = ref("");
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

async function load() {
  if (!active || loading.value) return;
  loading.value = true;
  sample.value = undefined;
  error.value = "";
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
    if (active) error.value = cause instanceof Error ? cause.message : String(cause);
  } finally {
    if (active) loading.value = false;
  }
}

onMounted(load);
onBeforeUnmount(() => { active = false; });
</script>

<template>
  <el-dialog :model-value="true" :title="name + ' · 资源使用'" width="min(600px, 94vw)" append-to-body
    @update:model-value="(value: boolean) => { if (!value) emit('close'); }">
    <p v-if="loading" role="status">正在读取 Docker 资源采样…</p>
    <el-alert v-if="error" :title="error" type="error" :closable="false" />
    <template v-if="sample">
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
      <el-button type="primary" :loading="loading" @click="load">重新采样</el-button>
    </template>
  </el-dialog>
</template>

<style scoped>
.metrics { display: grid; gap: 0; margin: 12px 0; }
.metrics div { display: flex; justify-content: space-between; flex-wrap: wrap; gap: 6px 16px; padding: 9px 0; border-bottom: 1px solid var(--el-border-color-lighter); }
.metrics dd { margin: 0; font-variant-numeric: tabular-nums; }
.description { color: var(--el-text-color-secondary); }
</style>
