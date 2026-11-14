<script setup lang="ts">
import { computed, onBeforeUnmount, onMounted, ref } from "vue";
import { formatPanelDateTime } from "./panelTime";

type Queue = {
  name: string;
  type: string;
  state: string;
  durable: boolean;
  messages_ready: number | null;
  messages_unacknowledged: number | null;
  consumers: number | null;
};

type QueueReport = {
  project_id: string;
  observed_at: string;
  virtual_hosts: string[];
  virtual_host: string;
  queues: Queue[];
};

const props = defineProps<{
  api: <T>(path: string) => Promise<T>;
  project: { id: string; name: string };
}>();
const emit = defineEmits<{ close: [] }>();
const loading = ref(false);
const report = ref<QueueReport>();
const hosts = ref<string[]>([]);
const vhost = ref("/");
const search = ref("");
const page = ref(1);
const error = ref("");
let sequence = 0;
const pageSize = 25;

const filtered = computed(() => {
  const needle = search.value.trim().toLocaleLowerCase();
  return (report.value?.queues || []).filter(queue => queue.name.toLocaleLowerCase().includes(needle));
});
const pageRows = computed(() => filtered.value.slice((page.value - 1) * pageSize, page.value * pageSize));
const count = (value: number | null) => value === null ? "未知" : value.toLocaleString("zh-CN");
const stateNames: Record<string, string> = { running: "运行中", idle: "空闲", down: "离线", crashed: "异常", stopped: "已停止" };

async function load(name = vhost.value, fallback = true) {
  if (loading.value) return;
  const ticket = ++sequence;
  loading.value = true;
  error.value = "";
  page.value = 1;
  report.value = undefined;
  try {
    const result = await props.api<QueueReport>(`/docker/projects/${props.project.id}/rabbitmq-queues?${new URLSearchParams({ vhost: name })}`);
    if (ticket !== sequence) return;
    if (result.project_id !== props.project.id || result.virtual_host !== name ||
        !Number.isFinite(Date.parse(result.observed_at)) || !Array.isArray(result.virtual_hosts) ||
        !Array.isArray(result.queues) || !result.virtual_hosts.length) {
      throw new Error("RabbitMQ 队列报告身份无法核对");
    }
    hosts.value = result.virtual_hosts;
    if (hosts.value.includes(name)) {
      report.value = result;
    } else if (fallback) {
      vhost.value = hosts.value[0];
      loading.value = false;
      await load(vhost.value, false);
    } else {
      error.value = "虚拟主机已经变化，请重新选择并刷新。";
    }
  } catch (cause) {
    if (ticket === sequence) error.value = cause instanceof Error ? cause.message : "RabbitMQ 队列读取失败";
  } finally {
    if (ticket === sequence) loading.value = false;
  }
}

onMounted(() => load());
onBeforeUnmount(() => { sequence++; });
</script>

<template>
  <el-dialog :model-value="true" :title="project.name + ' · RabbitMQ 队列'" width="min(950px, 94vw)"
    append-to-body @update:model-value="(value: boolean) => { if (!value) emit('close'); }">
    <div class="queue-filters">
      <label>
        <span>虚拟主机</span>
        <el-select v-model="vhost" aria-label="虚拟主机" :disabled="loading || !hosts.length" @change="load(vhost)">
          <el-option v-for="name in hosts" :key="name" :label="name" :value="name" />
        </el-select>
      </label>
      <label>
        <span>队列名称</span>
        <el-input v-model="search" maxlength="255" clearable aria-label="搜索队列" @input="page = 1" />
      </label>
    </div>
    <el-alert v-if="error" role="alert" type="error" :closable="false" :title="error" />
    <p v-if="loading" role="status">正在读取 RabbitMQ 队列…</p>
    <template v-if="report">
      <p role="status">{{ report.queues.length }} 个队列 · 读取时间 {{ formatPanelDateTime(report.observed_at) }}</p>
      <div v-if="pageRows.length" class="queue-overflow">
        <table aria-label="RabbitMQ 队列表">
          <thead><tr>
            <th scope="col">队列</th><th scope="col">状态</th><th scope="col">待投递</th>
            <th scope="col">未确认</th><th scope="col">消费者</th>
          </tr></thead>
          <tbody><tr v-for="queue in pageRows" :key="queue.name">
            <th scope="row">{{ queue.name }}<small>{{ queue.type }} · {{ queue.durable ? "持久" : "临时" }}</small></th>
            <td>{{ Object.hasOwn(stateNames, queue.state) ? stateNames[queue.state] : queue.state }}</td>
            <td>{{ count(queue.messages_ready) }}</td><td>{{ count(queue.messages_unacknowledged) }}</td>
            <td>{{ count(queue.consumers) }}</td>
          </tr></tbody>
        </table>
      </div>
      <el-empty v-else :description="search ? '没有匹配的队列' : '该虚拟主机还没有队列'" :image-size="64" />
      <el-pagination v-if="filtered.length > pageSize" v-model:current-page="page" :page-size="pageSize"
        :total="filtered.length" layout="prev, pager, next" :pager-count="5" />
    </template>
    <template #footer>
      <el-button @click="emit('close')">关闭</el-button>
      <el-button type="primary" :loading="loading" @click="load()">刷新队列</el-button>
    </template>
  </el-dialog>
</template>

<style scoped>
.queue-filters { display: grid; grid-template-columns: repeat(auto-fit, minmax(155px, 1fr)); gap: 12px; }
.queue-filters label { display: grid; gap: 4px; }
.queue-overflow { overflow-x: auto; margin: 12px 0; }
.queue-overflow table { border-collapse: collapse; width: 100%; min-width: 440px; text-align: left; }
.queue-overflow th, .queue-overflow td { padding: 8px 10px; border-bottom: 1px solid var(--el-border-color-lighter); }
.queue-overflow td { font-variant-numeric: tabular-nums; }
.queue-overflow small { display: block; font-weight: normal; color: var(--el-text-color-secondary); }
</style>
