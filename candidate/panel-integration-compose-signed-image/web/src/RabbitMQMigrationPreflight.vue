<script setup lang="ts">
import { computed, onBeforeUnmount, onMounted, ref } from "vue";
import { formatPanelDateTime } from "./panelTime";

interface MigrationReport {
  project_id: string;
  observed_at: string;
  broker_version: string;
  node: string;
  data_volume: string;
  disabled_stable_features: string[];
  alarm_count: number;
  connection_count: number;
}

const props = defineProps<{
  api: <T>(path: string) => Promise<T>;
  project: { id: string; name: string };
}>();
const emit = defineEmits<{ close: [] }>();
const report = ref<MigrationReport>();
const loading = ref(false);
const error = ref("");
let sequence = 0;

const pendingChecks = computed(() => {
  if (!report.value) return [];
  const { alarm_count, connection_count, disabled_stable_features } = report.value;
  const checks: string[] = [];
  if (alarm_count) checks.push(`处理 ${alarm_count} 个 RabbitMQ 告警。`);
  if (connection_count) checks.push(`维护时先停客户端写入，并断开 ${connection_count} 个活动连接。`);
  if (disabled_stable_features.length) checks.push(`核对以下稳定功能标志：${disabled_stable_features.join("、")}。`);
  return checks;
});

async function check() {
  const ticket = ++sequence;
  loading.value = true;
  report.value = undefined;
  error.value = "";
  try {
    const result = await props.api<MigrationReport>(`/docker/projects/${props.project.id}/rabbitmq-migration-preflight`);
    if (ticket !== sequence) return;
    if (result.project_id !== props.project.id || result.broker_version !== "4.1.4" ||
        result.node !== "rabbit@cloudstack-rabbitmq" ||
        result.data_volume !== `panel_${props.project.id.slice(0, 12)}_data` ||
        !Number.isSafeInteger(result.alarm_count) || result.alarm_count < 0 ||
        !Number.isSafeInteger(result.connection_count) || result.connection_count < 0 ||
        !Array.isArray(result.disabled_stable_features) || !result.observed_at) {
      throw new Error("无法核对原 RabbitMQ 实例的预检结果");
    }
    report.value = result;
  } catch (cause) {
    if (ticket === sequence) {
      error.value = cause instanceof Error ? cause.message : "读取 RabbitMQ 迁移预检失败";
    }
  } finally {
    if (ticket === sequence) loading.value = false;
  }
}

onMounted(check);
onBeforeUnmount(() => { sequence++; });
</script>

<template>
  <el-dialog :model-value="true" :title="project.name + ' · RabbitMQ 迁移预检'" width="min(720px, 94vw)"
    append-to-body @update:model-value="(open: boolean) => { if (!open) emit('close'); }">
    <p>检查原实例和数据卷。升级路径为 4.1 → 4.2 → 4.4，需要维护窗口。</p>
    <p v-if="loading" role="status">正在读取原 RabbitMQ 项目…</p>
    <el-alert v-if="error" type="error" role="alert" :title="error" :closable="false" />
    <template v-if="report">
      <dl class="migration-details">
        <dt>原版本</dt><dd>{{ report.broker_version }}</dd>
        <dt>节点</dt><dd><code>{{ report.node }}</code></dd>
        <dt>数据卷</dt><dd><code>{{ report.data_volume }}</code></dd>
        <dt>活动连接</dt><dd>{{ report.connection_count }}</dd>
        <dt>RabbitMQ 告警</dt><dd>{{ report.alarm_count }}</dd>
        <dt>未启用的稳定功能</dt><dd>{{ report.disabled_stable_features.length }}</dd>
        <dt>读取时间</dt><dd>{{ formatPanelDateTime(report.observed_at) }}</dd>
      </dl>
      <ul v-if="pendingChecks.length">
        <li v-for="item in pendingChecks" :key="item">{{ item }}</li>
      </ul>
      <p v-else role="status">本次预检已核对原卷、单节点状态和稳定功能标志。</p>
    </template>
    <template #footer>
      <el-button @click="emit('close')">关闭</el-button>
      <el-button type="primary" :loading="loading" @click="check">重新检查</el-button>
    </template>
  </el-dialog>
</template>

<style scoped>
.migration-details { display: grid; grid-template-columns: max-content minmax(0, 1fr); gap: 8px 16px; }
.migration-details dt { font-weight: 600; }
.migration-details dd { margin: 0; overflow-wrap: anywhere; }
</style>
