<script setup lang="ts">
import { computed, onBeforeUnmount, onMounted, ref } from "vue";
import { randomId } from "./randomId";
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
  source_sha256?: string;
}

interface MigrationStatus {
  request_id: string;
  job_id?: string;
  project_id?: string;
  phase?: string;
  needs_recovery?: boolean;
}

const props = defineProps<{
  api: <T>(path: string, method?: string, body?: unknown, idempotencyKey?: string) => Promise<T>;
  project: { id: string; name: string; template_id?: string; state: string };
  targetSHA: string;
  canMigrate: boolean;
}>();
const emit = defineEmits<{ close: []; changed: [] }>();
const report = ref<MigrationReport>();
const loading = ref(false);
const error = ref("");
const acknowledged = ref(false);
const status = ref<MigrationStatus>();
const request = ref("");
const actionBusy = ref(false);
let sequence = 0;
let timer: ReturnType<typeof setTimeout> | undefined;
let disposed = false;
const path = `/docker/projects/${props.project.id}`;
const phases: Record<string, string> = {
  submitted: "等待执行器确认",
  prepared: "正在核对原实例和签名镜像",
  "quiesce-intent": "正在暂停新连接",
  "stop-original-intent": "正在停止原实例",
  "original-stopped": "原实例已停止",
  "copy-intent": "正在复制原数据卷",
  "copy-verified": "候选卷复制已核对",
  "bridge-intent": "候选卷正在升级至 4.2",
  "bridge-stopped": "候选卷已完成 4.2 升级",
  "target-check-intent": "正在验证 4.4 实例",
  "target-verified-offline": "4.4 候选实例已核对",
  "publish-endpoint-intent": "正在核对原端口切换",
  "resume-listeners-intent": "正在恢复原监听",
  "restore-original-intent": "正在恢复原实例",
  "restart-original-intent": "正在核对原实例重启",
  "target-published": "已升级至 4.4.0",
  "original-restored": "迁移中止，原实例已恢复",
  "cancelled-before-stop": "迁移已结束，原实例未停机",
};
const terminal = computed(() => ["target-published", "original-restored", "cancelled-before-stop"].includes(status.value?.phase || ""));
const canSubmit = computed(() => props.canMigrate && /^[a-f0-9]{64}$/.test(props.targetSHA) &&
  /^[a-f0-9]{64}$/.test(report.value?.source_sha256 || "") && pendingChecks.value.length === 0 &&
  !request.value && !status.value);

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
  acknowledged.value = false;
  error.value = "";
  try {
    if (props.canMigrate) {
      const original = await props.api<MigrationStatus>(`${path}/rabbitmq-migrations`);
      if (ticket !== sequence) return;
      if (original.request_id) {
        accept(original, original.request_id);
        return;
      }
    }
    if (props.project.template_id !== "rabbitmq" || props.project.state !== "running") return;
    const result = await props.api<MigrationReport>(`${path}/rabbitmq-migration-preflight`);
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

function accept(result: MigrationStatus, expected: string) {
  if (disposed) return;
  if (!/^[a-f0-9]{32}$/.test(expected) || result.request_id !== expected || result.project_id !== props.project.id ||
      !/^[a-f0-9]{32}$/.test(result.job_id || "") || !result.phase || !phases[result.phase]) {
    throw new Error("无法核对原迁移任务回执");
  }
  request.value = expected;
  status.value = result;
  error.value = "";
  if (timer) clearTimeout(timer);
  if (terminal.value) emit("changed");
  else if (!result.needs_recovery) timer = setTimeout(poll, 2500);
}

async function poll() {
  if (disposed || !request.value) return;
  try {
    const result = await props.api<MigrationStatus>(`${path}/rabbitmq-migrations/${request.value}`);
    accept(result, request.value);
  } catch (cause) {
    if (!disposed) error.value = cause instanceof Error ? cause.message : "无法查询原任务";
  }
}

async function submit() {
  if (!canSubmit.value || !acknowledged.value || !report.value || actionBusy.value) return;
  actionBusy.value = true;
  const id = randomId().replaceAll("-", "");
  request.value = id;
  error.value = "";
  try {
    const result = await props.api<MigrationStatus>(`${path}/rabbitmq-migrations`, "POST", {
      source_sha256: report.value.source_sha256,
      target_manifest_sha256: props.targetSHA,
      downtime_acknowledged: true,
    }, id);
    accept(result, id);
  } catch (cause) {
    if (!disposed) {
      const code = (cause as {status?: number})?.status;
      if (code === 400 || code === 403 || code === 409 || code === 503) request.value = "";
      error.value = cause instanceof Error ? cause.message : "原迁移请求状态待核对";
    }
  } finally {
    actionBusy.value = false;
  }
}

async function recover() {
  if (!status.value?.needs_recovery || !request.value || actionBusy.value) return;
  actionBusy.value = true;
  try {
    const result = await props.api<MigrationStatus>(`${path}/rabbitmq-migrations/${request.value}/reconcile`, "POST", {});
    accept(result, request.value);
  } catch (cause) {
    if (!disposed) error.value = cause instanceof Error ? cause.message : "恢复请求状态待核对";
  } finally {
    actionBusy.value = false;
  }
}

onMounted(check);
onBeforeUnmount(() => {
  disposed = true;
  sequence++;
  if (timer) clearTimeout(timer);
});
</script>

<template>
  <el-dialog :model-value="true" :title="project.name + ' · RabbitMQ 迁移'" width="min(720px, 94vw)"
    append-to-body @update:model-value="(open: boolean) => { if (!open) emit('close'); }">
    <p>检查原实例和数据卷。升级路径为 4.1 → 4.2 → 4.4，需要维护窗口。</p>
    <p v-if="loading" role="status">正在读取原 RabbitMQ 项目…</p>
    <el-alert v-if="error" type="error" role="alert" :title="error" :closable="false" />
    <section v-if="status" aria-live="polite">
      <p role="status">{{ phases[status.phase || ""] }}</p>
      <p>任务编号 <code>{{ status.job_id }}</code></p>
      <p v-if="status.needs_recovery && status.phase === 'publish-endpoint-intent'">新实例可能已收到消息。恢复会继续核对同一个新实例及数据卷。</p>
      <p v-else-if="status.needs_recovery">可恢复原实例和监听。</p>
    </section>
    <template v-else-if="report">
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
      <p v-else role="status">预检已通过。升级期间 AMQP 和管理端口会暂时停止服务。</p>
      <el-checkbox v-if="canSubmit" v-model="acknowledged">我已停止发件和消费任务，并确认维护停机</el-checkbox>
    </template>
    <template #footer>
      <el-button @click="emit('close')">关闭</el-button>
      <el-button v-if="request" :disabled="actionBusy" @click="poll">查询原任务</el-button>
      <el-button v-else :loading="loading" @click="check">重新检查</el-button>
      <el-button v-if="canSubmit" type="primary" :disabled="!acknowledged" :loading="actionBusy" @click="submit">开始迁移</el-button>
      <el-button v-if="status?.needs_recovery" type="primary" :loading="actionBusy" @click="recover">恢复原任务</el-button>
    </template>
  </el-dialog>
</template>

<style scoped>
.migration-details { display: grid; grid-template-columns: max-content minmax(0, 1fr); gap: 8px 16px; }
.migration-details dt { font-weight: 600; }
.migration-details dd { margin: 0; overflow-wrap: anywhere; }
</style>
