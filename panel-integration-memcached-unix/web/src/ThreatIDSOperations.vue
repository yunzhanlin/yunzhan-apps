<script setup lang="ts">
import { computed, onBeforeUnmount, ref, watch } from "vue";
import { canReadPath, type AccessPlan } from "./menuPermissions";
import { validIDSOperation, type IDSOperation } from "./networkIDSOperations";
type API = <T>(
  path: string,
  method?: string,
  body?: unknown,
  idempotencyKey?: string,
) => Promise<T>;
const props = defineProps<{
  api: API;
  operationId?: string;
  installed: boolean;
  access?: AccessPlan | null;
}>();
const emit = defineEmits<{
  pending: [value: boolean];
  completed: [id: string];
}>();
const operation = ref<IDSOperation>(),
  error = ref(""),
  loading = ref(false);
const authorized = computed(
  () =>
    !!props.access &&
    canReadPath(
      props.access,
      "/app-modules/network-threat-detection/operations",
    ),
);
const labels: Record<string, string> = {
  queued: "已排队 · 未完成",
  running: "正在核对原生操作",
  succeeded: "原生操作已通过核对",
  failed: "操作失败",
  "needs-attention": "需要核对 · 未宣称完成",
};
let generation = 0,
  timer: ReturnType<typeof setTimeout> | undefined,
  observedID = "",
  finishedID = "",
  started = 0;
function invalidate() {
  generation++;
  if (timer) clearTimeout(timer);
  timer = undefined;
  observedID = "";
  finishedID = "";
  operation.value = undefined;
  error.value = "";
  loading.value = false;
  emit("pending", false);
}
onBeforeUnmount(invalidate);
async function refresh() {
  if (!authorized.value || !props.installed || loading.value) return;
  const token = generation;
  loading.value = true;
  error.value = "";
  try {
    let out: unknown;
    const id = props.operationId || observedID;
    if (id) {
      if (!/^[a-f0-9]{32}$/.test(id)) throw new Error("原生任务标识无效");
      out = await props.api(
        `/app-modules/network-threat-detection/operations/${id}`,
      );
    } else {
      const rows = await props.api<unknown>(
        "/app-modules/network-threat-detection/operations",
      );
      if (
        !Array.isArray(rows) ||
        rows.length > 16 ||
        !rows.every(validIDSOperation) ||
        new Set(rows.map((row) => row.id)).size !== rows.length
      )
        throw new Error("原生任务列表不能核对");
      out =
        rows.find((row) => ["queued", "running"].includes(row.state)) ||
        rows[0];
      if (out === undefined) {
        if (token === generation) emit("pending", false);
        return;
      }
    }
    if (token !== generation) return;
    if (!validIDSOperation(out) || (id && out.id !== id))
      throw new Error("原生任务状态身份不符，未采用旧结果");
    operation.value = out;
    observedID = out.id;
    const pending = ["queued", "running"].includes(out.state);
    emit("pending", pending);
    if (pending) {
      if (Date.now() - started < 8 * 60_000)
        timer = setTimeout(() => void refresh(), 1500);
      else
        error.value =
          "已达到 8 分钟页面观察上限；服务器任务未被取消，请用原任务编号重新查询。";
    } else if (out.state === "succeeded" && finishedID !== out.id) {
      finishedID = out.id;
      emit("completed", out.id);
    }
  } catch (e) {
    if (token === generation) {
      error.value = e instanceof Error ? e.message : String(e);
      operation.value = undefined;
      emit("pending", true);
    }
  } finally {
    if (token === generation) loading.value = false;
  }
}
function restartObservation() {
  if (timer) clearTimeout(timer);
  timer = undefined;
  started = Date.now();
  void refresh();
}
watch(
  () =>
    [
      props.operationId,
      props.installed,
      authorized.value,
      props.access,
    ] as const,
  () => {
    invalidate();
    started = Date.now();
    if (authorized.value && props.installed) void refresh();
  },
  { immediate: true },
);
</script>
<template>
  <section
    v-if="authorized && installed"
    class="ids-operations"
    aria-label="原生后台任务"
  >
    <h3>原生后台任务</h3>
    <p>
      已接受的任务由执行器继续处理；关闭窗口不取消任务。排队或运行状态不代表已经启用采集。
    </p>
    <el-alert v-if="error" :title="error" type="warning" :closable="false" />
    <template v-if="operation">
      <el-tag
        :type="
          operation.state === 'succeeded'
            ? 'success'
            : operation.state === 'needs-attention' ||
                operation.state === 'failed'
              ? 'danger'
              : 'warning'
        "
        >{{ labels[operation.state] }}</el-tag
      >
      <p>
        任务 {{ operation.id }} · {{ operation.action }} · 提交修订
        {{ operation.input.expected_revision }}
      </p>
      <el-alert
        v-if="operation.error"
        :title="operation.error"
        type="error"
        :closable="false"
      />
      <ol>
        <li v-for="(step, index) in operation.steps" :key="index">
          {{ step.time }}：{{ step.message }}
        </li>
      </ol>
    </template>
    <p v-else-if="!error && !loading">暂无原生后台任务。</p>
    <el-button :loading="loading" @click="restartObservation"
      >查询原任务状态</el-button
    >
  </section>
</template>
<style scoped>
.ids-operations {
  display: grid;
  gap: 12px;
  margin: 18px 0;
  padding: 16px;
  border: 1px solid #dce5ee;
  border-radius: 8px;
  min-width: 0;
  overflow-wrap: anywhere;
}
.ids-operations h3,
.ids-operations p {
  margin: 0;
}
.ids-operations p {
  color: #62718b;
  line-height: 1.6;
}
.ids-operations li {
  margin: 8px 0;
}
.ids-operations ol {
  padding-left: 24px;
  margin: 0;
}
</style>
