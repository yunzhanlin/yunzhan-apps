<script setup lang="ts">
import { computed, onBeforeUnmount, ref, watch } from "vue";
import { formatPanelDateTime } from "./panelTime";

type API = <T>(path: string, method?: string, body?: unknown, key?: string, signal?: AbortSignal) => Promise<T>;
type Inventory = {
  view: string;
  checked_at: string;
  rows: Record<string, string>[];
  partial: boolean;
  available: boolean;
  detail?: string;
};
const props = defineProps<{ api: API; view: string; enabled: boolean; active: boolean; sysvStartup: boolean; sshSources: boolean }>();
const columnsByView: Record<string, Record<string, string>> = {
  services: { name: "服务", load_state: "加载", active_state: "运行状态", sub_state: "子状态", description: "说明" },
  startup: { name: "服务", startup_state: "开机启动", preset: "系统预设" },
  "sysv-startup": { name: "初始化脚本", startup_state: "启动链接", runlevels: "运行级别" },
  accounts: { name: "系统账户", uid: "UID", gid: "GID", home: "主目录", shell: "登录 Shell" },
  network: { protocol: "协议", state: "状态", local: "本地端点", peer: "对端", receive_queue: "接收队列", send_queue: "发送队列" },
  cron: { source: "来源", timing: "执行时间", account: "账户" },
  ssh: { name: "账户", session: "会话", remote_host: "远端", terminal: "终端", state: "状态", started_at: "开始时间" },
};
const startupSource = ref<"systemd" | "sysv">("systemd");
const startupSources = [{ label: "systemd 服务", value: "systemd" }, { label: "SysV 初始化脚本", value: "sysv" }];
const activeView = computed(() => props.view === "startup" && props.sysvStartup && startupSource.value === "sysv"
  ? "sysv-startup" : props.view);
const columns = computed(() => activeView.value === "ssh" && props.sshSources
  ? { ...columnsByView.ssh, source: "来源" } : columnsByView[activeView.value]);
const report = ref<Inventory>();
const query = ref("");
const busy = ref(false);
const error = ref("");
let request: AbortController | undefined;
const rows = computed(() => {
  const term = query.value.trim().toLocaleLowerCase();
  const fields = Object.keys(columns.value || {});
  return report.value?.rows.filter(row => !term || fields.some(field => row[field].toLocaleLowerCase().includes(term))) ?? [];
});

async function refresh() {
  const view = activeView.value;
  const fields = columns.value;
  if (!props.active || !props.enabled || !fields || busy.value) return;
  const controller = new AbortController();
  request = controller;
  busy.value = true;
  error.value = "";
  try {
    const response = await props.api<Inventory>("/app-modules/task-manager/inventory/" + view, "GET", undefined, undefined, controller.signal);
    if (request !== controller || controller.signal.aborted) return;
    if (response.view !== view || typeof response.available !== "boolean" || typeof response.partial !== "boolean" ||
        !Number.isFinite(Date.parse(response.checked_at)) || !Array.isArray(response.rows) || response.rows.length > 256 ||
        response.rows.some(row => !row || typeof row !== "object" ||
          !Object.keys(fields).every(key => typeof row[key] === "string"))) {
      throw new Error("系统清单的来源或数据格式无法核对");
    }
    report.value = response;
  } catch (cause) {
    if (request === controller && !controller.signal.aborted) {
      report.value = undefined;
      error.value = cause instanceof Error ? cause.message : String(cause);
    }
  } finally {
    if (request === controller) {
      request = undefined;
      busy.value = false;
    }
  }
}

watch([() => props.active, () => props.enabled, activeView, () => props.sshSources], () => {
  request?.abort();
  request = undefined;
  report.value = undefined;
  query.value = "";
  error.value = "";
  busy.value = false;
  void refresh();
}, { immediate: true });
onBeforeUnmount(() => request?.abort());
</script>

<template>
  <section class="task-host-inventory" aria-label="系统清单">
    <el-alert v-if="!enabled" title="更新任务管理器至 1.3.0 后可读取此清单。" type="info" :closable="false" />
    <template v-else>
      <el-segmented v-if="view === 'startup' && sysvStartup" v-model="startupSource" :options="startupSources" aria-label="启动项来源" />
      <div class="inventory-controls">
        <el-input v-model="query" clearable aria-label="搜索清单" placeholder="搜索清单" />
        <el-button :loading="busy" @click="refresh">刷新清单</el-button>
        <span v-if="report">检查时间 {{ formatPanelDateTime(report.checked_at) }}</span>
      </div>
      <el-alert v-if="error || report?.available === false" :title="error || report?.detail || '无法读取系统清单'"
        type="warning" :closable="false" />
      <el-alert v-if="report?.partial" title="部分条目无法核对或达到读取上限，当前只显示已读到的条目。"
        type="warning" :closable="false" />
      <el-table v-if="report && (report.available || report.rows.length > 0)" :data="rows" empty-text="当前没有符合条件的记录">
        <el-table-column v-for="(label, field) in columns" :key="field" :prop="field" :label="label"
          :min-width="field === 'description' || field === 'source' ? 220 : 120" sortable />
      </el-table>
    </template>
  </section>
</template>

<style scoped>
.task-host-inventory { display: grid; gap: 12px; }
.inventory-controls { display: flex; gap: 10px; align-items: center; flex-wrap: wrap; }
.inventory-controls .el-input { width: min(100%, 19rem); }
</style>
