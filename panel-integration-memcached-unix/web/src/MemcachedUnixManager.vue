<script setup lang="ts">
import { computed, onMounted, onUnmounted, ref, watch } from "vue";
import { ElMessage, ElMessageBox } from "element-plus";
import {
  memcachedUnixVersion,
  memcachedConsoleBytes,
  validMemcachedWorkspace,
  validMemcachedControlRow,
  memcachedInputBytes,
  memcachedKeyBase64,
  memcachedValueText,
  type MemcachedWorkspace,
  type MemcachedCacheInput,
  type MemcachedCacheResult,
  type MemcachedControlRow,
} from "./memcachedUnix";
type API = <T>(
  path: string,
  method?: string,
  body?: unknown,
  key?: string,
  signal?: AbortSignal,
) => Promise<T>;
interface App {
  id: string;
  name: string;
  version: string;
  sha256: string;
  stage: string;
}
interface Site {
  id: string;
  name: string;
  status: string;
  php_version_id: string;
}
interface Project {
  id: string;
  name: string;
  template_id?: string;
  template_profile?: string;
  site_id?: string;
  state?: string;
  state_known?: boolean;
}
const props = defineProps<{
  api: API;
  actor: string;
  sites: Site[];
  fullAdmin: boolean;
}>();
const emit = defineEmits<{ changed: []; legacy: [] }>();
const visible = ref(false),
  tab = ref("instances"),
  busy = ref(false),
  reading = ref(false),
  error = ref("");
const compact = ref(false);
let media: MediaQueryList | undefined;
const measure = (e: MediaQueryListEvent) => {
  compact.value = e.matches;
};
onMounted(() => {
  media = window.matchMedia("(max-width:680px)");
  compact.value = media.matches;
  media.addEventListener("change", measure);
});
onUnmounted(() => media?.removeEventListener("change", measure));
const controlLabels: Record<string, string> = {
  start: "启动",
  stop: "停止",
  restart: "重启",
};
const application = ref<App>(),
  projects = ref<Project[]>([]),
  selected = ref(""),
  workspace = ref<MemcachedWorkspace>();
const history = ref<MemcachedControlRow[]>([]),
  historyTruncated = ref(false),
  legacyCount = ref(0);
const installSite = ref(""),
  installName = ref(""),
  installJob = ref<{ job_id: string; scope?: string }>(),
  installStatus = ref("");
const keyMode = ref("utf8"),
  valueMode = ref("utf8"),
  keyText = ref(""),
  valueText = ref(""),
  cas = ref(""),
  flags = ref(0),
  ttl = ref(0),
  valueFound = ref<boolean>(),
  cacheResult = ref<MemcachedCacheResult>(),
  statistics = ref<Record<string, string>>(),
  statisticsGroup = ref("basic");
let epoch = 0,
  abort = new AbortController(),
  lastValueMode = "utf8";
const websiteOptions = computed(() =>
  props.sites.filter(
    (s) =>
      /^[a-f0-9]{32}$/.test(s.id) &&
      ["running", "stopped"].includes(s.status) &&
      !!s.php_version_id,
  ),
);
const canWrite = computed(
  () => props.fullAdmin && !busy.value && !reading.value,
);
const pending = computed(() =>
  history.value.filter((r) => r.state !== "completed"),
);
const active = computed(
  () =>
    workspace.value?.state === "running" && workspace.value?.healthy === true,
);
function clearCache() {
  keyText.value = "";
  valueText.value = "";
  cas.value = "";
  flags.value = 0;
  ttl.value = 0;
  valueFound.value = undefined;
  cacheResult.value = undefined;
  statistics.value = undefined;
}
function closeState() {
  epoch++;
  abort.abort();
  abort = new AbortController();
  visible.value = false;
  busy.value = reading.value = false;
  workspace.value = undefined;
  history.value = [];
  projects.value = [];
  selected.value = "";
  installJob.value = undefined;
  installStatus.value = "";
  clearCache();
}
watch(() => props.actor, closeState);
onUnmounted(closeState);
watch(
  () => props.fullAdmin,
  (value) => {
    if (!value) closeState();
  },
);
watch([keyText, keyMode], () => {
  cas.value = "";
  valueFound.value = undefined;
  cacheResult.value = undefined;
});
function guardGeneration(g: number) {
  return g === epoch && visible.value;
}
function message(e: unknown) {
  return e instanceof Error ? e.message : String(e);
}
async function listRecords() {
  const records = await props.api<{
    records: MemcachedControlRow[];
    truncated: boolean;
  }>(
    "/app-registry/memcached/controls",
    "GET",
    undefined,
    undefined,
    abort.signal,
  );
  if (
    !Array.isArray(records.records) ||
    records.records.length > 100 ||
    typeof records.truncated !== "boolean" ||
    records.records.some((v) => !validMemcachedControlRow(v, props.actor)) ||
    new Set(records.records.map((v) => v.operation.request_id)).size !==
      records.records.length
  )
    throw new Error("启停原记录不完整或身份冲突，未采纳");
  return records;
}
async function inspectProject(project = selected.value) {
  if (
    !/^[a-f0-9]{32}$/.test(project) ||
    !projects.value.some((v) => v.id === project)
  )
    return;
  const value = await props.api<MemcachedWorkspace>(
    "/app-registry/memcached/instances/" + project + "/workspace",
    "POST",
    { action: "inspect" },
    undefined,
    abort.signal,
  );
  if (!validMemcachedWorkspace(value, project))
    throw new Error("原实例身份、固定隔离策略或真实运行状态不能核对");
  return value;
}
async function load() {
  if (busy.value || reading.value) return;
  const g = epoch;
  reading.value = true;
  error.value = "";
  workspace.value = undefined;
  try {
    const [result, records] = await Promise.all([
      props.api<{ projects: Project[] }>(
        "/docker/projects",
        "GET",
        undefined,
        undefined,
        abort.signal,
      ),
      listRecords(),
    ]);
    if (!guardGeneration(g)) return;
    if (!Array.isArray(result.projects) || result.projects.length > 4096)
      throw new Error("实例清单超出固定范围");
    projects.value = result.projects.filter(
      (v) =>
        v.template_id === "memcached-cache" &&
        v.template_profile === "memcached-unix-v1" &&
        /^[a-f0-9]{32}$/.test(v.id),
    );
    legacyCount.value = result.projects.filter(
      (v) =>
        v.template_id === "memcached-cache" &&
        v.template_profile !== "memcached-unix-v1",
    ).length;
    history.value = records.records;
    historyTruncated.value = records.truncated;
    if (!projects.value.some((v) => v.id === selected.value))
      selected.value = projects.value[0]?.id || "";
    if (selected.value) {
      const value = await inspectProject();
      if (guardGeneration(g)) workspace.value = value;
    }
  } catch (e) {
    if (guardGeneration(g)) error.value = message(e);
  } finally {
    if (guardGeneration(g)) reading.value = false;
  }
}
async function chooseProject() {
  if (busy.value || reading.value) return;
  const g = epoch;
  reading.value = true;
  workspace.value = undefined;
  error.value = "";
  clearCache();
  try {
    const value = await inspectProject();
    if (guardGeneration(g)) workspace.value = value;
  } catch (e) {
    if (guardGeneration(g)) error.value = message(e);
  } finally {
    if (guardGeneration(g)) reading.value = false;
  }
}
async function open(app: App, initial = "instances") {
  closeState();
  application.value = { ...app };
  visible.value = true;
  tab.value = initial;
  installName.value = "";
  installSite.value = "";
  await load();
}
function keyBase64() {
  return memcachedKeyBase64(keyText.value, keyMode.value);
}
function switchValueMode() {
  try {
    const canonical = memcachedInputBytes(
      valueText.value,
      lastValueMode,
      memcachedConsoleBytes,
    );
    valueText.value = memcachedValueText(canonical, valueMode.value);
    lastValueMode = valueMode.value;
  } catch (e) {
    valueMode.value = lastValueMode;
    ElMessage.warning(message(e));
  }
}
async function cache(action: "get" | "add" | "cas" | "delete" | "stats") {
  if (!canWrite.value || !active.value || !workspace.value || !selected.value)
    return;
  const g = epoch,
    project = selected.value;
  let input: MemcachedCacheInput;
  try {
    input = { action };
    if (action === "stats") input.stats = statisticsGroup.value;
    else input.key_base64 = keyBase64();
    if (action === "cas" || action === "delete") {
      if (
        !/^[1-9][0-9]{0,19}$/.test(cas.value) ||
        BigInt(cas.value) > 18446744073709551615n
      )
        throw new Error("先读取该键并取得原 CAS；不会执行无版本覆盖或删除");
      input.cas = cas.value;
    }
    if (action === "add" || action === "cas") {
      if (
        !Number.isInteger(ttl.value) ||
        ttl.value < 0 ||
        ttl.value === 1 ||
        ttl.value > 2592000 ||
        !Number.isInteger(flags.value) ||
        flags.value < 0 ||
        flags.value > 4294967295
      )
        throw new Error("TTL 为 0 或 2–2592000 秒；标志必须是 32 位非负整数");
      input.value_base64 = memcachedInputBytes(
        valueText.value,
        valueMode.value,
        memcachedConsoleBytes,
      );
      input.ttl_seconds = ttl.value;
      input.flags = flags.value;
    }
    if (action === "delete")
      await ElMessageBox.confirm(
        "只按当前 CAS 删除该键；若已被其他客户端更改则拒绝。不会清空整个缓存。",
        "删除当前版本",
        {
          type: "warning",
          confirmButtonText: "按原 CAS 删除",
          cancelButtonText: "取消",
        },
      );
  } catch (e) {
    if (e instanceof Error && e.message !== "cancel")
      ElMessage.warning(e.message);
    return;
  }
  if (
    !guardGeneration(g) ||
    !canWrite.value ||
    !active.value ||
    selected.value !== project
  )
    return;
  busy.value = true;
  error.value = "";
  try {
    const value = await props.api<MemcachedWorkspace>(
      "/app-registry/memcached/instances/" + project + "/workspace",
      "POST",
      { action: "cache", cache: input },
      undefined,
      abort.signal,
    );
    if (!guardGeneration(g)) return;
    if (
      !validMemcachedWorkspace(value, project) ||
      !value.cache ||
      value.cache.action !== action
    )
      throw new Error("缓存回复身份或动作不能核对；未自动重试");
    workspace.value = value;
    cacheResult.value = value.cache;
    if (action === "stats") statistics.value = value.cache.statistics || {};
    if (action === "get") {
      valueFound.value = value.cache.found;
      cas.value = value.cache.cas || "";
      flags.value = value.cache.flags || 0;
      ttl.value = value.cache.ttl_remaining < 0 ? 0 : value.cache.ttl_remaining;
      if (value.cache.found) {
        const raw = value.cache.value_base64 || "";
        try {
          valueText.value = memcachedValueText(raw, valueMode.value);
        } catch {
          valueMode.value = lastValueMode = "base64";
          valueText.value = memcachedValueText(raw, "base64");
          ElMessage.info("二进制值已使用 Base64 保真显示");
        }
      } else {
        valueText.value = "";
        cas.value = "";
      }
    } else if (action !== "stats") {
      cas.value = "";
      valueFound.value = undefined;
      ElMessage.success("该次原子操作已核对；继续修改前请重新读取 CAS");
    }
  } catch (e) {
    if (guardGeneration(g))
      error.value =
        message(e) + "。写入或删除结果不能确认时，只读核对原键，不自动重发。";
  } finally {
    if (guardGeneration(g)) busy.value = false;
  }
}
function randomRequest() {
  const bytes = crypto.getRandomValues(new Uint8Array(16));
  return Array.from(bytes, (v) => v.toString(16).padStart(2, "0")).join("");
}
async function control(action: "start" | "stop" | "restart") {
  if (
    !canWrite.value ||
    pending.value.length ||
    !workspace.value ||
    !selected.value
  )
    return;
  const g = epoch,
    original = workspace.value,
    project = selected.value;
  try {
    if (action !== "start")
      await ElMessageBox.confirm(
        "Memcached 是内存缓存。停止或重启会丢失当前缓存，不能恢复；请确保业务允许缓存重建。",
        "确认" + (action === "stop" ? "停止" : "重启"),
        {
          type: "warning",
          confirmButtonText: "确认缓存丢失并继续",
          cancelButtonText: "取消",
        },
      );
  } catch {
    return;
  }
  if (
    !guardGeneration(g) ||
    workspace.value !== original ||
    !canWrite.value ||
    pending.value.length
  )
    return;
  let key: string;
  try {
    key = randomRequest();
  } catch (e) {
    ElMessage.error("未生成原请求标识，未提交启停：" + message(e));
    return;
  }
  busy.value = true;
  error.value = "";
  try {
    const row = await props.api<MemcachedControlRow>(
      "/app-registry/memcached/instances/" + project + "/controls",
      "POST",
      {
        action,
        expected_runtime_sha256: original.runtime_sha256,
        acknowledge_cache_loss: action !== "start",
      },
      key,
      abort.signal,
    );
    if (!guardGeneration(g)) return;
    if (
      !validMemcachedControlRow(row, props.actor) ||
      row.operation.request_id !== key ||
      row.operation.project_id !== project ||
      row.operation.input.action !== action ||
      row.operation.input.expected_runtime_sha256 !== original.runtime_sha256
    )
      throw new Error("启停回执不属于该原请求");
    history.value = [
      row,
      ...history.value.filter((v) => v.operation.request_id !== key),
    ].slice(0, 100);
    workspace.value = undefined;
    clearCache();
    if (row.result?.state === "completed")
      ElMessage.success("原启停请求已完成真实状态核对");
    else if (row.result?.state === "refused")
      ElMessage.warning("原运行状态已改变；未执行启停，请刷新状态");
    else {
      error.value = "原请求 " + key + " 待核对。只查询该编号，不重发启停。";
      tab.value = "history";
    }
    emit("changed");
  } catch (e) {
    if (guardGeneration(g)) {
      workspace.value = undefined;
      error.value =
        message(e) + "。原请求：" + key + "；仅刷新并查询原记录，不自动重发。";
      tab.value = "history";
    }
  } finally {
    if (guardGeneration(g)) busy.value = false;
  }
  if (guardGeneration(g)) await load();
}
async function observe(row: MemcachedControlRow, close = false) {
  if (!canWrite.value || !validMemcachedControlRow(row, props.actor)) return;
  const g = epoch,
    op = row.operation;
  if (close) {
    try {
      await ElMessageBox.confirm(
        "仅在执行器能证明原请求没有发出原生命令时关闭。已发出或结果未知的命令不会重放、回滚或删除。",
        "关闭尚未执行的原请求",
        {
          type: "warning",
          confirmButtonText: "核对并关闭未执行请求",
          cancelButtonText: "取消",
        },
      );
    } catch {
      return;
    }
  }
  busy.value = true;
  error.value = "";
  try {
    const value = await props.api<MemcachedControlRow>(
      "/app-registry/memcached/instances/" +
        op.project_id +
        "/controls/" +
        op.request_id +
        (close ? "/close" : ""),
      close ? "POST" : "GET",
      close ? {} : undefined,
      undefined,
      abort.signal,
    );
    if (!guardGeneration(g)) return;
    if (
      !validMemcachedControlRow(value, props.actor) ||
      JSON.stringify(value.operation) !== JSON.stringify(op)
    )
      throw new Error("回复不属于原启停操作");
    history.value = history.value.map((v) =>
      v.operation.request_id === op.request_id ? value : v,
    );
  } catch (e) {
    if (guardGeneration(g)) error.value = message(e);
  } finally {
    if (guardGeneration(g)) busy.value = false;
  }
}
async function install() {
  const app = application.value;
  if (
    !canWrite.value ||
    !app ||
    app.version !== memcachedUnixVersion ||
    app.stage !== "ready" ||
    pending.value.length ||
    installJob.value
  )
    return;
  const g = epoch;
  if (
    installName.value.trim() &&
    !/^[A-Za-z0-9][A-Za-z0-9_.-]{0,39}$/.test(installName.value.trim())
  ) {
    ElMessage.warning(
      "名称须为 1–40 个字母、数字、点、横线或下划线，并以字母或数字开头",
    );
    return;
  }
  if (
    installSite.value &&
    !websiteOptions.value.some((v) => v.id === installSite.value)
  ) {
    ElMessage.warning("该网站不再具有活动 PHP 绑定");
    return;
  }
  try {
    await ElMessageBox.confirm(
      "将验签并安装固定摘要镜像，以专用非 root 账户通过 Unix Socket 运行；不开放 TCP/UDP。网站模式只复用已有 PHP 网站账户，不创建或接管网站账户。",
      "安装 Memcached Socket 实例",
      {
        confirmButtonText: "验签并安装",
        cancelButtonText: "取消",
        type: "info",
      },
    );
  } catch {
    return;
  }
  busy.value = true;
  error.value = "";
  try {
    const result = await props.api<{ job_id: string; scope?: string }>(
      "/app-registry/memcached/install",
      "POST",
      {
        expected_version: app.version,
        expected_sha256: app.sha256,
        ...(installName.value ? { name: installName.value } : {}),
        settings: { site_id: installSite.value },
      },
      undefined,
      abort.signal,
    );
    if (!guardGeneration(g)) return;
    if (!result || !/^[a-f0-9]{32}$/.test(result.job_id))
      throw new Error(
        "没有可核对的原安装任务；请到应用商店查询原请求，不重复安装",
      );
    installJob.value = result;
    installStatus.value = "已提交原安装任务；尚未确认安装成功";
    emit("changed");
  } catch (e) {
    if (guardGeneration(g))
      error.value =
        message(e) + "。请先核对应用商店保留的原安装请求，不重复点击安装。";
  } finally {
    if (guardGeneration(g)) busy.value = false;
  }
}
async function checkInstallation() {
  if (!installJob.value || !canWrite.value) return;
  const g = epoch,
    key = installJob.value.job_id;
  reading.value = true;
  error.value = "";
  try {
    const value = await props.api<{
      app_id: string;
      job_id: string;
      provider: string;
      version: string;
      state_known: boolean;
      state: string;
    }>(
      "/app-registry/memcached/installs/" + key,
      "GET",
      undefined,
      undefined,
      abort.signal,
    );
    if (!guardGeneration(g)) return;
    if (
      value.app_id !== "memcached" ||
      value.job_id !== key ||
      value.provider !== "compose" ||
      value.version !== memcachedUnixVersion ||
      typeof value.state_known !== "boolean" ||
      ![
        "unknown",
        "queued",
        "running",
        "succeeded",
        "failed",
        "needs_attention",
      ].includes(value.state)
    )
      throw new Error("安装回执身份不能核对");
    installStatus.value = value.state_known
      ? (
          {
            queued: "原安装已保留",
            running: "原安装执行中",
            succeeded: "原安装已完成；请刷新核对当前真实健康状态",
            failed: "原安装失败；保留原记录，不重发",
            needs_attention: "原安装结果需要处理；未重放或删除证据",
          } as Record<string, string>
        )[value.state] || "原结果待核对"
      : "原结果待核对；不推断安装成功";
    if (value.state_known && value.state === "succeeded") emit("changed");
  } catch (e) {
    if (guardGeneration(g)) error.value = message(e);
  } finally {
    if (guardGeneration(g)) reading.value = false;
  }
}
defineExpose({ open });
</script>

<template>
  <el-dialog
    v-model="visible"
    class="memcached-unix-dialog"
    title="Memcached · 缓存管理"
    top="5vh"
    width="min(1120px, 96vw)"
    :close-on-click-modal="false"
    @closed="closeState"
  >
    <div class="workspace-intro">
      <div>
        <strong>独立 Unix Socket 实例</strong>
        <p>非 root 进程 · 固定摘要镜像 · 不开放 TCP/UDP · 缓存重启即失效</p>
      </div>
      <el-tag type="info">1.6.45 · 兼容包 4</el-tag>
    </div>
    <el-alert
      v-if="!fullAdmin"
      type="warning"
      title="需要当前完整主机管理员权限；受限角色不能通过此页读取或修改缓存。"
      :closable="false"
    />
    <el-alert
      v-if="error"
      class="workspace-alert"
      type="error"
      :title="error"
      :closable="false"
      show-icon
    />
    <div class="workspace-toolbar">
      <el-select
        v-model="selected"
        aria-label="选择 Socket 缓存实例"
        placeholder="选择已安装实例"
        :disabled="busy || reading"
        @change="chooseProject"
        ><el-option
          v-for="p in projects"
          :key="p.id"
          :label="p.name || p.id"
          :value="p.id" /></el-select
      ><el-button :loading="reading" :disabled="busy" @click="load"
        >刷新真实状态</el-button
      ><el-button
        v-if="application?.version === '1.6.45-compat4'"
        @click="tab = 'install'"
        >新增实例</el-button
      >
    </div>
    <el-tabs v-model="tab">
      <el-tab-pane label="实例状态" name="instances">
        <el-empty
          v-if="!workspace"
          :description="
            selected
              ? '运行状态尚未确认；不显示健康或执行启停'
              : '尚无 Socket 实例'
          "
        />
        <template v-else>
          <div class="instance-summary">
            <strong>{{ workspace.name }}</strong
            ><el-tag :type="active ? 'success' : 'info'">{{
              active
                ? "运行中 · 已核对真实进程与 Socket"
                : "已停止 · 缓存不持久化"
            }}</el-tag>
          </div>
          <el-descriptions :column="compact ? 1 : 2" border
            ><el-descriptions-item label="归属">{{
              workspace.site_id
                ? sites.find((s) => s.id === workspace?.site_id)?.name ||
                  workspace.site_id
                : "管理员专用账户"
            }}</el-descriptions-item
            ><el-descriptions-item label="网络"
              >none · 无 TCP/UDP 端口</el-descriptions-item
            ><el-descriptions-item label="缓存容量">128 MB</el-descriptions-item
            ><el-descriptions-item label="进程内存上限"
              >192 MB · 禁用 swap</el-descriptions-item
            ><el-descriptions-item label="单项服务上限"
              >4 MB</el-descriptions-item
            ><el-descriptions-item label="面板编辑上限"
              >48 KB（超限拒绝，不截断）</el-descriptions-item
            ><el-descriptions-item label="主机 Socket" :span="compact ? 1 : 2"
              ><code>{{ workspace.socket_path }}</code></el-descriptions-item
            ></el-descriptions
          >
          <div class="instance-actions">
            <el-button
              v-if="!active"
              type="success"
              :disabled="!canWrite || pending.length > 0"
              @click="control('start')"
              >启动</el-button
            ><el-button
              v-if="active"
              type="warning"
              :disabled="!canWrite || pending.length > 0"
              @click="control('restart')"
              >重启（清空缓存）</el-button
            ><el-button
              v-if="active"
              :disabled="!canWrite || pending.length > 0"
              @click="control('stop')"
              >停止（清空缓存）</el-button
            >
          </div>
          <el-alert
            v-if="pending.length"
            type="warning"
            title="存在尚未结算的原启停请求。先在操作记录中核对；不能换编号重复执行。"
            :closable="false"
          />
        </template>
      </el-tab-pane>
      <el-tab-pane label="运行统计" name="stats" lazy>
        <div class="workspace-toolbar">
          <el-select v-model="statisticsGroup" aria-label="统计分组"
            ><el-option label="基础统计" value="basic" /><el-option
              label="服务设置"
              value="settings" /><el-option
              label="缓存项分组"
              value="items" /><el-option
              label="Slab 分配"
              value="slabs" /></el-select
          ><el-button :disabled="!canWrite || !active" @click="cache('stats')"
            >读取真实统计</el-button
          >
        </div>
        <p class="muted">
          只读取固定统计分组，不重置计数、不触发全量键转储、不执行 flush。
        </p>
        <el-table
          v-if="statistics"
          :data="
            Object.entries(statistics).map(([name, value]) => ({ name, value }))
          "
          max-height="420"
          ><el-table-column
            prop="name"
            label="指标"
            min-width="220" /><el-table-column
            prop="value"
            label="当前值"
            min-width="220" /></el-table
        ><el-empty v-else description="选择分组后读取，不使用模拟统计" />
      </el-tab-pane>
      <el-tab-pane label="缓存读写" name="cache" lazy>
        <el-alert
          type="info"
          title="新增仅在键不存在时成功；修改和删除都要求刚读取的 CAS。不会执行无条件覆盖或清空整个缓存。"
          :closable="false"
        />
        <p class="muted">
          普通无分隔字节键最多250字节；固定1.6.45协议中，含空白或控制字节的二进制键最多186字节。超限只明确拒绝，不截断或改名。
        </p>
        <el-form label-position="top" class="cache-form">
          <div class="cache-row">
            <el-form-item label="键的编码"
              ><el-select v-model="keyMode" aria-label="键编码" :disabled="busy"
                ><el-option label="UTF-8 文本" value="utf8" /><el-option
                  label="Base64（二进制键）"
                  value="base64" /></el-select></el-form-item
            ><el-form-item label="缓存键（解码后 1–250 字节）" class="cache-key"
              ><el-input
                v-model="keyText"
                aria-label="缓存键"
                :disabled="busy"
                maxlength="1000"
                autocomplete="off" /></el-form-item
            ><el-button :disabled="!canWrite || !active" @click="cache('get')"
              >读取当前值 / CAS</el-button
            >
          </div>
          <div v-if="valueFound !== undefined" class="cache-read-state">
            {{ valueFound ? "已找到该键" : "键不存在" }}
            <span v-if="cas"
              >· CAS：<code>{{ cas }}</code></span
            ><span v-if="cacheResult?.stale"> · 该项被标记为过期候选</span>
          </div>
          <el-form-item label="值的编码"
            ><el-select
              v-model="valueMode"
              aria-label="值编码"
              :disabled="busy"
              @change="switchValueMode"
              ><el-option label="UTF-8 文本" value="utf8" /><el-option
                label="Base64（字节保真）"
                value="base64" /></el-select
          ></el-form-item>
          <el-form-item
            label="缓存值（最多 48 KB 解码字节；不保存到浏览器存储）"
            ><el-input
              v-model="valueText"
              aria-label="缓存值"
              type="textarea"
              :rows="7"
              :disabled="busy"
              maxlength="65536"
              autocomplete="off"
          /></el-form-item>
          <div class="cache-row">
            <el-form-item label="TTL 秒（0 为不设置到期）"
              ><el-input-number
                v-model="ttl"
                :min="0"
                :max="2592000"
                :precision="0"
                :disabled="busy" /></el-form-item
            ><el-form-item label="32 位应用标志"
              ><el-input-number
                v-model="flags"
                :min="0"
                :max="4294967295"
                :precision="0"
                :disabled="busy"
            /></el-form-item>
          </div>
          <div class="instance-actions">
            <el-button :disabled="!canWrite || !active" @click="cache('add')"
              >仅新增不存在的键</el-button
            ><el-button
              type="primary"
              :disabled="!canWrite || !active || !cas"
              @click="cache('cas')"
              >按原 CAS 保存</el-button
            ><el-button
              type="danger"
              plain
              :disabled="!canWrite || !active || !cas"
              @click="cache('delete')"
              >按原 CAS 删除</el-button
            ><el-button :disabled="busy" @click="clearCache"
              >清除本页输入</el-button
            >
          </div>
        </el-form>
      </el-tab-pane>
      <el-tab-pane label="操作记录" name="history" lazy>
        <p class="muted">
          记录来自服务器数据库。核对只读取原回执，不重新提交原生命令；历史成功不代表当前服务健康。
        </p>
        <el-table
          :data="history"
          row-key="operation.request_id"
          max-height="420"
          ><el-table-column label="原请求" min-width="210"
            ><template #default="{ row }"
              ><code>{{ row.operation.request_id }}</code></template
            ></el-table-column
          ><el-table-column label="实例" min-width="180"
            ><template #default="{ row }">{{
              projects.find((p) => p.id === row.operation.project_id)?.name ||
              row.operation.project_id
            }}</template></el-table-column
          ><el-table-column label="动作" width="80"
            ><template #default="{ row }">{{
              controlLabels[row.operation.input.action]
            }}</template></el-table-column
          ><el-table-column label="记录状态" width="140"
            ><template #default="{ row }">{{
              row.result?.state === "completed"
                ? "已核对完成"
                : row.result?.state === "refused"
                  ? "未执行 / 已关闭"
                  : row.state === "reserved"
                    ? "原请求已保留"
                    : "原结果待核对"
            }}</template></el-table-column
          ><el-table-column label="操作" min-width="225"
            ><template #default="{ row }"
              ><el-button :disabled="!canWrite" @click="observe(row)"
                >只核对原请求</el-button
              ><el-button
                v-if="row.state !== 'completed'"
                :disabled="!canWrite"
                @click="observe(row, true)"
                >关闭未执行请求</el-button
              ></template
            ></el-table-column
          ></el-table
        >
        <p v-if="historyTruncated" class="muted">
          显示最近 100 条，待核对记录优先。旧回执仍保留在服务器。
        </p>
      </el-tab-pane>
      <el-tab-pane label="连接与隔离" name="connection">
        <p>
          网站模式只允许该网站现有 PHP 账户访问专属目录；管理员模式的 Socket
          不能供其他网站直接连接。面板不会替其他账户放宽目录权限。
        </p>
        <p>
          这里显示的是服务器主机上的 Socket
          路径，不是网址，也不需要绑定域名。业务客户端必须支持 Unix Socket；PHP
          客户端还需要对应缓存扩展，未安装的扩展不会在此被假定存在。
        </p>
        <p>
          缓存值是临时数据。停止、重启、容器重建或主机重启都可能使缓存丢失；请让业务具备回源和缓存重建能力。
        </p>
        <el-alert
          v-if="legacyCount"
          type="warning"
          :title="
            '另有 ' +
            legacyCount +
            ' 个旧版 TCP/其他配置实例。不会自动迁移、接管或卸载。'
          "
          :closable="false"
        /><el-button
          v-if="legacyCount"
          class="legacy-button"
          @click="emit('legacy')"
          >查看旧版原更新记录</el-button
        >
      </el-tab-pane>
      <el-tab-pane label="安装实例" name="install" lazy>
        <el-alert
          type="info"
          title="仅支持已签名的 Socket 兼容包 4。此安装不要求端口，也不接受自定义 UID、镜像或命令。"
          :closable="false"
        />
        <el-form label-position="top" class="install-form"
          ><el-form-item label="实例名称（可留空自动生成）"
            ><el-input
              v-model="installName"
              maxlength="40"
              :disabled="busy || !!installJob"
              placeholder="例如 site-cache" /></el-form-item
          ><el-form-item label="实例归属"
            ><el-select
              v-model="installSite"
              :disabled="busy || !!installJob"
              aria-label="实例归属"
              ><el-option label="管理员专用账户（非网站）" value="" /><el-option
                v-for="site in websiteOptions"
                :key="site.id"
                :label="site.name + ' · ' + site.php_version_id"
                :value="site.id" /></el-select></el-form-item
          ><el-button
            type="primary"
            :disabled="
              !canWrite ||
              application?.version !== '1.6.45-compat4' ||
              pending.length > 0 ||
              !!installJob
            "
            @click="install"
            >验签并安装 Socket 实例</el-button
          ></el-form
        >
        <section v-if="installJob" aria-live="polite">
          <p>
            原安装任务：<code>{{ installJob.job_id }}</code>
          </p>
          <p>{{ installStatus }}</p>
          <el-button :disabled="!canWrite" @click="checkInstallation"
            >只核对原安装任务</el-button
          >
        </section>
      </el-tab-pane>
    </el-tabs>
    <template #footer
      ><span class="muted">关闭窗口不撤销已发出的操作；请查询原请求。</span
      ><el-button @click="visible = false">关闭</el-button></template
    >
  </el-dialog>
</template>

<style>
.memcached-unix-dialog .el-dialog__body {
  max-height: calc(88dvh - 110px);
  overflow: auto;
  scrollbar-gutter: stable;
  overscroll-behavior: contain;
}
</style>
<style scoped>
.workspace-intro,
.workspace-toolbar,
.instance-summary,
.instance-actions,
.cache-row {
  display: flex;
  align-items: center;
  gap: 12px;
}
.workspace-intro {
  justify-content: space-between;
  margin-bottom: 18px;
}
.workspace-intro strong {
  font-size: 18px;
}
.workspace-intro p,
.muted {
  color: var(--el-text-color-secondary);
  line-height: 1.65;
}
.workspace-toolbar {
  margin: 18px 0;
}
.workspace-toolbar > .el-select {
  min-width: 200px;
  flex: 1;
}
.workspace-alert {
  margin: 12px 0;
}
.instance-summary {
  margin: 8px 0 18px;
  flex-wrap: wrap;
}
.instance-actions {
  margin: 18px 0;
  flex-wrap: wrap;
}
.cache-form,
.install-form {
  margin-top: 20px;
}
.install-form {
  max-width: 560px;
}
.install-form .el-select {
  width: 100%;
}
.cache-row {
  align-items: flex-end;
  flex-wrap: wrap;
}
.cache-key {
  flex: 1;
  min-width: 220px;
}
.cache-row > .el-button {
  margin-bottom: 18px;
}
.cache-read-state {
  margin: 0 0 18px;
  color: var(--el-text-color-secondary);
}
.legacy-button {
  margin-top: 14px;
}
code {
  overflow-wrap: anywhere;
  font-size: 12px;
}
.el-dialog__footer .muted {
  margin-right: 16px;
}
@media (max-width: 680px) {
  .workspace-intro,
  .workspace-toolbar,
  .cache-row {
    align-items: stretch;
    flex-direction: column;
  }
  .workspace-toolbar > .el-select {
    width: 100%;
  }
  .workspace-intro .el-tag {
    align-self: flex-start;
  }
  .cache-key {
    min-width: 0;
  }
  .cache-row > .el-button {
    margin-bottom: 0;
  }
  .instance-actions > .el-button {
    margin-left: 0;
  }
  .workspace-intro p {
    margin-bottom: 0;
  }
}
</style>
