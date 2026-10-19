<script setup lang="ts">
import { formatPanelDateTime } from "./panelTime";
import { apiURL } from "./panelBase";
import { computed, onMounted, onUnmounted, ref, watch } from "vue";
import { ElMessage, ElMessageBox } from "element-plus";
import { Coin, WarningFilled } from "@element-plus/icons-vue";
import { siMysql, siRedis } from "simple-icons";
import DatabaseImportManager from "./DatabaseImportManager.vue";
import DatabaseAccountManager from "./DatabaseAccountManager.vue";
import DatabaseLifecycleDialog from "./DatabaseLifecycleDialog.vue";
interface Server {
  id: string;
  name: string;
  release_id: string;
  port: number;
  status: string;
  created_at: string;
}
interface Database {
  revision: number;
  id: string;
  server_id: string;
  name: string;
  username: string;
  status: string;
  created_at: string;
  engine?: "mysql" | "redis";
  redis_index?: number;
  redis_keys?: number;
}
interface RedisInstance { id: string; name: string; status: string; created_at: string; clients?: number; used_memory?: number; logical_dbs?: { index: number; keys: number }[] }
interface ConnectionSample { at: number; mysql: number | null; redis: number | null }
interface BackupJob { id: string; kind: string; state: string; database_name?: string; site_name?: string; backup_bytes?: number; error?: string; created_at: string; updated_at: string }
interface Backup {
  id: string;
  database_id: string;
  server_id: string;
  version: string;
  bytes: number;
  sha256: string;
  created_at: string;
}
interface Actual {
  id: string;
  service_state: string;
  authenticated?: boolean;
  version?: string;
  socket: string;
  data_dir: string;
  system_user: string;
}
interface Metric {
  server_id: string;
  name: string;
  bytes: number;
  charset: string;
}
interface Data {
  servers: Server[];
  databases: Database[];
  backups: Backup[];
  actual: { servers: Actual[] };
}
const props = defineProps<{
  csrf: string;
  api: <T>(path: string, method?: string, body?: unknown) => Promise<T>;
  installed: { id: string; family: string; version: string; status: string }[];
  onJob: (id: string) => Promise<void>;
  openRedis: (instanceID?: string, db?: number) => void;
}>();
const openRedis = (instanceID?: string, db?: number) => props.openRedis(instanceID, db);
const data = ref<Data>({
    servers: [],
    databases: [],
    backups: [],
    actual: { servers: [] },
  }),
  error = ref(""),
  loading = ref(false),
  submitting = ref(false);
const redisInstances = ref<RedisInstance[]>([]);
const databaseMetrics = ref<Metric[]>([]);
const backupJobs = ref<BackupJob[]>([]);
const backupJobsReady = ref(false);
const backupJobsOpen = ref(false);
const storageDetailsOpen = ref(false);
const recentBackupJobs = computed(() => backupJobs.value.slice(0, 4));
const backupJobLabel = (state: string) => ({ succeeded: "备份成功", failed: "备份失败", needs_attention: "待核对", queued: "排队中", running: "执行中" })[state] || state;
async function openBackupJob(job: BackupJob) {
  backupJobsOpen.value = false;
  await props.onJob(job.id);
}
let metricsLoadedAt = 0;
let connectionsLoadedAt = 0;
let connectionHistoryLoadedAt = 0;
const mysqlConnections = ref<{ server_id: string; clients: number }[]>([]);
const mysqlConnectionsReady = ref(false);
const redisConnectionsReady = ref(false);
const connectionSamples = ref<ConnectionSample[]>([]);
const connectionHistoryReady = ref(false);
const connectionHoverIndex = ref<number | null>(null);
const hoveredConnection = computed(() => connectionHoverIndex.value === null ? null : connectionSamples.value[connectionHoverIndex.value] || null);
const currentMySQLConnections = computed(() => mysqlConnections.value.reduce((sum, item) => sum + item.clients, 0));
const currentRedisConnections = computed(() => redisInstances.value.filter((item) => item.status === "running").reduce((sum, item) => sum + (item.clients || 0), 0));
const mysqlUsedBytes = computed(() => databaseMetrics.value.reduce((sum, item) => sum + Math.max(0, item.bytes), 0));
const redisUsedBytes = computed(() => redisInstances.value.filter((item) => item.status === "running").reduce((sum, item) => sum + Math.max(0, item.used_memory || 0), 0));
const databaseUsedBytes = computed(() => mysqlUsedBytes.value + redisUsedBytes.value);
const mysqlUsedPercent = computed(() => databaseUsedBytes.value ? Math.round(mysqlUsedBytes.value / databaseUsedBytes.value * 100) : 0);
const connectionMax = computed(() => Math.max(4, ...connectionSamples.value.flatMap((item) => [item.mysql, item.redis].filter((value): value is number => value !== null))) * 1.15);
const connectionX = (index: number) => Math.max(0, Math.min(100, (connectionSamples.value[index].at - (Date.now() - 24 * 60 * 60 * 1000)) / (24 * 60 * 60 * 1000) * 100));
function connectionSeries(kind: "mysql" | "redis") {
  const segments: { points: string; single: boolean; x: number; y: number }[] = [];
  let current: string[] = [];
  let previousAt = 0;
  const flush = () => {
    if (current.length) {
      const [x, y] = current[0].split(",").map(Number);
      segments.push({ points: current.join(" "), single: current.length === 1, x, y });
    }
    current = [];
  };
  connectionSamples.value.forEach((item, index) => {
    if (item[kind] === null || (previousAt && item.at - previousAt > 90_000)) flush();
    if (item[kind] !== null) current.push(`${connectionX(index).toFixed(2)},${(100 - item[kind] / connectionMax.value * 100).toFixed(2)}`);
    previousAt = item.at;
  });
  flush();
  return segments;
}
function connectionHover(event: PointerEvent) {
  if (!connectionSamples.value.length) return;
  const rect = (event.currentTarget as SVGElement).getBoundingClientRect();
  const at = Date.now() - 24 * 60 * 60 * 1000 + Math.max(0, Math.min(1, (event.clientX - rect.left) / rect.width)) * 24 * 60 * 60 * 1000;
  connectionHoverIndex.value = connectionSamples.value.reduce((best, item, index) =>
    Math.abs(item.at - at) < Math.abs(connectionSamples.value[best].at - at) ? index : best, 0);
}
function connectionKey(event: KeyboardEvent) {
  if (!connectionSamples.value.length) return;
  if (!["ArrowLeft", "ArrowRight", "Home", "End"].includes(event.key)) return;
  event.preventDefault();
  const last = connectionSamples.value.length - 1;
  if (event.key === "Home") connectionHoverIndex.value = 0;
  else if (event.key === "End") connectionHoverIndex.value = last;
  else connectionHoverIndex.value = Math.max(0, Math.min(last, (connectionHoverIndex.value ?? last) + (event.key === "ArrowLeft" ? -1 : 1)));
}
const metricFor = (db: Database) => databaseMetrics.value.find((metric) => metric.server_id === db.server_id && metric.name === db.name);
const databaseSearch = ref("");
const databaseType = ref("all");
const selectedDatabases = ref<Database[]>([]);
const bulkAction = ref("backup");
const instanceOpen = ref(false),
  databaseOpen = ref(false),
  credentialsOpen = ref(false),
  credentials = ref<Record<string, string>>({});
const instance = ref({ name: "", release_id: "", port: 13306 }),
  database = ref({ server_id: "", name: "" });
const migrationOpen = ref(false),
  migrationSource = ref<Database | null>(null),
  migrationTarget = ref(""),
  migrationConfirm = ref("");
const migrationTargets = computed(() =>
  data.value.servers.filter(
    (s) =>
      s.release_id === "mysql-8.4.11" &&
      running(s.id) &&
      !data.value.databases.some(
        (d) => d.server_id === s.id && d.name === migrationSource.value?.name,
      ),
  ),
);
function openMigration(db: Database) {
  migrationSource.value = db;
  migrationTarget.value = "";
  migrationConfirm.value = "";
  migrationOpen.value = true;
}
async function migrate() {
  if (!migrationSource.value) return;
  const ok = await submit(
    `/databases/items/${migrationSource.value.id}/migrate`,
    {
      target_id: migrationTarget.value,
      confirm_name: migrationConfirm.value,
    },
  );
  if (ok) migrationOpen.value = false;
}
const mysqlVersions = computed(() =>
  props.installed.filter(
    (x) => x.family === "mysql" && x.status === "installed",
  ),
);
const importManager = ref<InstanceType<typeof DatabaseImportManager>>();
const lifecycle = ref<InstanceType<typeof DatabaseLifecycleDialog>>(),
  databaseScope = ref("active");
watch(databaseScope, () => {
  databasePage.value = 1;
});
watch([databaseSearch, databaseType], () => { databasePage.value = 1; });
async function lifecycleChanged(scope: string) {
  databaseScope.value = scope;
  databasePage.value = 1;
  await refresh();
}
async function databaseJob(db: Database) {
  try {
    const j = await props.api<{ job_id: string }>(
      `/databases/items/${db.id}/latest-job`,
    );
    await props.onJob(j.job_id);
  } catch (e) {
    ElMessage.error((e as Error).message);
  }
}
const databaseStatus = (status: string) =>
  ({
    ready: "可用",
    stopped: "已停止",
    creating: "创建中",
    importing: "导入中",
    migrating: "迁移中",
    needs_attention: "待核对",
    quarantined: "已回收",
    updating: "操作中",
  })[status] || status;
function backupSize(value: number) {
  const units = ["B", "KiB", "MiB", "GiB"];
  let index = 0;
  while (value >= 1024 && index < units.length - 1) {
    value /= 1024;
    index++;
  }
  return value.toFixed(index ? 1 : 0) + " " + units[index];
}
const backupPage = ref(1),
  databasePage = ref(1);
const databasePageSize = 8;
const redisDatabases = computed<Database[]>(() => redisInstances.value.flatMap((instance) => (instance.logical_dbs || [{ index: 0, keys: 0 }]).map((logical) => ({
  id: `redis-${instance.id}-${logical.index}`, server_id: instance.id, name: `${instance.name} / db${logical.index}`,
  username: "—", status: instance.status === "running" ? "ready" : instance.status, created_at: instance.created_at,
  revision: 0, engine: "redis", redis_index: logical.index, redis_keys: logical.keys,
}))));
const totalDatabaseCount = computed(() => activeDatabases.value.length + redisDatabases.value.length);
const healthyDatabaseCount = computed(() => readyDatabases.value.length + redisDatabases.value.filter((db) => db.status === "ready").length);
const filteredDatabases = computed(() =>
  [...data.value.databases, ...(databaseScope.value === "trash" ? [] : redisDatabases.value)].filter((d) =>
    (databaseScope.value === "trash" ? d.status === "quarantined" : d.status !== "quarantined") &&
    (databaseType.value === "all" || databaseType.value === (d.engine || "mysql")) &&
    `${d.name} ${d.username} ${sourceName(d)}`.toLowerCase().includes(databaseSearch.value.trim().toLowerCase()),
  ),
);
const visibleDatabases = computed(() =>
  filteredDatabases.value
    .slice()
    .reverse()
    .slice((databasePage.value - 1) * databasePageSize, databasePage.value * databasePageSize),
);
const visibleBackups = computed(() =>
  data.value.backups.slice((backupPage.value - 1) * 5, backupPage.value * 5),
);
const actual = (id: string) =>
  data.value.actual.servers.find((s) => s.id === id);
const serverName = (id: string) =>
  data.value.servers.find((s) => s.id === id)?.name || id;
const sourceName = (db: Database) => db.engine === "redis" ? redisInstances.value.find((item) => item.id === db.server_id)?.name || db.server_id : serverName(db.server_id);
const dbName = (id: string) =>
  data.value.databases.find((s) => s.id === id)?.name || id;
const storageRows = computed(() => [
  ...databaseMetrics.value.map((metric) => ({
    id: `mysql-${metric.server_id}-${metric.name}`,
    name: metric.name,
    source: `MySQL · ${serverName(metric.server_id)}`,
    bytes: Math.max(0, metric.bytes),
  })),
  ...redisInstances.value.filter((instance) => instance.status === "running").map((instance) => ({
    id: `redis-${instance.id}`,
    name: instance.name,
    source: "Redis 实例",
    bytes: Math.max(0, instance.used_memory || 0),
  })),
].sort((a, b) => b.bytes - a.bytes));
const latestBackup = (id: string) =>
  data.value.backups.filter((backup) => backup.database_id === id).reduce((latest, backup) => !latest || backup.created_at > latest ? backup.created_at : latest, "");
const activeDatabases = computed(() => data.value.databases.filter((db) => db.status !== "quarantined"));
const readyDatabases = computed(() => activeDatabases.value.filter((db) => db.status === "ready"));
const running = (id: string) =>
  actual(id)?.service_state === "active" && actual(id)?.authenticated;
let timer: ReturnType<typeof setInterval>;
async function refresh() {
  if (loading.value) return;
  loading.value = true;
  try {
    data.value = await props.api<Data>("/databases");
    try {
      backupJobs.value = await props.api<BackupJob[]>("/databases/backup-jobs");
      backupJobsReady.value = true;
    } catch {
      backupJobs.value = [];
      backupJobsReady.value = false;
    }
    if (Date.now() - metricsLoadedAt > 60000) {
      metricsLoadedAt = Date.now();
      try { databaseMetrics.value = (await props.api<{ metrics: Metric[] }>("/databases/metrics")).metrics; }
      catch { databaseMetrics.value = []; }
    }
    try {
      redisInstances.value = (await props.api<{ instances: RedisInstance[] }>("/redis/instances")).instances;
      redisConnectionsReady.value = !redisInstances.value.some((item) => item.status === "needs_attention");
    } catch {
      redisInstances.value = [];
      redisConnectionsReady.value = false;
    }
    if (Date.now() - connectionsLoadedAt > 14000) {
      connectionsLoadedAt = Date.now();
      try {
        const result = await props.api<{ sampled_at: string; connections: { server_id: string; clients: number }[] }>("/databases/connections");
        mysqlConnections.value = result.connections;
        const runningServers = data.value.servers.filter((server) => server.status === "running");
        mysqlConnectionsReady.value = data.value.servers.every((server) => server.status === "running" || server.status === "stopped") &&
          runningServers.length === result.connections.length && result.connections.every((item) => runningServers.some((server) => server.id === item.server_id));
      } catch {
        mysqlConnections.value = [];
        mysqlConnectionsReady.value = false;
      }
    }
    if (Date.now() - connectionHistoryLoadedAt > 55000) {
      connectionHistoryLoadedAt = Date.now();
      try {
        const history = await props.api<{ samples: { sampled_at: number; mysql: number | null; redis: number | null }[] }>("/databases/connections/history");
        connectionSamples.value = history.samples.map((item) => ({ at: item.sampled_at * 1000, mysql: item.mysql, redis: item.redis }));
        connectionHistoryReady.value = true;
      } catch {
        connectionHistoryReady.value = false;
      }
    }
    error.value = "";
  } catch (e) {
    error.value = (e as Error).message;
  } finally {
    loading.value = false;
  }
}
async function submit(path: string, body: unknown = {}) {
  submitting.value = true;
  try {
    const j = await props.api<{ job_id: string }>(path, "POST", body);
    instanceOpen.value = false;
    databaseOpen.value = false;
    await refresh();
    await props.onJob(j.job_id);
    return true;
  } catch (e) {
    ElMessage.error((e as Error).message);
    return false;
  } finally {
    submitting.value = false;
  }
}
function newInstance() {
  const preferred = mysqlVersions.value.find((release) => release.id.startsWith("mysql-8.4")) || mysqlVersions.value[0];
  if (!preferred) return;
  const used = data.value.servers.map((x) => x.port);
  let port = 13306;
  while (used.includes(port)) port++;
  instance.value = { name: "", release_id: preferred.id, port };
  instanceOpen.value = true;
}
function newDatabase() {
  databaseScope.value = "active";
  databasePage.value = 1;
  database.value = {
    server_id: data.value.servers.find((x) => running(x.id))?.id || "",
    name: "",
  };
  databaseOpen.value = true;
}
function openImport() { importManager.value?.begin(); }
function openPermissions() { document.querySelector(".database-account-section")?.scrollIntoView({ behavior: "smooth", block: "start" }); }
defineExpose({ newDatabase, openImport, openPermissions, refresh });
function databaseCommand(db: Database, command: string) {
  if (command === "credentials") void showCredentials(db);
  else if (command === "backup") void submit(`/databases/items/${db.id}/backup`);
  else if (command === "overwrite") importManager.value?.beginOverwrite(db);
  else if (command === "migrate") openMigration(db);
  else if (command === "lifecycle") lifecycle.value?.begin(db);
  else if (command === "job") void databaseJob(db);
}
async function runBulkAction() {
  const selected = selectedDatabases.value.filter((db) => db.status === "ready" && running(db.server_id));
  if (bulkAction.value !== "backup" || !selected.length) return;
  try {
    await ElMessageBox.confirm(`为选中的 ${selected.length} 个数据库创建备份？`, "批量备份", { confirmButtonText: "开始备份", cancelButtonText: "取消" });
    for (const db of selected) await props.api(`/databases/items/${db.id}/backup`, "POST", {});
    selectedDatabases.value = [];
    ElMessage.success(`已提交 ${selected.length} 个数据库备份任务`);
    await refresh();
  } catch (error) {
    if (error instanceof Error && error.message !== "cancel") ElMessage.error(error.message);
  }
}
async function operate(s: Server, action: string) {
  try {
    if (action === "stop")
      await ElMessageBox.confirm(
        `停止后，连接“${s.name}”的应用将暂时无法访问数据库。`,
        "停止数据库实例",
        {
          confirmButtonText: "停止",
          cancelButtonText: "取消",
          type: "warning",
        },
      );
    await submit(`/databases/instances/${s.id}/${action}`);
  } catch (e) {
    if (e !== "cancel" && e !== "close") ElMessage.error((e as Error).message);
  }
}
async function showCredentials(db: Database) {
  try {
    credentials.value = await props.api<Record<string, string>>(
      `/databases/items/${db.id}/credentials`,
      "POST",
      {},
    );
    credentialsOpen.value = true;
  } catch (e) {
    ElMessage.error((e as Error).message);
  }
}
async function restore(b: Backup) {
  try {
    const name = dbName(b.database_id);
    const { value } = await ElMessageBox.prompt(
      `将用此备份恢复“${name}”。系统先保留当前数据副本；恢复期间应用访问会受影响。请输入数据库名称确认。`,
      "恢复数据库",
      {
        confirmButtonText: "备份当前数据并恢复",
        cancelButtonText: "取消",
        inputValidator: (v) => v === name || "请输入完全一致的数据库名称",
      },
    );
    await submit(`/databases/items/${b.database_id}/restore`, {
      backup_id: b.id,
      confirm_name: value,
    });
  } catch (e) {
    if (e !== "cancel" && e !== "close") ElMessage.error((e as Error).message);
  }
}
const time = (s: string) =>
  formatPanelDateTime(s);
onMounted(() => {
  void refresh();
  timer = setInterval(refresh, 5000);
});
onUnmounted(() => {
  clearInterval(timer);
  credentials.value = {};
});
</script>
<template>
  <div class="database-manager">
    <el-alert
      v-if="error"
      :title="error"
      type="error"
      :closable="false"
      show-icon
    />
    <div class="database-summary">
      <div class="panel-card">
        <span class="database-summary-icon green"
          ><el-icon><Coin /></el-icon
        ></span>
        <div>
          <small>数据库总数</small><strong>{{ totalDatabaseCount }}</strong
          ><span
            >正常运行 {{ healthyDatabaseCount }}</span
          >
        </div>
      </div>
      <div class="panel-card">
        <span class="database-summary-icon blue"
          ><svg viewBox="0 0 24 24" aria-hidden="true"><path :d="siMysql.path" /></svg
        ></span>
        <div>
          <small>MySQL 数据库</small><strong>{{ activeDatabases.length }}</strong
          ><span
            >占比 {{ totalDatabaseCount ? Math.round(activeDatabases.length / totalDatabaseCount * 100) : 0 }}%</span
          >
        </div>
      </div>
      <div class="panel-card">
        <span class="database-summary-icon red"
          ><svg viewBox="0 0 24 24" aria-hidden="true"><path :d="siRedis.path" /></svg
        ></span>
        <div>
          <small>Redis 数据库</small><strong>{{ redisDatabases.length }}</strong
          ><span>运行中 {{ redisInstances.filter((item) => item.status === 'running').length }} 个实例</span>
        </div>
      </div>
      <div class="panel-card">
        <span class="database-summary-icon orange"
          ><el-icon><WarningFilled /></el-icon
        ></span>
        <div>
          <small>异常告警</small
          ><strong>{{
            data.servers.filter(
              (s) => !running(s.id) && s.status !== "creating",
            ).length
          }}</strong
          ><span>需要检查的数据库实例</span>
        </div>
      </div>
    </div>
    <section class="panel-card list-card database-instances-section">
      <div class="table-toolbar">
        <div>
          <h2>MySQL 实例</h2>
          <small class="muted"
            >精确版本各自运行，数据目录始终绑定原实例。</small
          >
        </div>
        <div class="database-actions">
          <el-button @click="refresh">刷新实例</el-button
          ><el-button
            type="primary"
            :disabled="!mysqlVersions.length"
            @click="newInstance"
            >创建实例</el-button
          >
        </div>
      </div>
      <el-empty
        v-if="!data.servers.length"
        :description="
          mysqlVersions.length
            ? '创建第一个独立 MySQL 实例'
            : '先到运行环境安装 MySQL'
        "
        :image-size="64"
      />
      <div v-for="s in data.servers" :key="s.id" class="database-instance">
        <span class="software-icon mysql">My</span>
        <div class="database-instance-main">
          <strong>{{ s.name }}</strong
          ><small
            >{{ s.release_id.replace("mysql-", "MySQL ") }} · 127.0.0.1:{{
              s.port
            }}</small
          ><small v-if="actual(s.id)">{{ actual(s.id)?.data_dir }}</small
          ><el-tag
            v-if="s.release_id.startsWith('mysql-8.0')"
            type="warning"
            size="small"
            disable-transitions
            >8.0 已结束维护 · 兼容迁移</el-tag
          >
        </div>
        <el-tag
          :type="
            running(s.id)
              ? 'success'
              : s.status === 'creating'
                ? 'warning'
                : 'info'
          "
          disable-transitions
          >{{
            running(s.id)
              ? "运行正常"
              : s.status === "creating"
                ? "创建中"
                : actual(s.id)?.service_state === "inactive"
                  ? "已停止"
                  : "待核对"
          }}</el-tag
        >
        <div class="database-actions">
          <el-button
            size="small"
            :disabled="submitting || s.status === 'creating'"
            @click="operate(s, running(s.id) ? 'stop' : 'start')"
            >{{ running(s.id) ? "停止" : "启动" }}</el-button
          ><el-button
            size="small"
            :disabled="submitting || !running(s.id)"
            @click="operate(s, 'restart')"
            >重启</el-button
          >
        </div>
      </div>
    </section>
    <section class="panel-card list-card database-items-section">
      <div class="table-toolbar">
        <div><h2>数据库列表</h2></div>
        <div class="database-toolbar-controls">
          <el-input v-model="databaseSearch" clearable aria-label="搜索数据库" placeholder="搜索数据库名、用户或备注..." />
          <el-select v-model="databaseType" aria-label="数据库类型筛选" @change="databasePage = 1"><el-option label="全部类型" value="all"/><el-option label="MySQL" value="mysql"/><el-option label="Redis" value="redis"/></el-select>
          <el-select v-model="databaseScope" aria-label="数据库状态筛选"><el-option label="使用中的数据库" value="active"/><el-option label="数据库回收站" value="trash"/></el-select>
          <el-button @click="refresh">刷新</el-button>
        </div>
      </div>
      <p v-if="databaseScope === 'trash'" class="database-trash-note">
        每库应用账号已锁定且撤销权限。数据、库名、原密码和备份仍保留，恢复数据库后可恢复依赖账号。
      </p>
      <el-table
        :data="visibleDatabases"
        @selection-change="(rows: Database[]) => selectedDatabases = rows"
        size="small"
        class="database-items-table database-desktop-table"
        empty-text="暂无应用数据库"
        style="width: 100%"
      >
        <el-table-column type="selection" width="42" :selectable="(row: Database) => row.engine !== 'redis' && row.status === 'ready' && running(row.server_id)" />
        <el-table-column label="数据库名" min-width="165"
          ><template #default="{ row }"
            ><strong class="database-name">{{ row.name }}</strong></template
          ></el-table-column
        >
        <el-table-column label="类型" width="100"><template #default="{ row }"><span class="database-type"><svg viewBox="0 0 24 24" :class="row.engine === 'redis' ? 'redis' : 'mysql'" aria-hidden="true"><path :d="row.engine === 'redis' ? siRedis.path : siMysql.path" /></svg>{{ row.engine === 'redis' ? 'Redis' : 'MySQL' }}</span></template></el-table-column>
        <el-table-column label="用户" min-width="120" prop="username" show-overflow-tooltip />
        <el-table-column label="大小" width="90"><template #default="{ row }">{{ row.engine === 'redis' ? (row.status === 'ready' ? `${row.redis_keys ?? 0} 键` : '—') : metricFor(row) ? backupSize(metricFor(row)!.bytes) : '—' }}</template></el-table-column>
        <el-table-column label="字符集" width="90"><template #default="{ row }">{{ row.engine === 'redis' ? '—' : metricFor(row)?.charset || '—' }}</template></el-table-column>
        <el-table-column label="状态" width="85"
          ><template #default="{ row }"
            ><span class="database-state" :class="row.status === 'ready' ? 'ready' : 'paused'"><i />{{ databaseStatus(row.status) }}</span
            ></template
          ></el-table-column
        >
        <el-table-column label="最近备份" min-width="155"
          ><template #default="{ row }">{{ row.engine === 'redis' ? 'AOF 持久化' : latestBackup(row.id) ? time(latestBackup(row.id)!) : "—" }}</template></el-table-column
        >
        <el-table-column label="备注" min-width="100"><template #default="{ row }">{{ row.engine === 'redis' ? `逻辑库 db${row.redis_index}` : sourceName(row) }}</template></el-table-column>
        <el-table-column label="操作" width="175"><template #default="{ row }"><div class="database-row-actions">
          <el-button link type="primary" :disabled="row.status !== 'ready'" @click="row.engine === 'redis' ? openRedis(row.server_id, row.redis_index) : showCredentials(row)">管理</el-button>
          <el-button link type="primary" :disabled="row.engine === 'redis' || submitting || row.status !== 'ready' || !running(row.server_id)" @click="submit(`/databases/items/${row.id}/backup`)">备份</el-button>
          <el-dropdown v-if="row.engine !== 'redis'" trigger="click" @command="(command: string) => databaseCommand(row, command)"><el-button link type="primary">更多⌄</el-button><template #dropdown><el-dropdown-menu>
            <el-dropdown-item command="credentials" :disabled="row.status !== 'ready'">连接信息</el-dropdown-item>
            <el-dropdown-item command="overwrite" :disabled="row.status !== 'ready' || !running(row.server_id)">覆盖导入</el-dropdown-item>
            <el-dropdown-item v-if="data.servers.find((s) => s.id === row.server_id)?.release_id.startsWith('mysql-8.0')" command="migrate" :disabled="row.status !== 'ready' || !running(row.server_id)">迁移至 8.4</el-dropdown-item>
            <el-dropdown-item command="lifecycle" :disabled="!running(row.server_id)">{{ row.status === 'quarantined' ? '恢复数据库' : '移入回收站' }}</el-dropdown-item>
            <el-dropdown-item command="job">查看任务</el-dropdown-item>
          </el-dropdown-menu></template></el-dropdown><el-button v-else link type="primary" @click="openRedis()">实例⌄</el-button>
        </div></template></el-table-column>
      </el-table>
      <div class="database-mobile-list">
        <article
          v-for="db in visibleDatabases"
          :key="db.id"
          class="database-mobile-item"
        >
          <div class="database-mobile-title">
            <strong>{{ db.name }}</strong
            ><el-tag
              :type="db.status === 'ready' ? 'success' : 'warning'"
              size="small"
              disable-transitions
              >{{ databaseStatus(db.status) }}</el-tag
            >
          </div>
          <small>{{ sourceName(db) }}</small
          ><small>{{ db.username }}</small>
          <div class="database-mobile-buttons">
            <template v-if="db.engine === 'redis'"><el-button size="small" @click="openRedis(db.server_id, db.redis_index)">浏览 Redis 键</el-button></template>
            <template v-else-if="db.status !== 'quarantined'"
              ><el-button
                size="small"
                :disabled="db.status !== 'ready'"
                @click="showCredentials(db)"
                >连接信息</el-button
              ><el-button
                size="small"
                :disabled="
                  submitting || db.status !== 'ready' || !running(db.server_id)
                "
                @click="submit(`/databases/items/${db.id}/backup`)"
                >备份</el-button
              ><el-button
                size="small"
                :disabled="db.status !== 'ready' || !running(db.server_id)"
                @click="importManager?.beginOverwrite(db)"
                >覆盖导入</el-button
              ><el-button
                v-if="
                  data.servers
                    .find((s) => s.id === db.server_id)
                    ?.release_id.startsWith('mysql-8.0')
                "
                size="small"
                :disabled="
                  submitting || db.status !== 'ready' || !running(db.server_id)
                "
                @click="openMigration(db)"
                >迁移至 8.4</el-button
              ><el-button
                size="small"
                type="danger"
                plain
                :disabled="db.status !== 'ready' || !running(db.server_id)"
                @click="lifecycle?.begin(db)"
                >移入回收站</el-button
              ></template
            >
            <el-button
              v-else
              size="small"
              type="primary"
              :disabled="!running(db.server_id)"
              @click="lifecycle?.begin(db)"
              >恢复数据库</el-button
            >
            <el-button size="small" text @click="databaseJob(db)"
              >查看任务</el-button
            >
          </div>
        </article>
        <el-empty
          v-if="!filteredDatabases.length"
          description="暂无数据库"
          :image-size="50"
        />
      </div>
      <div class="database-table-footer">
        <div class="database-bulk-controls"><el-select v-model="bulkAction" aria-label="批量操作"><el-option label="批量备份" value="backup" /></el-select><el-button :disabled="!selectedDatabases.length" @click="runBulkAction">应用</el-button></div>
        <div><span>共 {{ filteredDatabases.length }} 条</span><el-pagination v-model:current-page="databasePage" :page-size="databasePageSize" :total="filteredDatabases.length" layout="prev, pager, next" background /><span>{{ databasePageSize }} 条/页</span></div>
      </div>
    </section>
    <div class="database-analytics">
      <section class="panel-card database-analytics-card">
        <div class="database-analytics-heading"><h2>数据库连接统计</h2><span class="database-chart-legend"><i class="mysql-dot"></i>MySQL {{ mysqlConnectionsReady ? currentMySQLConnections : '—' }}<i class="redis-dot"></i>Redis {{ redisConnectionsReady ? currentRedisConnections : '—' }}</span></div>
        <div class="database-connection-chart" aria-label="最近 24 小时服务器实际连接数采样">
          <div class="database-chart-grid"><span>{{ Math.round(connectionMax) }}</span><span>{{ Math.round(connectionMax / 2) }}</span><span>0</span></div>
          <svg viewBox="0 0 100 100" preserveAspectRatio="none" role="img" tabindex="0" aria-label="MySQL 和 Redis 连接趋势，使用左右方向键查看采样" @pointermove="connectionHover" @pointerleave="connectionHoverIndex = null" @focus="connectionHoverIndex = connectionSamples.length ? connectionSamples.length - 1 : null" @blur="connectionHoverIndex = null" @keydown="connectionKey">
            <template v-for="(segment, index) in connectionSeries('mysql')" :key="`mysql-${index}`"><circle v-if="segment.single" :cx="segment.x" :cy="segment.y" r="1.5" class="mysql-point" /><polyline v-else :points="segment.points" class="mysql-line" /></template>
            <template v-for="(segment, index) in connectionSeries('redis')" :key="`redis-${index}`"><circle v-if="segment.single" :cx="segment.x" :cy="segment.y" r="1.5" class="redis-point" /><polyline v-else :points="segment.points" class="redis-line" /></template>
            <line v-if="hoveredConnection && connectionHoverIndex !== null" :x1="connectionX(connectionHoverIndex)" y1="0" :x2="connectionX(connectionHoverIndex)" y2="100" stroke="#7f9ab7" stroke-dasharray="2 2" vector-effect="non-scaling-stroke" />
            <circle v-if="hoveredConnection?.mysql !== null && hoveredConnection && connectionHoverIndex !== null" :cx="connectionX(connectionHoverIndex)" :cy="100 - hoveredConnection.mysql / connectionMax * 100" r="2" fill="#0ca85c" stroke="white" stroke-width="1" vector-effect="non-scaling-stroke" />
            <circle v-if="hoveredConnection?.redis !== null && hoveredConnection && connectionHoverIndex !== null" :cx="connectionX(connectionHoverIndex)" :cy="100 - hoveredConnection.redis / connectionMax * 100" r="2" fill="#1579ef" stroke="white" stroke-width="1" vector-effect="non-scaling-stroke" />
          </svg>
          <div v-if="hoveredConnection && connectionHoverIndex !== null" class="database-connection-tooltip" :style="{ left: `${Math.max(18, Math.min(80, connectionX(connectionHoverIndex)))}%` }" role="status"><strong>{{ formatPanelDateTime(hoveredConnection.at) }}</strong><span><i class="mysql-dot"></i>MySQL：{{ hoveredConnection.mysql === null ? '暂不可用' : `${hoveredConnection.mysql} 个连接` }}</span><span><i class="redis-dot"></i>Redis：{{ hoveredConnection.redis === null ? '暂不可用' : `${hoveredConnection.redis} 个连接` }}</span></div>
        </div>
        <div class="database-chart-axis"><span>24 小时前</span><span>{{ !connectionHistoryReady ? '历史暂不可用' : connectionSamples.length > 1 ? `${connectionSamples.length} 次采样` : '正在采样' }}</span><span>现在</span></div>
      </section>
      <section class="panel-card database-analytics-card">
        <div class="database-analytics-heading"><h2>备份任务状态</h2><button class="database-analytics-link" type="button" @click="backupJobsOpen = true">查看更多 ›</button></div>
        <div class="database-analytics-body">
          <div v-for="job in recentBackupJobs" :key="job.id" class="database-analytics-row" :title="job.error || backupJobLabel(job.state)">
            <span><i class="database-job-mark" :class="job.state">{{ job.state === 'succeeded' ? '✓' : job.state === 'failed' || job.state === 'needs_attention' ? '!' : '·' }}</i>{{ job.database_name || job.site_name || '数据库备份' }}</span><span :class="job.state === 'succeeded' ? 'healthy' : job.state === 'failed' || job.state === 'needs_attention' ? 'database-job-failed' : 'database-job-pending'">{{ backupJobLabel(job.state) }}</span><span>{{ time(job.updated_at || job.created_at) }}</span><span>{{ job.state === 'succeeded' && job.backup_bytes !== undefined ? backupSize(job.backup_bytes) : job.state === 'succeeded' ? '完成' : '任务' }}</span>
          </div>
          <div v-if="!recentBackupJobs.length" v-for="backup in data.backups.slice(0, 4)" :key="backup.id" class="database-analytics-row">
            <span><i class="database-success-dot">✓</i>{{ dbName(backup.database_id) }}</span><span class="healthy">备份成功</span><span>{{ time(backup.created_at) }}</span><span>{{ backupSize(backup.bytes) }}</span>
          </div>
          <p v-if="!backupJobsReady" class="muted">任务状态暂不可用；下方仅显示已完成的备份文件。</p>
          <p v-else-if="!recentBackupJobs.length && !data.backups.length" class="muted">暂无数据库备份任务</p>
        </div>
      </section>
      <section class="panel-card database-analytics-card database-distribution">
        <div class="database-analytics-heading"><h2>数据库使用情况</h2><button class="database-analytics-link" type="button" @click="storageDetailsOpen = true">查看详情 ›</button></div>
        <div class="database-analytics-body">
          <div class="database-distribution-ring" :style="{ '--healthy-percent': `${mysqlUsedPercent}%` }"><strong>{{ backupSize(databaseUsedBytes) }}</strong><small>已统计用量</small></div>
          <div class="database-distribution-legend">
            <span><i class="healthy-dot"></i>MySQL <b>{{ backupSize(mysqlUsedBytes) }}</b></span>
            <span><i class="backup-dot"></i>Redis <b>{{ backupSize(redisUsedBytes) }}</b></span>
          </div>
        </div>
      </section>
    </div>
    <DatabaseLifecycleDialog
      ref="lifecycle"
      :api="api"
      :servers="data.servers"
      :on-job="onJob"
      @changed="lifecycleChanged"
    />
    <DatabaseAccountManager
      :api="api"
      :servers="data.servers"
      :databases="data.databases"
      :on-job="onJob"
      @changed="refresh"
    />
    <DatabaseImportManager
      ref="importManager"
      :api="api"
      :csrf="csrf"
      :servers="data.servers"
      :on-job="onJob"
      @changed="refresh"
    />
    <section class="panel-card list-card">
      <div class="table-toolbar">
        <div>
          <h2>数据库备份</h2>
          <small class="muted"
            >恢复前自动保存当前数据。跨版本变更使用独立实例迁移。</small
          >
        </div>
      </div>
      <el-table
        :data="visibleBackups"
        class="database-backups-table database-desktop-table"
        empty-text="尚未创建备份"
        style="width: 100%"
      >
        <el-table-column label="数据库" min-width="180"
          ><template #default="{ row }"
            ><strong>{{ dbName(row.database_id) }}</strong
            ><small class="database-cell-small">{{
              serverName(row.server_id)
            }}</small></template
          ></el-table-column
        >
        <el-table-column label="创建时间" min-width="185"
          ><template #default="{ row }">{{
            time(row.created_at)
          }}</template></el-table-column
        >
        <el-table-column label="版本 / 大小" width="145"
          ><template #default="{ row }"
            >{{ row.version }} · {{ backupSize(row.bytes) }}</template
          ></el-table-column
        >
        <el-table-column label="校验" width="125"
          ><template #default="{ row }"
            ><span :title="row.sha256"
              >{{ row.sha256.slice(0, 10) }}…</span
            ></template
          ></el-table-column
        >
        <el-table-column label="操作" width="170"
          ><template #default="{ row }"
            ><a
              class="database-download"
              :href="apiURL(`/databases/backups/${row.id}/download`)"
              :aria-label="`${dbName(row.database_id)} 下载 SQL`"
              :data-backup-id="row.id"
              download
              target="_blank"
              rel="noopener noreferrer"
              >下载 SQL</a
            ><el-button
              link
              type="primary"
              :disabled="submitting || !running(row.server_id)"
              @click="restore(row)"
              >恢复</el-button
            ></template
          ></el-table-column
        >
      </el-table>
      <div class="database-mobile-list">
        <article
          v-for="b in visibleBackups"
          :key="b.id"
          class="database-mobile-item"
        >
          <div class="database-mobile-title">
            <strong>{{ dbName(b.database_id) }}</strong>
            <div class="database-backup-actions">
              <a
                class="database-download"
                :href="apiURL(`/databases/backups/${b.id}/download`)"
                :aria-label="`${dbName(b.database_id)} 下载 SQL`"
                :data-backup-id="b.id"
                download
                target="_blank"
                rel="noopener noreferrer"
                >下载 SQL</a
              ><el-button
                size="small"
                :disabled="submitting || !running(b.server_id)"
                @click="restore(b)"
                >恢复</el-button
              >
            </div>
          </div>
          <small>{{ serverName(b.server_id) }}</small
          ><small>{{ time(b.created_at) }}</small
          ><small
            >MySQL {{ b.version }} · {{ backupSize(b.bytes) }} ·
            {{ b.sha256.slice(0, 10) }}…</small
          >
        </article>
        <el-empty
          v-if="!data.backups.length"
          description="暂无备份"
          :image-size="50"
        />
      </div>
      <el-pagination
        v-if="data.backups.length > 5"
        v-model:current-page="backupPage"
        :page-size="5"
        :total="data.backups.length"
        layout="prev, pager, next"
        class="database-pagination"
      />
    </section>
    <el-dialog v-model="backupJobsOpen" title="数据库备份任务" width="min(700px, 94vw)">
      <p class="database-storage-note">最近 {{ backupJobs.length }} 条数据库备份任务；按创建时间排序，不受任务中心最近 100 条总任务的截断影响。</p>
      <div v-if="backupJobsReady" class="database-backup-job-list">
        <article v-for="job in backupJobs" :key="job.id">
          <span><strong>{{ job.database_name || job.site_name || '数据库备份' }}</strong><small>{{ time(job.updated_at || job.created_at) }}<template v-if="job.backup_bytes !== undefined"> · {{ backupSize(job.backup_bytes) }}</template><template v-if="job.error"> · {{ job.error }}</template></small></span>
          <b :class="job.state === 'succeeded' ? 'healthy' : job.state === 'failed' || job.state === 'needs_attention' ? 'database-job-failed' : 'database-job-pending'">{{ backupJobLabel(job.state) }}</b>
          <el-button link type="primary" @click="openBackupJob(job)">查看任务</el-button>
        </article>
        <p v-if="!backupJobs.length" class="muted">暂无数据库备份任务。</p>
      </div>
      <p v-else class="muted">备份任务状态暂不可用，请刷新数据库页后重试。</p>
    </el-dialog>
    <el-dialog v-model="storageDetailsOpen" title="数据库使用详情" width="min(600px, 94vw)">
      <p class="database-storage-note">已统计用量 {{ backupSize(databaseUsedBytes) }}；MySQL 数据库为实例返回的估算值，Redis 为运行实例当前内存。此处不代表磁盘剩余空间。</p>
      <div class="database-storage-list">
        <div v-for="row in storageRows" :key="row.id" class="database-storage-row">
          <span><strong>{{ row.name }}</strong><small>{{ row.source }}</small></span>
          <b>{{ backupSize(row.bytes) }}</b>
        </div>
        <p v-if="!storageRows.length" class="muted">暂无可统计的数据库或运行中的 Redis 实例。</p>
      </div>
    </el-dialog>
    <el-dialog
      v-model="instanceOpen"
      title="创建 MySQL 实例"
      width="500px"
      destroy-on-close
    >
      <el-form
        label-position="top"
        @submit.prevent="submit('/databases/instances', instance)"
      >
        <el-form-item label="实例名称"
          ><el-input
            v-model="instance.name"
            aria-label="实例名称"
            maxlength="40"
            placeholder="例如：主业务数据库"
        /></el-form-item>
        <el-form-item label="MySQL 版本"
          ><el-select
            v-model="instance.release_id"
            aria-label="实例 MySQL 版本"
            style="width: 100%"
            ><el-option
              v-for="r in mysqlVersions"
              :key="r.id"
              :value="r.id"
              :label="
                r.version +
                (r.version.startsWith('8.4') ? ' · LTS' : ' · 已结束维护')
              " /></el-select
        ></el-form-item>
        <el-alert
          v-if="instance.release_id.startsWith('mysql-8.0')"
          title="MySQL 8.0 已结束常规维护，建议仅用于兼容和迁移。"
          type="warning"
          :closable="false"
        />
        <el-form-item label="本机端口"
          ><el-input-number
            v-model="instance.port"
            aria-label="MySQL 本机端口"
            :min="13306"
            :max="13999"
        /></el-form-item>
        <p class="muted">
          自动生成私有管理凭据。实例使用独立数据目录、系统用户、socket 和服务。
        </p>
        <el-button
          native-type="submit"
          type="primary"
          :loading="submitting"
          :disabled="!instance.name.trim()"
          >创建实例</el-button
        >
      </el-form>
    </el-dialog>
    <el-dialog
      v-model="databaseOpen"
      title="创建数据库"
      width="500px"
      destroy-on-close
    >
      <el-form
        label-position="top"
        @submit.prevent="
          submit(`/databases/instances/${database.server_id}/databases`, {
            name: database.name,
          })
        "
      >
        <el-form-item label="所属实例"
          ><el-select
            v-model="database.server_id"
            aria-label="数据库所属实例"
            style="width: 100%"
            ><el-option
              v-for="s in data.servers.filter((s) => running(s.id))"
              :key="s.id"
              :value="s.id"
              :label="
                s.name + ' · ' + s.release_id.replace('mysql-', '')
              " /></el-select
        ></el-form-item>
        <el-form-item label="数据库名称"
          ><el-input
            v-model="database.name"
            aria-label="数据库名称"
            maxlength="32"
            placeholder="小写字母开头，可含数字与下划线"
        /></el-form-item>
        <p class="muted">
          使用 utf8mb4，自动创建独立账号与随机密码。连接信息可在完成后查看。
        </p>
        <el-button
          native-type="submit"
          type="primary"
          :loading="submitting"
          :disabled="
            !database.server_id || !/^[a-z][a-z0-9_]{0,31}$/.test(database.name)
          "
          >创建数据库</el-button
        >
      </el-form>
    </el-dialog>
    <el-dialog
      v-model="migrationOpen"
      title="迁移至 MySQL 8.4"
      width="530px"
      destroy-on-close
    >
      <el-alert
        title="迁移期间会暂停源实例写入，读取仍可进行。完成或进程中断后会自动解除。"
        type="warning"
        :closable="false"
      />
      <el-form label-position="top" @submit.prevent="migrate">
        <el-form-item label="源数据库"
          ><el-input :model-value="migrationSource?.name" readonly
        /></el-form-item>
        <el-form-item label="目标 8.4 实例"
          ><el-select
            v-model="migrationTarget"
            aria-label="迁移目标实例"
            style="width: 100%"
            ><el-option
              v-for="s in migrationTargets"
              :key="s.id"
              :value="s.id"
              :label="s.name + ' · ' + s.port" /></el-select
        ></el-form-item>
        <p class="muted">
          目标必须没有同名数据库。系统复制数据与对象并逐行核对，保留源库与备份。迁移后需核对新连接信息，再调整应用连接；两个实例将各自接收写入。
        </p>
        <el-form-item label="输入源数据库名称确认"
          ><el-input v-model="migrationConfirm" aria-label="迁移确认数据库名称"
        /></el-form-item>
        <el-button
          native-type="submit"
          type="primary"
          :loading="submitting"
          :disabled="
            !migrationTarget || migrationConfirm !== migrationSource?.name
          "
          >开始迁移</el-button
        >
      </el-form>
    </el-dialog>
    <el-dialog
      v-model="credentialsOpen"
      title="数据库连接信息"
      width="500px"
      destroy-on-close
      @closed="credentials = {}"
    >
      <el-form label-position="top"
        ><el-form-item label="数据库"
          ><el-input
            :model-value="credentials.database"
            readonly /></el-form-item
        ><el-form-item label="主机与端口"
          ><el-input
            :model-value="credentials.host + ':' + credentials.port"
            readonly /></el-form-item
        ><el-form-item label="用户名"
          ><el-input
            :model-value="credentials.username"
            readonly /></el-form-item
        ><el-form-item label="密码"
          ><el-input
            :model-value="credentials.password"
            type="password"
            show-password
            readonly /></el-form-item
      ></el-form>
      <p class="muted">
        这里的地址供同一 Linux 虚拟机内的应用连接。每次查看都会记入操作日志。
      </p>
    </el-dialog>
  </div>
</template>
<style scoped>
.database-scope {
  margin: 0;
}
.database-toolbar-controls {
  display: flex;
  align-items: center;
  gap: 12px;
}
.database-trash-note {
  padding: 0 22px 18px;
  font-size: 13px;
  color: #718078;
}
.database-pagination {
  padding: 16px 24px;
}
.database-manager {
  display: grid;
  gap: 24px;
  min-width: 0;
}
.database-manager > * {
  order: 4;
}
.database-manager > .database-summary {
  order: 1;
}
.database-manager > .database-items-section {
  order: 2;
  min-height: 395px;
  display: flex;
  flex-direction: column;
}
.database-manager > .database-analytics {
  order: 3;
}
.database-manager > .database-instances-section {
  order: 4;
}
.database-manager .database-items-section :deep(.el-table__cell) {
  padding: 3px 0;
}
.database-manager .database-items-section :deep(.el-table__body td.el-table__cell) {
  height: 31px;
}
.database-manager .database-items-section :deep(.cell) {
  line-height: 20px;
}
.database-manager .database-items-section :deep(.el-table__body tr) {
  height: 31px;
}
.database-table-footer { min-height: 43px; display: flex; justify-content: space-between; align-items: center; gap: 12px; padding: 5px 15px; border-top: 1px solid #e9eef5; color: #657895; font-size: 12px; margin-top: auto; }
.database-table-footer > div { display: flex; align-items: center; gap: 9px; }
.database-bulk-controls .el-select { width: 105px; }.database-bulk-controls .el-button { margin: 0; }
.database-table-footer :deep(.el-pagination) { --el-pagination-button-width: 27px; --el-pagination-button-height: 27px; }
.database-manager .database-items-section :deep(.el-table__body td:nth-child(3) .cell) {
  overflow: hidden;
  white-space: nowrap;
  text-overflow: ellipsis;
}
.database-name {
  display: block;
  color: #0a9654;
  overflow: hidden;
  white-space: nowrap;
  text-overflow: ellipsis;
}
.database-row-actions {
  display: flex;
  align-items: center;
  white-space: nowrap;
  gap: 2px;
}
.database-row-actions :deep(.el-button) {
  font-size: 12px;
  padding: 0 3px;
}
.database-row-actions :deep(.el-button + .el-button) {
  margin-left: 0;
}
.database-analytics {
  display: grid;
  grid-template-columns: 1.12fr 1fr .9fr;
  gap: 12px;
  min-width: 0;
}
.database-analytics-card {
  min-width: 0;
  min-height: 216px;
  padding: 15px 17px;
}
.database-analytics-heading {
  min-height: 31px;
  display: flex;
  align-items: flex-start;
  justify-content: space-between;
  gap: 10px;
  padding-bottom: 9px;
  border-bottom: 1px solid #e9edf3;
}
.database-analytics-heading h2 { margin: 0; }
.database-analytics-heading > .muted { white-space: nowrap; font-size: 12px; }
.database-analytics-link { border: 0; padding: 0; background: transparent; color: #536984; font: inherit; font-size: 12px; white-space: nowrap; cursor: pointer; }
.database-analytics-link:hover, .database-analytics-link:focus-visible { color: #079a54; text-decoration: underline; }
.database-storage-note { margin: 0 0 12px; color: #60738c; font-size: 12px; line-height: 1.6; }
.database-storage-list { max-height: 430px; overflow: auto; border: 1px solid #e5edf4; border-radius: 6px; }
.database-storage-row { display: flex; align-items: center; justify-content: space-between; gap: 16px; padding: 9px 12px; border-bottom: 1px solid #edf1f6; }
.database-storage-row:last-child { border-bottom: 0; }
.database-storage-row span { display: grid; min-width: 0; gap: 3px; }
.database-storage-row strong { overflow: hidden; text-overflow: ellipsis; white-space: nowrap; color: #263955; font-size: 13px; }
.database-storage-row small { color: #71819a; }
.database-storage-row b { flex: none; color: #34445b; font-size: 12px; }
.database-backup-job-list { max-height: 450px; overflow: auto; border: 1px solid #e5edf4; border-radius: 6px; }
.database-backup-job-list article { display: flex; align-items: center; gap: 12px; padding: 9px 12px; border-bottom: 1px solid #edf1f6; }
.database-backup-job-list article:last-child { border-bottom: 0; }
.database-backup-job-list article > span { display: grid; min-width: 0; flex: 1; gap: 3px; }
.database-backup-job-list article strong { overflow: hidden; text-overflow: ellipsis; white-space: nowrap; color: #263955; font-size: 13px; }
.database-backup-job-list article small { overflow: hidden; text-overflow: ellipsis; white-space: nowrap; color: #71819a; }
.database-backup-job-list article b { flex: none; font-size: 12px; }
.database-backup-job-list > .muted { padding: 12px; }
.database-chart-legend { display: inline-flex; align-items: center; gap: 5px; white-space: nowrap; color: #576781; font-size: 12px; }
.database-chart-legend i { width: 9px; height: 9px; border-radius: 50%; margin-left: 8px; }
.database-chart-legend .mysql-dot { background: #0ca85c; }
.database-chart-legend .redis-dot { background: #1579ef; }
.database-connection-chart { position: relative; height: 129px; margin: 10px 4px 0 34px; }
.database-chart-grid { position: absolute; inset: 0; display: flex; flex-direction: column; justify-content: space-between; background: repeating-linear-gradient(to right, transparent 0, transparent calc(20% - 1px), #e6edf5 calc(20% - 1px), #e6edf5 20%); border-top: 1px solid #e6edf5; border-bottom: 1px solid #e6edf5; }
.database-chart-grid span { position: relative; left: -35px; width: 31px; text-align: right; color: #667890; font-size: 10px; line-height: 1; }
.database-connection-chart svg { position: absolute; inset: 0; width: 100%; height: 100%; overflow: visible; }
.database-connection-chart svg:focus-visible { outline: 2px solid #0ca85c; outline-offset: 3px; }
.database-connection-tooltip { position: absolute; z-index: 2; top: 8px; display: grid; gap: 5px; min-width: 154px; padding: 8px 10px; border: 1px solid #dce5ef; border-radius: 6px; background: #fff; box-shadow: 0 4px 16px #122a4226; color: #314665; font-size: 11px; pointer-events: none; transform: translateX(-50%); }
.database-connection-tooltip strong { font-weight: 600; color: #243955; }
.database-connection-tooltip span { display: flex; align-items: center; gap: 7px; white-space: nowrap; }
.database-connection-tooltip i { width: 7px; height: 7px; border-radius: 50%; }
.database-connection-tooltip .mysql-dot { background: #0ca85c; }
.database-connection-tooltip .redis-dot { background: #1579ef; }
.database-connection-chart polyline { fill: none; stroke-width: 1.3; vector-effect: non-scaling-stroke; stroke-linecap: round; stroke-linejoin: round; }
.database-connection-chart .mysql-line { stroke: #0ca85c; }
.database-connection-chart .redis-line { stroke: #1579ef; }
.database-connection-chart .mysql-point { fill: #0ca85c; }
.database-connection-chart .redis-point { fill: #1579ef; }
.database-chart-axis { display: flex; justify-content: space-between; padding: 3px 4px 0 34px; color: #63748b; font-size: 11px; }
.database-analytics-body {
  display: grid;
  gap: 7px;
  font-size: 12px;
}
.database-analytics-row {
  display: grid;
  grid-template-columns: minmax(0, 1fr) 64px 113px 54px;
  gap: 10px;
  align-items: center;
  padding: 6px 0;
  border-bottom: 1px solid #edf1f6;
}
.database-analytics-row > span { overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.database-success-dot { display: inline-grid; width: 18px; height: 18px; place-items: center; margin-right: 8px; border-radius: 50%; background: #08a75d; color: white; font-size: 12px; font-style: normal; }
.database-analytics-row > span:first-child {
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}
.database-analytics-row .healthy,
.database-job-mark.succeeded { color: #078e50; }
.database-job-mark.failed, .database-job-mark.needs_attention, .database-job-failed { color: #d94343; }
.database-job-mark.queued, .database-job-mark.running, .database-job-pending { color: #bc7914; }
.database-job-mark { display: inline-grid; place-items: center; width: 18px; height: 18px; margin-right: 8px; border-radius: 50%; background: #edf4f1; font-style: normal; font-weight: 700; }
.database-distribution-legend .healthy-dot {
  color: #0a9d59;
}
.database-distribution .database-analytics-body {
  display: flex;
  align-items: center;
  justify-content: space-evenly;
  gap: 18px;
}
.database-distribution-ring {
  width: 136px;
  height: 136px;
  flex: none;
  border-radius: 50%;
  background: conic-gradient(#0da55d var(--healthy-percent), #1477ea var(--healthy-percent));
  display: grid;
  place-content: center;
  text-align: center;
  position: relative;
}
.database-distribution-ring::before {
  content: "";
  position: absolute;
  inset: 17px;
  border-radius: 50%;
  background: white;
}
.database-distribution-ring strong,
.database-distribution-ring small {
  position: relative;
}
.database-distribution-ring strong {
  font-size: 20px;
}
.database-distribution-ring small {
  color: #718098;
}
.database-distribution-legend {
  display: grid;
  gap: 15px;
  white-space: nowrap;
}
.database-distribution-legend span { display: flex; align-items: center; gap: 5px; }
.database-distribution-legend b { margin-left: auto; color: #34445b; font-weight: 500; }
.database-distribution-legend i {
  display: inline-block;
  width: 8px;
  height: 8px;
  margin-right: 7px;
  border-radius: 50%;
  background: #0da55d;
}
.database-distribution-legend .muted-dot { background: #b8c5d5; }
.database-distribution-legend .backup-dot { background: #2077e8; }
.database-summary {
  display: grid;
  grid-template-columns: repeat(4, minmax(0, 1fr));
  gap: 12px;
}
.database-summary .panel-card {
  min-height: 125px;
  padding: 18px;
  display: flex;
  align-items: center;
  gap: 20px;
}
.database-summary .panel-card > div {
  display: grid;
  gap: 6px;
}
.database-summary-icon {
  width: 60px;
  height: 60px;
  border-radius: 11px;
  display: grid;
  place-items: center;
  flex: none;
  font-size: 26px;
}
.database-summary-icon :deep(.el-icon) { font-size: 31px; }
.database-summary-icon svg { width: 38px; height: 38px; fill: currentColor; }
.database-type { display: inline-flex; align-items: center; gap: 8px; white-space: nowrap; }
.database-type svg { width: 20px; height: 20px; fill: currentColor; }
.database-type .mysql { color: #1873ad; }
.database-type .redis { color: #d82020; }
.database-state { display: inline-flex; align-items: center; gap: 7px; white-space: nowrap; font-weight: 600; }
.database-state i { width: 9px; height: 9px; border-radius: 50%; background: currentColor; }
.database-state.ready { color: #08a858; }
.database-state.paused { color: #ef8b22; }
.database-summary-icon.green {
  background: #e4f8ed;
  color: #08ad5b;
}
.database-summary-icon.blue {
  background: #e7f2ff;
  color: #2387eb;
}
.database-summary-icon.purple {
  background: #f0e9ff;
  color: #8747e8;
}
.database-summary-icon.orange {
  background: #fff0e7;
  color: #f27621;
}
.database-summary small,
.database-summary span {
  color: #7d9188;
  font-size: 12px;
}
.database-summary strong {
  font-size: 27px;
  color: #10213a;
  line-height: 1;
}
.database-instance {
  display: flex;
  align-items: center;
  gap: 18px;
  padding: 24px;
  border-top: 1px solid #edf1ee;
}
.database-instance-main {
  display: grid;
  gap: 6px;
  flex: 1;
  min-width: 0;
}
.database-instance-main small,
.database-cell-small {
  display: block;
  color: #82968c;
  font-size: 12px;
  overflow-wrap: anywhere;
}
.database-instance-main .el-tag {
  justify-self: start;
}
.database-actions {
  display: flex;
  gap: 8px;
  flex-shrink: 0;
}
.database-actions .el-button + .el-button {
  margin: 0;
}
.database-manager h2 {
  margin: 0 0 7px;
  font-size: 16px;
}
.database-manager .table-toolbar {
  gap: 16px;
}
.database-toolbar-controls { display: flex; align-items: center; gap: 9px; }
.database-toolbar-controls .el-input { width: 265px; }
.database-toolbar-controls .el-select { width: 128px; }
.database-toolbar-controls .el-button { margin: 0; }
.database-summary-icon.red { background: #ffebeb; color: #e33636; }
.database-manager .database-items-section :deep(.el-table th.el-table__cell) { height: 34px; }
.database-manager .database-items-section :deep(.el-table .cell) { padding: 0 8px; }
.database-manager .database-items-section :deep(.el-table__body td.el-table__cell) { padding: 0; }
.database-row-actions :deep(.el-button) { margin: 0; }
.database-manager :deep(.el-dialog) {
  max-width: calc(100vw - 28px);
}
.database-manager .el-alert {
  margin-bottom: 16px;
}
.database-mobile-list {
  display: none;
}
.database-download {
  display: inline-flex;
  align-items: center;
  padding: 8px 0;
  margin-right: 12px;
  font-size: 13px;
  color: var(--el-color-primary);
  text-decoration: none;
  white-space: nowrap;
}
.database-download:focus-visible {
  outline: 2px solid var(--el-color-primary);
  outline-offset: 3px;
}
.database-backup-actions {
  display: flex;
  align-items: center;
  flex-shrink: 0;
}
@media (max-width: 680px) {
  .database-analytics { grid-template-columns: 1fr; }
  .database-desktop-table {
    display: none;
  }
  .database-mobile-list {
    display: block;
  }
  .database-mobile-item {
    display: grid;
    gap: 8px;
    padding: 18px 14px;
    border-top: 1px solid #edf1ee;
  }
  .database-mobile-item small {
    color: #82968c;
    font-size: 11px;
    overflow-wrap: anywhere;
  }
  .database-mobile-title {
    display: flex;
    justify-content: space-between;
    gap: 8px;
    align-items: center;
  }
  .database-mobile-title strong {
    font-size: 13px;
    overflow-wrap: anywhere;
    min-width: 0;
  }
  .database-mobile-buttons {
    display: flex;
    flex-wrap: wrap;
    gap: 7px;
    margin-top: 4px;
  }
  .database-mobile-buttons .el-button {
    margin: 0;
    padding: 7px 10px;
    font-size: 11px;
  }

  .database-summary {
    gap: 8px;
  }
  .database-summary .panel-card {
    padding: 14px;
  }
  .database-summary span {
    font-size: 10px;
  }
  .database-summary strong {
    font-size: 23px;
  }
  .database-manager .table-toolbar {
    align-items: flex-start;
    flex-wrap: wrap;
  }
  .database-toolbar-controls { flex-wrap: wrap; }
  .database-instance {
    display: grid;
    grid-template-columns: 36px minmax(0, 1fr);
    padding: 18px 14px;
    gap: 12px;
  }
  .database-instance > .el-tag,
  .database-instance > .database-actions {
    grid-column: 2;
    justify-self: start;
  }
  .database-instance-main small {
    font-size: 11px;
  }
  .database-manager {
    gap: 18px;
  }
  .database-manager > .database-items-section {
    min-height: 0;
  }
}
</style>
