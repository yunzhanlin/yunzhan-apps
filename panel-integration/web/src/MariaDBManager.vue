<script setup lang="ts">
import { apiURL } from "./panelBase";
import { computed, ref } from "vue";
import { ElMessage, ElMessageBox } from "element-plus";
import { Plus, Refresh, Tickets } from "@element-plus/icons-vue";

type API = <T>(path: string, method?: string, body?: unknown) => Promise<T>;
interface Runtime {
  id: string;
  family: string;
  version: string;
  status: string;
}
interface Instance {
  id: string;
  name: string;
  release_id: string;
  port: number;
  memory_mb: number;
  created_at: string;
  status: string;
  connections: number;
  data_bytes: number;
}
interface Database {
  id: string;
  instance_id: string;
  name: string;
  username: string;
  created_at: string;
}
interface Backup {
  id: string;
  database_id: string;
  instance_id: string;
  database_name: string;
  version: string;
  bytes: number;
  sha256: string;
  created_at: string;
}
interface MySQLServer {
  id: string;
  name: string;
  release_id: string;
  status: string;
}
interface MySQLDatabase {
  id: string;
  server_id: string;
  name: string;
  status: string;
}
const props = defineProps<{ api: API; csrf: string; installed: Runtime[] }>();
const drawer = ref(false),
  loading = ref(false),
  createOpen = ref(false),
  databaseOpen = ref(false),
  migrationOpen = ref(false),
  reverseMigrationOpen = ref(false),
  credentialsOpen = ref(false),
  logsOpen = ref(false),
  logs = ref("");
const instances = ref<Instance[]>([]);
const databases = ref<Database[]>([]),
  credentials = ref<Record<string, string | number>>({});
const credentialsTarget = ref<Database>();
const backups = ref<Backup[]>([]);
const mysqlServers = ref<MySQLServer[]>([]),
  mysqlDatabases = ref<MySQLDatabase[]>([]);
const form = ref({ name: "", release_id: "", port: 13000, memory_mb: 256 });
const databaseForm = ref({ instance_id: "", name: "" });
const migrationForm = ref({
  source_database_id: "",
  target_instance_id: "",
  target_name: "",
  confirm_name: "",
});
const reverseMigrationForm = ref({
  source_database_id: "",
  source_name: "",
  target_server_id: "",
  target_name: "",
  confirm_name: "",
});
const importInput = ref<HTMLInputElement>(),
  importTarget = ref<Database>();
const releases = computed(() =>
  props.installed.filter(
    (r) => r.family === "mariadb" && r.status === "installed",
  ),
);
const running = computed(
  () => instances.value.filter((item) => item.status === "running").length,
);
const memory = (bytes: number) =>
  bytes < 1024 * 1024
    ? `${Math.round(bytes / 1024)} KB`
    : `${(bytes / 1024 / 1024).toFixed(1)} MB`;

async function refresh() {
  loading.value = true;
  try {
    const [instanceData, databaseData, backupData, mysqlData] =
      await Promise.all([
        props.api<{ instances: Instance[] }>("/mariadb/instances"),
        props.api<{ databases: Database[] }>("/mariadb/databases"),
        props.api<{ backups: Backup[] }>("/mariadb/backups"),
        props.api<{ servers: MySQLServer[]; databases: MySQLDatabase[] }>(
          "/databases",
        ),
      ]);
    instances.value = instanceData.instances;
    databases.value = databaseData.databases;
    backups.value = backupData.backups;
    mysqlServers.value = mysqlData.servers;
    mysqlDatabases.value = mysqlData.databases.filter(
      (item) => item.status === "ready",
    );
  } catch (e) {
    ElMessage.error(e instanceof Error ? e.message : "读取 MariaDB 实例失败");
  } finally {
    loading.value = false;
  }
}
async function backupDatabase(database: Database) {
  loading.value = true;
  try {
    await props.api(`/mariadb/databases/${database.id}/backup`, "POST", {});
    ElMessage.success("MariaDB 备份已完成并记录 SHA-256");
    await refresh();
  } catch (e) {
    ElMessage.error(e instanceof Error ? e.message : "备份失败");
  } finally {
    loading.value = false;
  }
}
function chooseImport(database: Database) {
  importTarget.value = database;
  if (importInput.value) {
    importInput.value.value = "";
    importInput.value.click();
  }
}
async function uploadImport(file: File, database: Database, confirm: string) {
  return new Promise<void>((resolve, reject) => {
    const request = new XMLHttpRequest();
    request.open(
      "POST",
      apiURL(`/mariadb/databases/${database.id}/import?confirm_name=${encodeURIComponent(confirm)}&bytes=${file.size}`),
    );
    request.setRequestHeader("Content-Type", "application/octet-stream");
    request.setRequestHeader("X-CSRF-Token", props.csrf);
    request.timeout = 1800000;
    request.onload = () => {
      let result: { error?: string } = {};
      try {
        result = JSON.parse(request.responseText);
      } catch {
        reject(new Error("无法读取 MariaDB 导入结果"));
        return;
      }
      if (request.status === 200) resolve();
      else reject(new Error(result.error || "MariaDB SQL 导入失败"));
    };
    request.onerror = () => reject(new Error("MariaDB SQL 上传连接中断"));
    request.ontimeout = () => reject(new Error("MariaDB SQL 上传超时"));
    request.send(file);
  });
}
async function importSQL(event: Event) {
  const file = (event.target as HTMLInputElement).files?.[0];
  const database = importTarget.value;
  if (!file || !database) return;
  if (!file.name.toLowerCase().endsWith(".sql") || file.size < 1) {
    ElMessage.warning("请选择非空 .sql 文件");
    return;
  }
  try {
    const answer = await ElMessageBox.prompt(
      `导入将覆盖当前数据，并先自动创建安全备份。请输入数据库名称 ${database.name}`,
      "导入 MariaDB SQL",
      {
        confirmButtonText: "创建安全备份并导入",
        cancelButtonText: "取消",
        inputPlaceholder: database.name,
        type: "warning",
      },
    );
    loading.value = true;
    await uploadImport(file, database, answer.value);
    ElMessage.success("SQL 导入完成，导入前安全备份已保留");
    await refresh();
  } catch (e) {
    if (e instanceof Error) ElMessage.error(e.message);
  } finally {
    loading.value = false;
    importTarget.value = undefined;
  }
}
async function restoreBackup(backup: Backup) {
  const database = databases.value.find(
    (item) => item.id === backup.database_id,
  );
  if (!database) {
    ElMessage.warning("原数据库不存在，当前版本不能恢复到新名称");
    return;
  }
  try {
    const answer = await ElMessageBox.prompt(
      `恢复会覆盖当前数据，并先自动创建安全备份。请输入数据库名称 ${database.name}`,
      "恢复 MariaDB 备份",
      {
        confirmButtonText: "创建安全备份并恢复",
        cancelButtonText: "取消",
        inputPlaceholder: database.name,
        type: "warning",
      },
    );
    loading.value = true;
    await props.api(`/mariadb/databases/${database.id}/restore`, "POST", {
      backup_id: backup.id,
      confirm_name: answer.value,
    });
    ElMessage.success("恢复完成，恢复前安全备份已保留");
    await refresh();
  } catch (e) {
    if (e instanceof Error) ElMessage.error(e.message);
  } finally {
    loading.value = false;
  }
}
async function removeBackup(backup: Backup) {
  try {
    const answer = await ElMessageBox.prompt(
      `将永久删除备份。请输入数据库名称 ${backup.database_name}`,
      "删除 MariaDB 备份",
      {
        confirmButtonText: "永久删除",
        cancelButtonText: "取消",
        inputPlaceholder: backup.database_name,
        type: "warning",
      },
    );
    await props.api(`/mariadb/backups/${backup.id}`, "DELETE", {
      confirm_name: answer.value,
    });
    ElMessage.success("MariaDB 备份已删除");
    await refresh();
  } catch (e) {
    if (e instanceof Error) ElMessage.error(e.message);
  }
}
const mysqlSourceLabel = (database: MySQLDatabase) => {
  const server = mysqlServers.value.find(
    (item) => item.id === database.server_id,
  );
  return `${database.name} · ${server?.name || database.server_id.slice(0, 8)} · ${server?.release_id.replace("mysql-", "MySQL ") || "MySQL"}`;
};
function openMigration() {
  const source = mysqlDatabases.value[0];
  const target = instances.value.find((item) => item.status === "running");
  if (!source || !target) {
    ElMessage.warning("需要一个可用 MySQL 数据库和一个运行中的 MariaDB 实例");
    return;
  }
  migrationForm.value = {
    source_database_id: source.id,
    target_instance_id: target.id,
    target_name: source.name,
    confirm_name: "",
  };
  migrationOpen.value = true;
}
function selectMigrationSource(id: string) {
  const source = mysqlDatabases.value.find((item) => item.id === id);
  if (source) migrationForm.value.target_name = source.name;
  migrationForm.value.confirm_name = "";
}
async function migrateFromMySQL() {
  const source = mysqlDatabases.value.find(
    (item) => item.id === migrationForm.value.source_database_id,
  );
  if (!source || migrationForm.value.confirm_name !== source.name) {
    ElMessage.warning("请输入完整 MySQL 源数据库名确认迁移");
    return;
  }
  if (!/^[a-z][a-z0-9_]{0,31}$/.test(migrationForm.value.target_name)) {
    ElMessage.warning("目标数据库名格式无效");
    return;
  }
  loading.value = true;
  try {
    const result = await props.api<{ rows: number; tables: number }>(
      `/mariadb/instances/${migrationForm.value.target_instance_id}/migrations/mysql`,
      "POST",
      {
        source_database_id: source.id,
        target_name: migrationForm.value.target_name,
        confirm_name: migrationForm.value.confirm_name,
      },
    );
    migrationOpen.value = false;
    ElMessage.success(
      `迁移完成，已核对 ${result.tables} 张表、${result.rows} 行数据`,
    );
    await refresh();
  } catch (e) {
    ElMessage.error(e instanceof Error ? e.message : "跨引擎迁移失败");
  } finally {
    loading.value = false;
  }
}
function openReverseMigration(database: Database) {
  const target = mysqlServers.value.find((item) => item.status === "running");
  if (!target) {
    ElMessage.warning("需要一个运行中的 MySQL 目标实例");
    return;
  }
  reverseMigrationForm.value = {
    source_database_id: database.id,
    source_name: database.name,
    target_server_id: target.id,
    target_name: `${database.name}_mysql`.slice(0, 32),
    confirm_name: "",
  };
  reverseMigrationOpen.value = true;
}
async function waitDatabaseJob(id: string) {
  const deadline = Date.now() + 25 * 60 * 1000;
  while (Date.now() < deadline) {
    const job = await props.api<{ state: string; error?: string }>(`/jobs/${id}`);
    if (job.state === "succeeded") return;
    if (job.state === "failed" || job.state === "needs_attention")
      throw new Error(job.error || "跨引擎迁移失败");
    await new Promise((resolve) => setTimeout(resolve, 1000));
  }
  throw new Error("跨引擎迁移等待超时，可在任务中心继续查看");
}
async function migrateToMySQL() {
  const form = reverseMigrationForm.value;
  if (form.confirm_name !== form.source_name) {
    ElMessage.warning("请输入完整 MariaDB 源数据库名确认迁移");
    return;
  }
  if (!/^[a-z][a-z0-9_]{0,31}$/.test(form.target_name)) {
    ElMessage.warning("MySQL 目标数据库名格式无效");
    return;
  }
  loading.value = true;
  try {
    const result = await props.api<{ job_id: string }>(
      `/mariadb/databases/${form.source_database_id}/migrations/mysql`,
      "POST",
      {
        target_server_id: form.target_server_id,
        target_name: form.target_name,
        confirm_name: form.confirm_name,
      },
    );
    await waitDatabaseJob(result.job_id);
    reverseMigrationOpen.value = false;
    ElMessage.success("MariaDB 基础表已迁入 MySQL，并完成逐行指纹核对");
    await refresh();
  } catch (e) {
    ElMessage.error(e instanceof Error ? e.message : "MariaDB 到 MySQL 迁移失败");
  } finally {
    loading.value = false;
  }
}
const instanceName = (id: string) =>
  instances.value.find((item) => item.id === id)?.name || id.slice(0, 8);
function createDatabase() {
  const instance = instances.value.find((item) => item.status === "running");
  if (!instance) {
    ElMessage.warning("请先启动一个 MariaDB 实例");
    return;
  }
  databaseForm.value = { instance_id: instance.id, name: "" };
  databaseOpen.value = true;
}
async function submitDatabase() {
  if (!/^[a-z][a-z0-9_]{0,31}$/.test(databaseForm.value.name)) {
    ElMessage.warning("数据库名需以小写字母开头，只能包含字母、数字和下划线");
    return;
  }
  loading.value = true;
  try {
    await props.api(
      `/mariadb/instances/${databaseForm.value.instance_id}/databases`,
      "POST",
      { name: databaseForm.value.name },
    );
    databaseOpen.value = false;
    ElMessage.success("MariaDB 数据库和独立应用账号已创建");
    await refresh();
  } catch (e) {
    ElMessage.error(e instanceof Error ? e.message : "创建数据库失败");
  } finally {
    loading.value = false;
  }
}
async function showCredentials(database: Database) {
  try {
    credentials.value = await props.api<Record<string, string | number>>(
      `/mariadb/databases/${database.id}/credentials`,
      "POST",
      {},
    );
    credentialsTarget.value = database;
    credentialsOpen.value = true;
  } catch (e) {
    ElMessage.error(e instanceof Error ? e.message : "读取连接信息失败");
  }
}
async function rotateCredentials() {
  const database = credentialsTarget.value;
  if (!database) return;
  try {
    const answer = await ElMessageBox.prompt(
      `旧密码会立即失效。请输入数据库名称 ${database.name}`,
      "重置 MariaDB 密码",
      {
        confirmButtonText: "重置并显示新密码",
        cancelButtonText: "取消",
        inputPlaceholder: database.name,
        type: "warning",
      },
    );
    credentials.value = await props.api<Record<string, string | number>>(
      `/mariadb/databases/${database.id}/credentials/rotate`,
      "POST",
      { confirm_name: answer.value },
    );
    ElMessage.success("MariaDB 应用账号密码已重置，请立即更新应用配置");
  } catch (e) {
    if (e instanceof Error) ElMessage.error(e.message);
  }
}
async function removeDatabase(database: Database) {
  try {
    const answer = await ElMessageBox.prompt(
      `将永久删除数据库及应用账号。请输入数据库名称 ${database.name}`,
      "删除 MariaDB 数据库",
      {
        confirmButtonText: "永久删除",
        cancelButtonText: "取消",
        inputPlaceholder: database.name,
        type: "warning",
      },
    );
    await props.api(`/mariadb/databases/${database.id}`, "DELETE", {
      confirm_name: answer.value,
    });
    ElMessage.success("MariaDB 数据库已删除");
    await refresh();
  } catch (e) {
    if (e instanceof Error) ElMessage.error(e.message);
  }
}
async function open() {
  drawer.value = true;
  await refresh();
}
function create() {
  if (!releases.value.length) {
    ElMessage.warning("请先安装 MariaDB 运行环境");
    return;
  }
  const used = new Set(instances.value.map((item) => item.port));
  let port = 13000;
  while (used.has(port) && port <= 13999) port++;
  form.value = {
    name: "",
    release_id: releases.value.at(-1)?.id || releases.value[0].id,
    port,
    memory_mb: 256,
  };
  createOpen.value = true;
}
async function submit() {
  if (!form.value.name.trim()) {
    ElMessage.warning("请输入实例名称");
    return;
  }
  loading.value = true;
  try {
    await props.api("/mariadb/instances", "POST", {
      ...form.value,
      name: form.value.name.trim(),
    });
    createOpen.value = false;
    ElMessage.success("MariaDB 实例已初始化并通过 SQL 版本检查");
    await refresh();
  } catch (e) {
    ElMessage.error(e instanceof Error ? e.message : "创建失败");
  } finally {
    loading.value = false;
  }
}
async function action(item: Instance, value: "start" | "stop" | "restart") {
  try {
    await props.api(`/mariadb/instances/${item.id}/${value}`, "POST", {});
    ElMessage.success("实例状态已更新");
    await refresh();
  } catch (e) {
    ElMessage.error(e instanceof Error ? e.message : "操作失败");
  }
}
async function showLogs(item: Instance) {
  try {
    logs.value = (
      await props.api<{ content: string }>(`/mariadb/instances/${item.id}/logs`)
    ).content;
    logsOpen.value = true;
  } catch (e) {
    ElMessage.error(e instanceof Error ? e.message : "读取日志失败");
  }
}
async function remove(item: Instance) {
  try {
    const name = await ElMessageBox.prompt(
      `将停止实例并永久删除数据目录。请输入实例名称 ${item.name}`,
      "删除 MariaDB 实例",
      {
        confirmButtonText: "永久删除",
        cancelButtonText: "取消",
        inputPlaceholder: item.name,
        type: "warning",
      },
    );
    await props.api(`/mariadb/instances/${item.id}`, "DELETE", {
      confirm_name: name.value,
    });
    ElMessage.success("MariaDB 实例与数据已删除");
    await refresh();
  } catch (e) {
    if (e instanceof Error) ElMessage.error(e.message);
  }
}
defineExpose({ open, refresh });
</script>

<template>
  <el-drawer
    v-model="drawer"
    title="MariaDB 实例管理"
    size="900px"
    class="mariadb-drawer"
    @open="refresh"
  >
    <div class="mariadb-summary">
      <div>
        <small>实例总数</small><strong>{{ instances.length }}</strong>
      </div>
      <div>
        <small>运行中</small><strong class="green">{{ running }}</strong>
      </div>
      <div>
        <small>版本数量</small><strong>{{ releases.length }}</strong>
      </div>
      <div class="mariadb-actions">
        <el-button :icon="Refresh" @click="refresh">刷新</el-button
        ><el-button
          type="primary"
          :icon="Plus"
          :disabled="!releases.length"
          @click="create"
          >创建实例</el-button
        >
      </div>
    </div>
    <el-table
      v-loading="loading"
      :data="instances"
      empty-text="尚未创建 MariaDB 实例"
      class="mariadb-table"
    >
      <el-table-column label="实例" min-width="150"
        ><template #default="{ row }"
          ><strong>{{ row.name }}</strong
          ><small>{{ row.id.slice(0, 8) }}</small></template
        ></el-table-column
      >
      <el-table-column label="版本" min-width="110"
        ><template #default="{ row }"
          >MariaDB {{ row.release_id.replace("mariadb-", "") }}</template
        ></el-table-column
      >
      <el-table-column label="本机地址" min-width="145"
        ><template #default="{ row }"
          >127.0.0.1:{{ row.port }}</template
        ></el-table-column
      >
      <el-table-column label="数据" min-width="115"
        ><template #default="{ row }">{{
          memory(row.data_bytes || 0)
        }}</template></el-table-column
      >
      <el-table-column label="连接" width="75" prop="connections" />
      <el-table-column label="状态" width="95"
        ><template #default="{ row }"
          ><el-tag
            :type="
              row.status === 'running'
                ? 'success'
                : row.status === 'needs_attention'
                  ? 'danger'
                  : 'info'
            "
            >{{
              row.status === "running"
                ? "运行中"
                : row.status === "stopped"
                  ? "已停止"
                  : row.status === "starting"
                    ? "启动中"
                    : "需核对"
            }}</el-tag
          ></template
        ></el-table-column
      >
      <el-table-column label="操作" min-width="245" fixed="right"
        ><template #default="{ row }"
          ><el-button
            link
            type="primary"
            :disabled="row.status === 'starting'"
            @click="action(row, row.status === 'running' ? 'stop' : 'start')"
            >{{ row.status === "running" ? "停止" : "启动" }}</el-button
          ><el-button
            link
            type="primary"
            :disabled="row.status !== 'running'"
            @click="action(row, 'restart')"
            >重启</el-button
          ><el-button link type="primary" @click="showLogs(row)">日志</el-button
          ><el-button link type="danger" @click="remove(row)"
            >删除</el-button
          ></template
        ></el-table-column
      >
    </el-table>
    <div class="mariadb-database-heading">
      <div>
        <strong>应用数据库</strong><small>每个数据库使用独立本机账号</small>
      </div>
      <el-button type="primary" :disabled="!running" @click="createDatabase"
        >创建数据库</el-button
      >
      <el-button
        :disabled="!running || !mysqlDatabases.length"
        @click="openMigration"
        >从 MySQL 迁移</el-button
      >
    </div>
    <el-table
      v-loading="loading"
      :data="databases"
      empty-text="尚未创建 MariaDB 数据库"
      class="mariadb-table"
    >
      <el-table-column label="数据库" min-width="160"
        ><template #default="{ row }"
          ><strong>{{ row.name }}</strong
          ><small>{{ row.username }}</small></template
        ></el-table-column
      >
      <el-table-column label="所属实例" min-width="150"
        ><template #default="{ row }">{{
          instanceName(row.instance_id)
        }}</template></el-table-column
      >
      <el-table-column label="状态" width="100"
        ><template #default="{ row }"
          ><el-tag
            :type="
              instances.find((item) => item.id === row.instance_id)?.status ===
              'running'
                ? 'success'
                : 'info'
            "
            >{{
              instances.find((item) => item.id === row.instance_id)?.status ===
              "running"
                ? "可连接"
                : "实例停止"
            }}</el-tag
          ></template
        ></el-table-column
      >
      <el-table-column label="操作" width="330"
        ><template #default="{ row }"
          ><el-button link type="primary" @click="showCredentials(row)"
            >连接信息</el-button
          ><el-button link type="primary" @click="backupDatabase(row)"
            >备份</el-button
          ><el-button link type="primary" @click="chooseImport(row)"
            >导入</el-button
          ><el-button link type="primary" @click="openReverseMigration(row)"
            >迁到 MySQL</el-button
          ><el-button link type="danger" @click="removeDatabase(row)"
            >删除</el-button
          ></template
        ></el-table-column
      >
    </el-table>
    <input
      ref="importInput"
      type="file"
      accept=".sql,application/sql,text/plain"
      hidden
      aria-label="MariaDB SQL 文件"
      @change="importSQL"
    />
    <div class="mariadb-database-heading">
      <div>
        <strong>本地备份</strong
        ><small>SHA-256 校验 · 恢复前自动安全备份</small>
      </div>
    </div>
    <el-table
      v-loading="loading"
      :data="backups"
      empty-text="尚未创建 MariaDB 备份"
      class="mariadb-table"
    >
      <el-table-column label="数据库" min-width="140" prop="database_name" />
      <el-table-column label="版本" width="110"
        ><template #default="{ row }"
          >MariaDB {{ row.version }}</template
        ></el-table-column
      >
      <el-table-column label="大小" width="100"
        ><template #default="{ row }">{{
          memory(row.bytes)
        }}</template></el-table-column
      >
      <el-table-column label="时间" min-width="170" prop="created_at" />
      <el-table-column label="摘要" min-width="130"
        ><template #default="{ row }"
          ><code>{{ row.sha256.slice(0, 12) }}…</code></template
        ></el-table-column
      >
      <el-table-column label="操作" width="175"
        ><template #default="{ row }"
          ><el-link
            type="primary"
            :underline="false"
            :href="apiURL(`/mariadb/backups/${row.id}/download`)"
            >下载</el-link
          ><el-button link type="primary" @click="restoreBackup(row)"
            >恢复</el-button
          ><el-button link type="danger" @click="removeBackup(row)"
            >删除</el-button
          ></template
        ></el-table-column
      >
    </el-table>
    <div class="mariadb-security">
      <strong>访问边界</strong
      ><span
        >所有实例只监听 127.0.0.1，以 Unix Socket 管理本机 root，并由独立
        panel-mariadb 系统账户运行。</span
      >
    </div>
  </el-drawer>
  <el-dialog v-model="createOpen" title="创建 MariaDB 实例" width="520px">
    <el-form label-position="top">
      <el-form-item label="实例名称"
        ><el-input
          v-model="form.name"
          maxlength="40"
          placeholder="例如：业务数据库"
      /></el-form-item>
      <el-form-item label="MariaDB 版本"
        ><el-select v-model="form.release_id" style="width: 100%"
          ><el-option
            v-for="item in releases"
            :key="item.id"
            :label="`MariaDB ${item.version}`"
            :value="item.id" /></el-select
      ></el-form-item>
      <div class="mariadb-form-grid">
        <el-form-item label="本机端口"
          ><el-input-number
            v-model="form.port"
            :min="13000"
            :max="13999"
            controls-position="right" /></el-form-item
        ><el-form-item label="InnoDB 缓冲池（MB）"
          ><el-input-number
            v-model="form.memory_mb"
            :min="128"
            :max="32768"
            :step="128"
            controls-position="right"
        /></el-form-item>
      </div>
      <el-alert
        :closable="false"
        type="info"
        title="数据目录独立持久化，默认 utf8mb4；TCP 端口仅监听回环地址。"
      />
    </el-form>
    <template #footer
      ><el-button @click="createOpen = false">取消</el-button
      ><el-button type="primary" :loading="loading" @click="submit"
        >创建并启动</el-button
      ></template
    >
  </el-dialog>
  <el-dialog
    v-model="reverseMigrationOpen"
    title="MariaDB 迁移到 MySQL"
    width="560px"
  >
    <el-form label-position="top" @submit.prevent="migrateToMySQL">
      <el-form-item label="MariaDB 源数据库"
        ><el-input :model-value="reverseMigrationForm.source_name" disabled
      /></el-form-item>
      <el-form-item label="MySQL 目标实例"
        ><el-select
          v-model="reverseMigrationForm.target_server_id"
          aria-label="MySQL 目标实例"
          style="width: 100%"
          ><el-option
            v-for="item in mysqlServers.filter(
              (value) => value.status === 'running',
            )"
            :key="item.id"
            :label="`${item.name} · ${item.release_id.replace('mysql-', 'MySQL ')}`"
            :value="item.id" /></el-select
      ></el-form-item>
      <el-form-item label="MySQL 目标数据库名称"
        ><el-input
          v-model="reverseMigrationForm.target_name"
          aria-label="MySQL 目标数据库名称"
          maxlength="32"
      /></el-form-item>
      <el-alert
        :closable="false"
        type="warning"
        title="首版接受 InnoDB 基础表。源库保持不变；视图、过程、触发器和事件需先单独转换，失败目标会清理。"
      />
      <el-form-item
        label="输入完整 MariaDB 源数据库名称确认"
        class="migration-confirm"
        ><el-input
          v-model="reverseMigrationForm.confirm_name"
          aria-label="反向迁移确认源数据库名称"
      /></el-form-item>
    </el-form>
    <template #footer
      ><el-button @click="reverseMigrationOpen = false">取消</el-button
      ><el-button type="primary" :loading="loading" @click="migrateToMySQL"
        >开始兼容迁移</el-button
      ></template
    >
  </el-dialog>
  <el-dialog v-model="databaseOpen" title="创建 MariaDB 数据库" width="500px">
    <el-form label-position="top" @submit.prevent="submitDatabase">
      <el-form-item label="所属实例"
        ><el-select v-model="databaseForm.instance_id" style="width: 100%"
          ><el-option
            v-for="item in instances.filter(
              (value) => value.status === 'running',
            )"
            :key="item.id"
            :label="`${item.name} · ${item.release_id.replace('mariadb-', 'MariaDB ')}`"
            :value="item.id" /></el-select
      ></el-form-item>
      <el-form-item label="数据库名称"
        ><el-input
          v-model="databaseForm.name"
          maxlength="32"
          placeholder="例如：website_db"
      /></el-form-item>
      <el-alert
        :closable="false"
        type="info"
        title="创建 utf8mb4 数据库和仅拥有该库权限的随机应用账号。"
      />
    </el-form>
    <template #footer
      ><el-button @click="databaseOpen = false">取消</el-button
      ><el-button type="primary" :loading="loading" @click="submitDatabase"
        >创建数据库</el-button
      ></template
    >
  </el-dialog>
  <el-dialog v-model="migrationOpen" title="MySQL 迁移到 MariaDB" width="560px">
    <el-form label-position="top" @submit.prevent="migrateFromMySQL">
      <el-form-item label="MySQL 源数据库"
        ><el-select
          v-model="migrationForm.source_database_id"
          aria-label="MySQL 源数据库"
          style="width: 100%"
          @change="selectMigrationSource"
          ><el-option
            v-for="item in mysqlDatabases"
            :key="item.id"
            :label="mysqlSourceLabel(item)"
            :value="item.id" /></el-select
      ></el-form-item>
      <el-form-item label="MariaDB 目标实例"
        ><el-select
          v-model="migrationForm.target_instance_id"
          aria-label="MariaDB 目标实例"
          style="width: 100%"
          ><el-option
            v-for="item in instances.filter(
              (value) => value.status === 'running',
            )"
            :key="item.id"
            :label="`${item.name} · ${item.release_id.replace('mariadb-', 'MariaDB ')}`"
            :value="item.id" /></el-select
      ></el-form-item>
      <el-form-item label="目标数据库名称"
        ><el-input
          v-model="migrationForm.target_name"
          aria-label="迁移目标数据库名称"
          maxlength="32"
      /></el-form-item>
      <el-alert
        :closable="false"
        type="warning"
        title="首版迁移接受基础表，源库保持不变；视图、过程、触发器和事件需先单独转换。目标失败会自动清理。"
      />
      <el-form-item label="输入完整源数据库名称确认" class="migration-confirm"
        ><el-input
          v-model="migrationForm.confirm_name"
          aria-label="迁移确认源数据库名称"
      /></el-form-item>
    </el-form>
    <template #footer
      ><el-button @click="migrationOpen = false">取消</el-button
      ><el-button type="primary" :loading="loading" @click="migrateFromMySQL"
        >开始兼容迁移</el-button
      ></template
    >
  </el-dialog>
  <el-dialog v-model="credentialsOpen" title="MariaDB 连接信息" width="540px">
    <el-descriptions :column="1" border>
      <el-descriptions-item label="主机">{{
        credentials.host
      }}</el-descriptions-item>
      <el-descriptions-item label="端口">{{
        credentials.port
      }}</el-descriptions-item>
      <el-descriptions-item label="数据库">{{
        credentials.database
      }}</el-descriptions-item>
      <el-descriptions-item label="用户名">{{
        credentials.username
      }}</el-descriptions-item>
      <el-descriptions-item label="密码"
        ><code>{{ credentials.password }}</code></el-descriptions-item
      >
    </el-descriptions>
    <template #footer
      ><el-button type="danger" plain @click="rotateCredentials"
        >重置密码</el-button
      ><el-button
        @click="
          credentialsOpen = false;
          credentials = {};
          credentialsTarget = undefined;
        "
        >关闭</el-button
      ></template
    >
  </el-dialog>
  <el-dialog v-model="logsOpen" title="MariaDB 服务日志" width="760px">
    <pre class="mariadb-logs">{{ logs || "暂无日志" }}</pre>
    <template #footer
      ><el-button :icon="Tickets" @click="logsOpen = false"
        >关闭</el-button
      ></template
    ></el-dialog
  >
</template>

<style scoped>
.mariadb-summary {
  display: grid;
  grid-template-columns: repeat(3, minmax(100px, 1fr)) auto;
  gap: 12px;
  margin-bottom: 18px;
}
.mariadb-summary > div {
  border: 1px solid #e8edf3;
  border-radius: 8px;
  padding: 14px 16px;
  background: #fff;
}
.mariadb-summary small {
  display: block;
  color: #718096;
  margin-bottom: 8px;
}
.mariadb-summary strong {
  font-size: 24px;
  color: #172033;
}
.mariadb-summary .green {
  color: #08a858;
}
.mariadb-summary .mariadb-actions {
  display: flex;
  align-items: center;
  gap: 8px;
  border: 0;
  padding: 0;
}
.mariadb-table {
  border: 1px solid #e8edf3;
  border-radius: 8px;
}
.mariadb-table strong,
.mariadb-table small {
  display: block;
}
.mariadb-table small {
  color: #94a3b8;
  margin-top: 4px;
}
.mariadb-security {
  display: flex;
  gap: 12px;
  margin-top: 16px;
  padding: 14px 16px;
  border-radius: 8px;
  background: #f0fbf5;
  color: #4b6474;
  font-size: 13px;
}
.mariadb-database-heading {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 16px;
  margin: 22px 0 12px;
}
.mariadb-database-heading > div:first-child {
  margin-right: auto;
}
.migration-confirm {
  margin-top: 16px;
}
.mariadb-database-heading strong,
.mariadb-database-heading small {
  display: block;
}
.mariadb-database-heading small {
  color: #94a3b8;
  margin-top: 4px;
}
.mariadb-security strong {
  color: #08a858;
  white-space: nowrap;
}
.mariadb-form-grid {
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: 16px;
}
.mariadb-form-grid :deep(.el-input-number) {
  width: 100%;
}
.mariadb-logs {
  max-height: 480px;
  overflow: auto;
  margin: 0;
  padding: 16px;
  background: #111820;
  color: #d9e7df;
  border-radius: 7px;
  font:
    12px/1.6 ui-monospace,
    monospace;
  white-space: pre-wrap;
}
@media (max-width: 760px) {
  .mariadb-summary {
    grid-template-columns: 1fr 1fr;
  }
  .mariadb-summary .mariadb-actions {
    grid-column: 1/-1;
  }
  .mariadb-form-grid {
    grid-template-columns: 1fr;
  }
  .mariadb-security {
    flex-direction: column;
  }
}
</style>
