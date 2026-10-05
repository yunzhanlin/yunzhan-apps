<script setup lang="ts">
import { formatPanelDateTime } from "./panelTime";
import { apiURL } from "./panelBase";
import { computed, onMounted, onUnmounted, ref, watch } from "vue";
import { ElMessage, ElMessageBox } from "element-plus";

interface Backup {
  id: string;
  kind: "database" | "mariadb" | "site";
  target_id: string;
  target_name: string;
  parent_name?: string;
  version?: string;
  format: string;
  files?: number;
  source_bytes?: number;
  bytes: number;
  sha256: string;
  schedule?: string;
  created_at: string;
}
interface BackupRemote {
  id: string;
  name: string;
  base_url: string;
  username: string;
  path_prefix: string;
  enabled: boolean;
  password_set: boolean;
  last_test_at?: string;
  last_error?: string;
  created_at: string;
  updated_at: string;
}
interface RemoteCopy {
  id: string;
  remote_id: string;
  remote_name: string;
  artifact_kind: "database" | "mariadb" | "site";
  artifact_id: string;
  remote_path?: string;
  bytes: number;
  sha256: string;
  state: "pending" | "running" | "succeeded" | "failed";
  attempts: number;
  error?: string;
  created_at: string;
  completed_at?: string;
}
interface SystemBackup {
  id: string;
  format: string;
  bytes: number;
  sha256: string;
  files: number;
  schema: number;
  arch: string;
  created_at: string;
}
const props = defineProps<{
  api: <T>(path: string, method?: string, body?: unknown) => Promise<T>;
  onJob: (id: string) => Promise<void>;
  sites: { id: string; name: string; domain: string; status: string }[];
}>();
const backupSiteDialog = ref(false), backupSiteID = ref(""), backupConfirm = ref(""), backupSiteSaving = ref(false);
const backupSite = computed(() => props.sites.find(item => item.id === backupSiteID.value));
const backupableSites = computed(() => props.sites.filter(item => !["provisioning", "needs_attention", "archived"].includes(item.status)));
function openSiteBackup(siteID = "") {
  backupSiteID.value = backupableSites.value.find(item => item.id === siteID)?.id || backupableSites.value[0]?.id || "";
  backupConfirm.value = "";
  backupSiteDialog.value = true;
}
async function createSiteBackup() {
  if (backupSiteSaving.value || !backupSite.value || backupConfirm.value !== backupSite.value.name) return;
  backupSiteSaving.value = true;
  try {
    const result = await props.api<{ job_id: string }>("/backups/sites", "POST", { site_id: backupSite.value.id, confirm_name: backupConfirm.value });
    backupSiteDialog.value = false;
    ElMessage.success("网站备份已排队，完成后会出现在备份中心");
    await props.onJob(result.job_id);
  } catch (e) { ElMessage.error(e instanceof Error ? e.message : "创建网站备份失败"); }
  finally { backupSiteSaving.value = false; }
}
const backups = ref<Backup[]>([]),
  remotes = ref<BackupRemote[]>([]),
  remoteCopies = ref<RemoteCopy[]>([]),
  systemBackups = ref<SystemBackup[]>([]),
  scope = ref("all"),
  query = ref(""),
  page = ref(1),
  error = ref(""),
  loading = ref(false),
  remoteDialog = ref(false),
  remoteSaving = ref(false),
  editingRemote = ref(false),
  systemDialog = ref(false),
  systemSaving = ref(false),
  systemPassphrase = ref(""),
  systemPassphraseAgain = ref("");
const freshRemote = () => ({
  id: "",
  name: "",
  base_url: "",
  username: "",
  password: "",
  path_prefix: "panel-backups",
  enabled: true,
});
const remoteDraft = ref(freshRemote());
const sorted = computed(() =>
  backups.value
    .filter((item) => scope.value === "all" || item.kind === scope.value)
    .filter((item) =>
      `${item.target_name} ${item.parent_name || ""} ${item.schedule || ""}`
        .toLowerCase()
        .includes(query.value.toLowerCase()),
    )
    .sort((a, b) => b.created_at.localeCompare(a.created_at)),
);
const visible = computed(() =>
  sorted.value.slice((page.value - 1) * 12, page.value * 12),
);
watch([scope, query], () => (page.value = 1));
const totalBytes = computed(() =>
  backups.value.reduce((sum, item) => sum + item.bytes, 0),
);
const count = (kind: string) =>
  backups.value.filter((item) => item.kind === kind).length;
const size = (value = 0) => {
  const units = ["B", "KiB", "MiB", "GiB", "TiB"];
  let index = 0;
  while (value >= 1024 && index < units.length - 1) {
    value /= 1024;
    index++;
  }
  return `${value.toFixed(index ? 1 : 0)} ${units[index]}`;
};
const time = (value: string) =>
  formatPanelDateTime(value);
const download = (item: Backup) =>
  item.kind === "database"
    ? apiURL(`/databases/backups/${item.id}/download`)
    : item.kind === "mariadb"
      ? apiURL(`/mariadb/backups/${item.id}/download`)
      : apiURL(`/backups/sites/${item.id}/download`);
async function refresh() {
  if (loading.value) return;
  loading.value = true;
  try {
    const [backupData, remoteData, copyData, systemData] = await Promise.all([
      props.api<{ backups: Backup[] }>("/backups"),
      props.api<{ remotes: BackupRemote[] }>("/backups/remotes"),
      props.api<{ copies: RemoteCopy[] }>("/backups/remote-copies"),
      props.api<{ backups: SystemBackup[] }>("/backups/system"),
    ]);
    backups.value = backupData.backups;
    remotes.value = remoteData.remotes;
    remoteCopies.value = copyData.copies;
    systemBackups.value = systemData.backups;
    error.value = "";
  } catch (e) {
    error.value = (e as Error).message;
  } finally {
    loading.value = false;
  }
}
function openSystemBackup() {
  systemPassphrase.value = "";
  systemPassphraseAgain.value = "";
  systemDialog.value = true;
}
async function createSystemBackup() {
  if (systemSaving.value) return;
  if (systemPassphrase.value !== systemPassphraseAgain.value) {
    ElMessage.error("两次输入的恢复密码不一致");
    return;
  }
  systemSaving.value = true;
  try {
    await props.api<SystemBackup>("/backups/system", "POST", {
      passphrase: systemPassphrase.value,
    });
    systemPassphrase.value = "";
    systemPassphraseAgain.value = "";
    systemDialog.value = false;
    await refresh();
    ElMessage.success("面板元数据整包已加密创建，请下载并妥善保存恢复密码");
  } catch (e) {
    ElMessage.error((e as Error).message);
  } finally {
    systemSaving.value = false;
  }
}
function createRemote() {
  remoteDraft.value = freshRemote();
  editingRemote.value = false;
  remoteDialog.value = true;
}
function editRemote(item: BackupRemote) {
  remoteDraft.value = {
    id: item.id,
    name: item.name,
    base_url: item.base_url,
    username: item.username,
    password: "",
    path_prefix: item.path_prefix,
    enabled: item.enabled,
  };
  editingRemote.value = true;
  remoteDialog.value = true;
}
async function saveRemote() {
  if (remoteSaving.value) return;
  remoteSaving.value = true;
  try {
    const path = editingRemote.value
      ? `/backups/remotes/${remoteDraft.value.id}`
      : "/backups/remotes";
    await props.api(
      path,
      editingRemote.value ? "PUT" : "POST",
      remoteDraft.value,
    );
    remoteDialog.value = false;
    await refresh();
    ElMessage.success(
      editingRemote.value ? "远端存储已更新" : "远端存储已创建",
    );
  } catch (e) {
    ElMessage.error((e as Error).message);
  } finally {
    remoteSaving.value = false;
  }
}
async function testRemote(item: BackupRemote) {
  try {
    await props.api(`/backups/remotes/${item.id}/test`, "POST", {});
    await refresh();
    ElMessage.success("WebDAV 连接和认证通过");
  } catch (e) {
    await refresh();
    ElMessage.error((e as Error).message);
  }
}
async function toggleRemote(item: BackupRemote, enabled: boolean) {
  try {
    await props.api(`/backups/remotes/${item.id}`, "PUT", {
      name: item.name,
      base_url: item.base_url,
      username: item.username,
      password: "",
      path_prefix: item.path_prefix,
      enabled,
    });
    await refresh();
  } catch (e) {
    ElMessage.error((e as Error).message);
  }
}
async function syncRemote(item: Backup, remoteID: string) {
  try {
    await props.api(
      `/backups/${item.kind}/${item.id}/remotes/${remoteID}`,
      "POST",
      {},
    );
    ElMessage.success("已加入远端传输队列");
    setTimeout(refresh, 2500);
  } catch (e) {
    ElMessage.error((e as Error).message);
  }
}
async function retryRemoteCopy(copy: RemoteCopy) {
  const backup = backups.value.find(
    (item) => item.id === copy.artifact_id && item.kind === copy.artifact_kind,
  );
  const remote = remotes.value.find((item) => item.id === copy.remote_id);
  if (!backup) {
    ElMessage.error("本地备份已不存在，不能重试远端传输");
    return;
  }
  if (!remote?.enabled) {
    ElMessage.error("请先启用并测试该远端存储");
    return;
  }
  await syncRemote(backup, copy.remote_id);
  await refresh();
}
const copyStateName: Record<string, string> = {
  pending: "等待传输",
  running: "传输中",
  succeeded: "已核验",
  failed: "失败",
};
const copyStateType = (state: string) =>
  state === "succeeded" ? "success" : state === "failed" ? "danger" : "warning";
async function restoreDatabase(item: Backup) {
  try {
    const { value } = await ElMessageBox.prompt(
      `将用所选备份恢复“${item.target_name}”。系统会先保留当前数据副本。请输入数据库名称确认。`,
      "恢复数据库",
      {
        confirmButtonText: "备份当前数据并恢复",
        cancelButtonText: "取消",
        type: "warning",
        inputValidator: (value) =>
          value === item.target_name || "请输入完全一致的数据库名称",
      },
    );
    const result = await props.api<{ job_id: string }>(
      `/databases/items/${item.target_id}/restore`,
      "POST",
      {
        backup_id: item.id,
        confirm_name: value,
      },
    );
    await props.onJob(result.job_id);
  } catch (e) {
    if (e !== "cancel" && e !== "close") ElMessage.error((e as Error).message);
  }
}
async function restoreMariaDB(item: Backup) {
  try {
    const { value } = await ElMessageBox.prompt(
      `将先保留“${item.target_name}”当前数据，再用所选 MariaDB SQL 恢复。请输入数据库名称确认。`,
      "恢复 MariaDB 数据库",
      { confirmButtonText: "备份当前数据并恢复", cancelButtonText: "取消", type: "warning", inputValidator: (value) => value === item.target_name || "请输入完全一致的数据库名称" },
    );
    await props.api(`/mariadb/databases/${item.target_id}/restore`, "POST", { backup_id: item.id, confirm_name: value });
    await refresh();
  } catch (e) { if (e !== "cancel" && e !== "close") ElMessage.error((e as Error).message); }
}
async function restoreSite(item: Backup) {
  try {
    const { value } = await ElMessageBox.prompt(
      `将先保留“${item.target_name}”当前公开目录，再用所选 ZIP 恢复并检查站点响应。请输入网站名称确认。`,
      "恢复网站文件",
      {
        confirmButtonText: "保留当前目录并恢复",
        cancelButtonText: "取消",
        type: "warning",
        inputValidator: (value) =>
          value === item.target_name || "请输入完全一致的网站名称",
      },
    );
    const result = await props.api<{ job_id: string }>(
      `/backups/sites/${item.id}/restore`,
      "POST",
      { confirm_name: value },
    );
    await props.onJob(result.job_id);
  } catch (e) {
    if (e !== "cancel" && e !== "close") ElMessage.error((e as Error).message);
  }
}
let timer: ReturnType<typeof setInterval>;
onMounted(() => {
  void refresh();
  timer = setInterval(refresh, 10000);
});
onUnmounted(() => clearInterval(timer));
defineExpose({ refresh, openSiteBackup });
</script>

<template>
  <div class="backup-page">
    <el-alert
      v-if="error"
      :title="error"
      type="error"
      :closable="false"
      show-icon
    />
    <div class="backup-summary">
      <article class="panel-card">
        <small>本地备份</small><strong>{{ backups.length }}</strong
        ><span>已核对的可用产物</span>
      </article>
      <article class="panel-card">
        <small>数据库</small><strong>{{ count("database") }}</strong
        ><span>原生 SQL 逻辑备份</span>
      </article>
      <article class="panel-card">
        <small>网站文件</small><strong>{{ count("site") }}</strong
        ><span>不跟随链接的 ZIP</span>
      </article>
      <article class="panel-card">
        <small>远端副本</small
        ><strong>{{
          remoteCopies.filter((item) => item.state === "succeeded").length
        }}</strong
        ><span
          >{{
            remotes.filter((item) => item.enabled).length
          }}
          个存储已启用</span
        >
      </article>
      <article class="panel-card">
        <small>占用空间</small><strong>{{ size(totalBytes) }}</strong
        ><span>当前面板登记总量</span>
      </article>
    </div>
    <section class="panel-card system-backups">
      <div class="backup-toolbar">
        <div>
          <h2>面板整包备份</h2>
          <p>
            加密保存
            SQLite、凭据主密钥、证书和服务配置；网站文件与数据库数据继续使用下方独立备份。
          </p>
        </div>
        <el-button type="primary" @click="openSystemBackup"
          >创建加密整包</el-button
        >
      </div>
      <el-alert
        title="恢复密码不会保存到面板。丢失密码无法解密；恢复需要在新机停止面板后使用离线命令。"
        type="warning"
        :closable="false"
        show-icon
      />
      <div v-if="systemBackups.length" class="system-backup-list">
        <article v-for="item in systemBackups.slice(0, 5)" :key="item.id">
          <div>
            <strong>控制面快照 · schema {{ item.schema }}</strong
            ><small>{{ time(item.created_at) }} · {{ item.arch }}</small>
          </div>
          <span>{{ item.files }} 个文件 · {{ size(item.bytes) }}</span>
          <el-button
            tag="a"
            type="primary"
            plain
            :href="apiURL(`/backups/system/${item.id}/download`)"
            >下载</el-button
          >
        </article>
      </div>
      <el-empty v-else description="还没有面板整包备份" :image-size="52" />
    </section>
    <section class="panel-card remote-list">
      <div class="backup-toolbar">
        <div>
          <h2>远端存储</h2>
          <p>
            通过 WebDAV 保存数据库或网站备份；上传后重新读取并核对 SHA-256。
          </p>
        </div>
        <el-button type="primary" plain @click="createRemote"
          >添加 WebDAV</el-button
        >
      </div>
      <el-table :data="remotes" empty-text="还没有远端存储。">
        <el-table-column label="名称" min-width="160">
          <template #default="{ row }"
            ><strong>{{ row.name }}</strong
            ><span class="table-secondary">{{
              row.path_prefix || "根目录"
            }}</span></template
          >
        </el-table-column>
        <el-table-column label="地址" min-width="260" prop="base_url" />
        <el-table-column label="账号" min-width="130" prop="username" />
        <el-table-column label="最近测试" min-width="180">
          <template #default="{ row }"
            ><span :class="{ 'remote-error': row.last_error }">{{
              row.last_error ||
              (row.last_test_at
                ? `通过 · ${time(row.last_test_at)}`
                : "尚未测试")
            }}</span></template
          >
        </el-table-column>
        <el-table-column label="启用" width="85">
          <template #default="{ row }"
            ><el-switch
              :model-value="row.enabled"
              aria-label="启用远端存储"
              @change="toggleRemote(row, Boolean($event))"
          /></template>
        </el-table-column>
        <el-table-column label="操作" width="145" fixed="right">
          <template #default="{ row }"
            ><el-button link type="primary" @click="testRemote(row)"
              >测试</el-button
            ><el-button link type="primary" @click="editRemote(row)"
              >编辑</el-button
            ></template
          >
        </el-table-column>
      </el-table>
      <div v-if="remoteCopies.length" class="remote-history">
        <h3>最近远端传输</h3>
        <div
          v-for="copy in remoteCopies.slice(0, 8)"
          :key="copy.id"
          class="remote-history-row"
        >
          <div>
            <strong>{{ copy.remote_name }}</strong
            ><small>{{ copy.remote_path || copy.artifact_id }}</small>
          </div>
          <el-tag :type="copyStateType(copy.state)" size="small">{{
            copyStateName[copy.state]
          }}</el-tag>
          <span :class="{ 'remote-error': copy.error }">{{
            copy.error || `${size(copy.bytes)} · ${copy.attempts} 次尝试`
          }}</span>
          <el-button
            v-if="copy.state === 'failed'"
            link
            type="primary"
            @click="retryRemoteCopy(copy)"
            >重试</el-button
          >
        </div>
      </div>
    </section>
    <section class="panel-card backup-list">
      <div class="backup-toolbar">
        <div>
          <h2>备份中心</h2>
          <p>统一查看本地数据库和网站文件备份；摘要不一致时拒绝下载或恢复。</p>
        </div>
        <div class="backup-filters">
          <el-button type="primary" @click="openSiteBackup()">备份站点</el-button>
          <el-segmented
            v-model="scope"
            :options="[
              { label: '全部', value: 'all' },
              { label: 'MySQL', value: 'database' },
              { label: 'MariaDB', value: 'mariadb' },
              { label: '网站', value: 'site' },
            ]"
          />
          <el-input
            v-model="query"
            clearable
            placeholder="搜索目标或计划"
            aria-label="搜索备份"
          />
        </div>
      </div>
      <el-table :data="visible" empty-text="还没有备份。">
        <el-table-column label="备份目标" min-width="210">
          <template #default="{ row }"
            ><strong>{{ row.target_name }}</strong
            ><span class="table-secondary">{{
              row.parent_name
            }}</span></template
          >
        </el-table-column>
        <el-table-column label="类型" width="120">
          <template #default="{ row }"
            ><el-tag
              size="small"
              :type="row.kind === 'database' || row.kind === 'mariadb' ? 'success' : 'info'"
              >{{ row.kind === "database" ? "MySQL" : row.kind === "mariadb" ? "MariaDB" : "网站文件" }}</el-tag
            ></template
          >
        </el-table-column>
        <el-table-column label="版本 / 内容" min-width="145">
          <template #default="{ row }">{{
            row.kind === "database"
              ? `MySQL ${row.version}`
              : row.kind === "mariadb"
                ? `MariaDB ${row.version}`
                : `${row.files || 0} 个条目`
          }}</template>
        </el-table-column>
        <el-table-column label="大小" width="105"
          ><template #default="{ row }">{{
            size(row.bytes)
          }}</template></el-table-column
        >
        <el-table-column label="来源" min-width="150"
          ><template #default="{ row }">{{
            row.schedule || "手动操作"
          }}</template></el-table-column
        >
        <el-table-column label="创建时间" min-width="170"
          ><template #default="{ row }">{{
            time(row.created_at)
          }}</template></el-table-column
        >
        <el-table-column label="操作" min-width="245" fixed="right">
          <template #default="{ row }"
            ><el-button link type="primary" tag="a" :href="download(row)"
              >下载</el-button
            ><el-button
              v-if="row.kind === 'database'"
              link
              type="warning"
              @click="restoreDatabase(row)"
              >恢复</el-button
            ><el-button v-else-if="row.kind === 'mariadb'" link type="warning" @click="restoreMariaDB(row)"
              >恢复</el-button
            ><el-button v-else link type="warning" @click="restoreSite(row)"
              >恢复</el-button
            ><el-dropdown
              trigger="click"
              :disabled="!remotes.some((remote) => remote.enabled)"
              @command="syncRemote(row, String($event))"
            >
              <el-button link type="primary">远端备份</el-button>
              <template #dropdown
                ><el-dropdown-menu
                  ><el-dropdown-item
                    v-for="remote in remotes.filter((item) => item.enabled)"
                    :key="remote.id"
                    :command="remote.id"
                    >{{ remote.name }}</el-dropdown-item
                  ></el-dropdown-menu
                ></template
              >
            </el-dropdown></template
          >
        </el-table-column>
      </el-table>
      <div class="backup-pagination">
        <span>共 {{ sorted.length }} 份</span>
        <el-pagination
          v-model:current-page="page"
          :page-size="12"
          layout="prev, pager, next"
          :total="sorted.length"
          hide-on-single-page
        />
      </div>
      <div class="backup-cards">
        <article v-for="item in visible" :key="item.id" class="backup-card">
          <div>
            <div>
              <strong>{{ item.target_name }}</strong
              ><small>{{ item.parent_name }}</small>
            </div>
            <el-tag
              size="small"
              :type="item.kind === 'database' || item.kind === 'mariadb' ? 'success' : 'info'"
              >{{ item.kind === "database" ? "MySQL" : item.kind === "mariadb" ? "MariaDB" : "网站文件" }}</el-tag
            >
          </div>
          <dl>
            <div>
              <dt>内容</dt>
              <dd>
                {{
                  item.kind === "database"
                    ? `MySQL ${item.version}`
                    : item.kind === "mariadb"
                      ? `MariaDB ${item.version}`
                      : `${item.files || 0} 个条目`
                }}
              </dd>
            </div>
            <div>
              <dt>大小</dt>
              <dd>{{ size(item.bytes) }}</dd>
            </div>
            <div>
              <dt>来源</dt>
              <dd>{{ item.schedule || "手动操作" }}</dd>
            </div>
            <div>
              <dt>时间</dt>
              <dd>{{ time(item.created_at) }}</dd>
            </div>
          </dl>
          <div class="backup-actions">
            <el-button
              tag="a"
              :href="download(item)"
              size="small"
              type="primary"
              plain
              >下载</el-button
            ><el-button
              v-if="item.kind === 'database'"
              size="small"
              type="warning"
              plain
              @click="restoreDatabase(item)"
              >恢复</el-button
            ><el-button
              v-else-if="item.kind === 'mariadb'"
              size="small"
              type="warning"
              plain
              @click="restoreMariaDB(item)"
              >恢复</el-button
            ><el-button
              v-else
              size="small"
              type="warning"
              plain
              @click="restoreSite(item)"
              >恢复</el-button
            ><el-dropdown
              trigger="click"
              :disabled="!remotes.some((remote) => remote.enabled)"
              @command="syncRemote(item, String($event))"
              ><el-button size="small" type="primary" plain>远端备份</el-button
              ><template #dropdown
                ><el-dropdown-menu
                  ><el-dropdown-item
                    v-for="remote in remotes.filter((value) => value.enabled)"
                    :key="remote.id"
                    :command="remote.id"
                    >{{ remote.name }}</el-dropdown-item
                  ></el-dropdown-menu
                ></template
              ></el-dropdown
            >
          </div>
        </article>
      </div>
    </section>
    <el-dialog v-model="backupSiteDialog" title="创建网站文件备份" width="500px">
      <p>归档所选网站的公开目录，完成后核对 ZIP 大小和 SHA-256。网站服务会保持运行。</p>
      <el-form label-width="82px">
        <el-form-item label="选择网站"><el-select v-model="backupSiteID" aria-label="备份网站" style="width: 100%" @change="backupConfirm = ''"><el-option v-for="site in backupableSites" :key="site.id" :label="`${site.name} · ${site.domain}`" :value="site.id" /></el-select></el-form-item>
        <el-form-item label="确认名称"><el-input v-model="backupConfirm" aria-label="备份确认名称" :placeholder="backupSite?.name || '输入网站名称'" autocomplete="off" /></el-form-item>
      </el-form>
      <template #footer><el-button @click="backupSiteDialog = false">取消</el-button><el-button type="primary" :disabled="!backupSite || backupConfirm !== backupSite.name" :loading="backupSiteSaving" @click="createSiteBackup">创建备份</el-button></template>
    </el-dialog>
    <el-dialog
      v-model="remoteDialog"
      :title="editingRemote ? '编辑 WebDAV' : '添加 WebDAV'"
      width="540px"
      destroy-on-close
    >
      <el-form label-position="top" @submit.prevent="saveRemote">
        <el-form-item label="存储名称" required
          ><el-input
            v-model="remoteDraft.name"
            maxlength="60"
            placeholder="例如：异地 NAS"
        /></el-form-item>
        <el-form-item label="WebDAV 地址" required
          ><el-input
            v-model="remoteDraft.base_url"
            placeholder="https://dav.example.com/backups"
          /><small class="remote-help"
            >公网地址必须使用 HTTPS；地址中不要包含账号、查询参数或片段。</small
          ></el-form-item
        >
        <div class="remote-form-grid">
          <el-form-item label="用户名"
            ><el-input v-model="remoteDraft.username"
          /></el-form-item>
          <el-form-item
            :label="editingRemote ? '新密码（留空不修改）' : '密码'"
            required
            ><el-input
              v-model="remoteDraft.password"
              type="password"
              show-password
              autocomplete="new-password"
          /></el-form-item>
        </div>
        <el-form-item label="远端目录"
          ><el-input
            v-model="remoteDraft.path_prefix"
            placeholder="panel-backups"
          /><small class="remote-help"
            >面板会在此目录下按 database/site、目标 ID 和备份 ID
            保存文件及清单。</small
          ></el-form-item
        >
        <el-form-item label="启用状态"
          ><el-switch v-model="remoteDraft.enabled" active-text="允许发送备份"
        /></el-form-item>
      </el-form>
      <template #footer
        ><el-button @click="remoteDialog = false">取消</el-button
        ><el-button
          type="primary"
          :loading="remoteSaving"
          :disabled="
            !remoteDraft.name.trim() ||
            !remoteDraft.base_url.trim() ||
            (!editingRemote && !remoteDraft.password)
          "
          @click="saveRemote"
          >保存</el-button
        ></template
      >
    </el-dialog>
    <el-dialog
      v-model="systemDialog"
      title="创建面板加密整包"
      width="520px"
      destroy-on-close
    >
      <el-alert
        title="此密码只用于本次归档，面板不会保留。请先存入自己的密码管理器。"
        type="warning"
        :closable="false"
        show-icon
      />
      <el-form
        label-position="top"
        class="system-backup-form"
        @submit.prevent="createSystemBackup"
      >
        <el-form-item label="恢复密码" required
          ><el-input
            v-model="systemPassphrase"
            type="password"
            show-password
            minlength="12"
            maxlength="256"
            autocomplete="new-password"
            aria-label="整包恢复密码"
        /></el-form-item>
        <el-form-item label="再次输入" required
          ><el-input
            v-model="systemPassphraseAgain"
            type="password"
            show-password
            minlength="12"
            maxlength="256"
            autocomplete="new-password"
            aria-label="再次输入整包恢复密码"
        /></el-form-item>
      </el-form>
      <template #footer
        ><el-button @click="systemDialog = false">取消</el-button
        ><el-button
          type="primary"
          :loading="systemSaving"
          :disabled="
            systemPassphrase.length < 12 ||
            systemPassphrase !== systemPassphraseAgain
          "
          @click="createSystemBackup"
          >加密并创建</el-button
        ></template
      >
    </el-dialog>
  </div>
</template>

<style scoped>
.backup-page {
  display: grid;
  gap: 18px;
}
.backup-summary {
  display: grid;
  grid-template-columns: repeat(5, minmax(0, 1fr));
  gap: 14px;
}
.system-backups {
  padding: 24px;
}
.system-backups > .el-alert {
  margin: 16px 0;
}
.system-backup-list {
  display: grid;
  gap: 9px;
}
.system-backup-list article {
  display: grid;
  grid-template-columns: 1fr auto auto;
  align-items: center;
  gap: 18px;
  padding: 13px 15px;
  border-radius: 8px;
  background: #f7f9f8;
}
.system-backup-list article div {
  display: flex;
  flex-direction: column;
  gap: 5px;
}
.system-backup-list small,
.system-backup-list span {
  font-size: 12px;
  color: #7c8983;
}
.system-backup-form {
  margin-top: 18px;
}
.backup-summary article {
  display: flex;
  flex-direction: column;
  padding: 20px 22px;
}
.backup-summary small {
  color: #7c8983;
}
.backup-summary strong {
  margin: 7px 0 4px;
  color: #203b34;
  font-size: 27px;
}
.backup-summary span {
  color: #89958f;
  font-size: 12px;
}
.backup-list,
.remote-list {
  padding: 22px 24px;
}
.remote-history {
  margin-top: 18px;
  padding-top: 16px;
  border-top: 1px solid #edf1ef;
}
.remote-history h3 {
  margin: 0 0 10px;
  font-size: 14px;
}
.remote-history-row {
  display: grid;
  grid-template-columns: minmax(180px, 1fr) 90px minmax(220px, 1fr) auto;
  align-items: center;
  gap: 14px;
  padding: 9px 0;
  border-top: 1px solid #f1f4f2;
  font-size: 12px;
}
.remote-history-row strong,
.remote-history-row small {
  display: block;
}
.remote-history-row small {
  margin-top: 3px;
  color: #84918b;
  word-break: break-all;
}
.remote-error {
  color: #b84242;
}
.remote-form-grid {
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: 14px;
}
.remote-help {
  display: block;
  width: 100%;
  margin-top: 6px;
  color: #7b8882;
  font-size: 12px;
  line-height: 1.5;
}
.backup-toolbar {
  display: flex;
  justify-content: space-between;
  align-items: flex-end;
  gap: 20px;
  margin-bottom: 18px;
}
.backup-toolbar h2 {
  margin: 0;
  font-size: 18px;
}
.backup-toolbar p {
  margin: 6px 0 0;
  color: #77847e;
  font-size: 13px;
}
.backup-filters {
  display: flex;
  gap: 10px;
}
.backup-filters .el-input {
  width: 210px;
}
.backup-cards {
  display: none;
}
.backup-pagination {
  display: flex;
  align-items: center;
  justify-content: space-between;
  margin-top: 16px;
  color: #7d8984;
  font-size: 12px;
}
.backup-card {
  border: 1px solid #e1e9e5;
  border-radius: 12px;
  padding: 16px;
}
.backup-card > div:first-child {
  display: flex;
  justify-content: space-between;
  gap: 12px;
}
.backup-card strong,
.backup-card small {
  display: block;
}
.backup-card small {
  margin-top: 4px;
  color: #7b8882;
}
.backup-card dl {
  margin: 13px 0;
  padding: 10px 0;
  border-block: 1px solid #edf1ef;
}
.backup-card dl div {
  display: flex;
  justify-content: space-between;
  gap: 12px;
  padding: 4px 0;
}
.backup-card dt {
  color: #84918b;
}
.backup-card dd {
  margin: 0;
  text-align: right;
}
@media (max-width: 900px) {
  .backup-summary {
    grid-template-columns: repeat(2, minmax(0, 1fr));
  }
}
@media (max-width: 760px) {
  .backup-summary {
    grid-template-columns: 1fr 1fr;
    gap: 10px;
  }
  .backup-summary article {
    padding: 16px;
  }
  .backup-toolbar {
    align-items: stretch;
    flex-direction: column;
  }
  .backup-filters {
    flex-direction: column;
  }
  .backup-filters .el-input {
    width: 100%;
  }
  .backup-list {
    padding: 18px;
  }
  .remote-list {
    padding: 18px;
    overflow: hidden;
  }
  .remote-history-row {
    grid-template-columns: 1fr auto;
  }
  .remote-history-row > span {
    grid-column: 1 / 2;
  }
  .remote-form-grid {
    grid-template-columns: 1fr;
    gap: 0;
  }
  .system-backups {
    padding: 18px;
  }
  .system-backup-list article {
    grid-template-columns: 1fr;
    gap: 9px;
  }
  .system-backup-list article .el-button {
    width: 100%;
  }
  .backup-list :deep(.el-table) {
    display: none;
  }
  .backup-cards {
    display: grid;
    gap: 12px;
  }
}
</style>
