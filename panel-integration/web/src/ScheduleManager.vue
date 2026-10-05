<script setup lang="ts">
import { formatPanelDateTime } from "./panelTime";
import { computed, onMounted, onUnmounted, ref } from "vue";
import { ElMessage, ElMessageBox } from "element-plus";
import {
  Calendar,
  Clock,
  VideoPlay,
  WarningFilled,
} from "@element-plus/icons-vue";

interface Schedule {
  id: string;
  name: string;
  kind: "database_backup" | "site_backup" | "log_cleanup" | "admin_script";
  target_id: string;
  target_name: string;
  database_engine?: "mysql" | "mariadb";
  instance_id?: string;
  instance_name?: string;
  release_id?: string;
  schedule_type: "hourly" | "daily" | "weekly";
  timezone: string;
  minute: number;
  hour: number;
  weekday: number;
  retention_count: number;
  script?: string;
  script_site_id?: string;
  timeout_seconds?: number;
  remote_id?: string;
  remote_name?: string;
  enabled: boolean;
  revision: number;
  next_run_at: number;
  last_run_at?: number;
  created_at: string;
  updated_at: string;
}
interface Run {
  id: string;
  schedule_id: string;
  schedule_name: string;
  trigger: "scheduled" | "manual";
  state: "queued" | "running" | "succeeded" | "failed" | "skipped";
  scheduled_for: number;
  started_at?: number;
  finished_at?: number;
  artifact_id?: string;
  error?: string;
  log?: string;
}
interface Database {
  id: string;
  server_id: string;
  name: string;
  status: string;
}
interface DatabaseData {
  databases: Database[];
  servers: { id: string; name: string; status: string }[];
  actual: {
    servers: { id: string; service_state: string; authenticated?: boolean }[];
  };
}
interface MariaDBDatabase { id: string; instance_id: string; name: string; }
interface MariaDBInstance { id: string; name: string; release_id: string; status: string; }
interface Site {
  php_version_id?: string;
  id: string;
  name: string;
  domain: string;
  status: string;
}
interface BackupRemote {
  id: string;
  name: string;
  enabled: boolean;
}
const props = defineProps<{
  api: <T>(path: string, method?: string, body?: unknown) => Promise<T>;
}>();
const schedules = ref<Schedule[]>([]),
  runs = ref<Run[]>([]),
  historyPage = ref(1),
  databases = ref<DatabaseData>({
    databases: [],
    servers: [],
    actual: { servers: [] },
  }),
  sites = ref<Site[]>([]),
  mariadbDatabases = ref<MariaDBDatabase[]>([]),
  mariadbInstances = ref<MariaDBInstance[]>([]),
  remotes = ref<BackupRemote[]>([]),
  loading = ref(false),
  saving = ref(false),
  error = ref(""),
  dialogOpen = ref(false),
  editing = ref(false),
  kindFilter = ref("all"),
  statusFilter = ref("all"),
  searchText = ref(""),
  selectedScheduleIDs = ref<string[]>([]),
  batchBusy = ref(false),
  scheduleLogsOpen = ref(false),
  scheduleLogsTarget = ref<Schedule | null>(null),
  scheduleTable = ref<{ clearSelection: () => void } | null>(null),
  statisticsDays = ref(7),
  runPickerOpen = ref(false),
  taskSettingsOpen = ref(false);
const savedTaskSettings = (() => {
  try {
    const value = JSON.parse(localStorage.getItem("panel-schedule-defaults") || "{}");
    return {
      timezone: typeof value.timezone === "string" && value.timezone.length <= 64 ? value.timezone : Intl.DateTimeFormat().resolvedOptions().timeZone || "Asia/Shanghai",
      hour: Number.isInteger(value.hour) && value.hour >= 0 && value.hour <= 23 ? value.hour : 3,
      retention_count: Number.isInteger(value.retention_count) && value.retention_count >= 1 && value.retention_count <= 100 ? value.retention_count : 7,
    };
  } catch {
    return { timezone: Intl.DateTimeFormat().resolvedOptions().timeZone || "Asia/Shanghai", hour: 3, retention_count: 7 };
  }
})();
const taskSettings = ref(savedTaskSettings);
const historyPageSize = 5;
const historyPages = computed(() => Math.max(1, Math.ceil(runs.value.length / historyPageSize)));
const visibleRuns = computed(() => runs.value.slice((historyPage.value - 1) * historyPageSize, historyPage.value * historyPageSize));
const filteredSchedules = computed(() => schedules.value.filter((item) =>
  (kindFilter.value === "all" || item.kind === kindFilter.value) &&
  (statusFilter.value === "all" || (statusFilter.value === "enabled") === item.enabled) &&
  (!searchText.value.trim() || `${item.name} ${item.target_name} ${item.remote_name || ""}`.toLocaleLowerCase().includes(searchText.value.trim().toLocaleLowerCase())),
));
const selectedSchedules = computed(() => schedules.value.filter(item => selectedScheduleIDs.value.includes(item.id)));
const scheduleLogs = computed(() => runs.value.filter(item => item.schedule_id === scheduleLogsTarget.value?.id).slice(0, 20));
const lastRun = (item: Schedule) => runs.value.filter(run => run.schedule_id === item.id).sort((a, b) => b.scheduled_for - a.scheduled_for)[0];
const readyPHPSites = computed(() => readySites.value.filter(site => site.php_version_id));
const scriptSite = computed(() => readyPHPSites.value.find(site => site.id === draft.value.script_site_id));
const scheduleKindLabel = (item: Schedule) => item.kind === "site_backup" ? "网站备份" : item.kind === "log_cleanup" ? "系统维护" : item.kind === "admin_script" ? (item.script_site_id ? "PHP 脚本" : "Shell 脚本") : item.database_engine === "mariadb" ? "MariaDB 备份" : "数据库备份";
const statisticsRuns = computed(() => runs.value.filter((item) =>
  item.scheduled_for >= Math.floor(Date.now() / 1000) - statisticsDays.value * 86400,
));
const statisticCount = (state: Run["state"]) => statisticsRuns.value.filter((item) => item.state === state).length;
const freshDraft = (): Schedule => ({
  id: "",
  name: "",
  kind: "database_backup",
  database_engine: "mysql",
  target_id: "",
  target_name: "",
  schedule_type: "daily",
  timezone: taskSettings.value.timezone,
  minute: 0,
  hour: taskSettings.value.hour,
  weekday: 1,
  retention_count: taskSettings.value.retention_count,
  script_site_id: "",
  script: '#!/bin/bash\nset -euo pipefail\n\necho "计划任务运行正常"\n',
  timeout_seconds: 30,
  remote_id: "",
  remote_name: "",
  enabled: true,
  revision: 0,
  next_run_at: 0,
  created_at: "",
  updated_at: "",
});
const draft = ref<Schedule>(freshDraft());
const readyDatabases = computed(() =>
  databases.value.databases.filter((db) => {
    const actual = databases.value.actual.servers.find(
      (v) => v.id === db.server_id,
    );
    return (
      db.status === "ready" &&
      actual?.service_state === "active" &&
      actual.authenticated
    );
  }),
);
const readySites = computed(() =>
  sites.value.filter(
    (site) => !["provisioning", "needs_attention"].includes(site.status),
  ),
);
const readyMariaDBDatabases = computed(() =>
  mariadbDatabases.value.filter((database) =>
    mariadbInstances.value.some((instance) => instance.id === database.instance_id && instance.status === "running"),
  ),
);
const mariaDBLabel = (database: MariaDBDatabase) => {
  const instance = mariadbInstances.value.find((value) => value.id === database.instance_id);
  return `${instance?.name || "MariaDB"} / ${database.name} / ${(instance?.release_id || "mariadb").replace("mariadb-", "MariaDB ")}`;
};
const serverName = (id: string) =>
  databases.value.servers.find((v) => v.id === id)?.name || "MySQL";
const weekdays = ["周日", "周一", "周二", "周三", "周四", "周五", "周六"];
const stateName: Record<string, string> = {
  queued: "排队中",
  running: "执行中",
  succeeded: "成功",
  failed: "失败",
  skipped: "已跳过",
};
const stateType = (state: string): "success" | "warning" | "danger" | "info" =>
  state === "succeeded"
    ? "success"
    : state === "failed"
      ? "danger"
      : state === "queued" || state === "running"
        ? "warning"
        : "info";
const unixTime = (value?: number) =>
  value
    ? formatPanelDateTime(value * 1000)
    : "尚未执行";
const scheduleText = (item: Schedule) => {
  const minute = String(item.minute).padStart(2, "0");
  if (item.schedule_type === "hourly") return `每小时 ${minute} 分`;
  const time = `${String(item.hour).padStart(2, "0")}:${minute}`;
  return item.schedule_type === "weekly"
    ? `每${weekdays[item.weekday]} ${time}`
    : `每天 ${time}`;
};
const runResult = (run: Run) => {
  if (run.error) return run.error;
  const log = run.log || "等待执行";
  if (!log.startsWith("MariaDB SQL 备份、大小与 SHA-256 已核对：")) return log;
  const database = log.match(/"database_name":"([^"]+)"/)?.[1];
  const bytes = Number(log.match(/"bytes":(\d+)/)?.[1] || 0);
  const sha = log.match(/"sha256":"([a-f0-9]+)/)?.[1];
  const details = [
    database,
    bytes ? `${(bytes / 1024).toFixed(1)} KiB` : "",
    sha ? `SHA-256 ${sha.slice(0, 12)}…` : "摘要已核对",
  ].filter(Boolean);
  return `MariaDB SQL 备份成功 · ${details.join(" · ")}`;
};
async function refresh() {
  if (loading.value) return;
  loading.value = true;
  try {
    const [scheduleData, runData, databaseData, siteData, remoteData, mariaDBData, mariaDBInstanceData] =
      await Promise.all([
        props.api<{ schedules: Schedule[] }>("/schedules"),
        props.api<{ runs: Run[] }>("/schedules/runs?limit=100"),
        props.api<DatabaseData>("/databases"),
        props.api<Site[]>("/sites"),
        props.api<{ remotes: BackupRemote[] }>("/backups/remotes"),
        props.api<{ databases: MariaDBDatabase[] }>("/mariadb/databases"),
        props.api<{ instances: MariaDBInstance[] }>("/mariadb/instances"),
      ]);
    schedules.value = scheduleData.schedules;
    runs.value = runData.runs;
    historyPage.value = Math.min(historyPage.value, historyPages.value);
    databases.value = databaseData;
    sites.value = siteData;
    remotes.value = remoteData.remotes;
    mariadbDatabases.value = mariaDBData.databases;
    mariadbInstances.value = mariaDBInstanceData.instances;
    error.value = "";
  } catch (e) {
    error.value = (e as Error).message;
  } finally {
    loading.value = false;
  }
}
function createSchedule() {
  draft.value = freshDraft();
  draft.value.target_id = readyDatabases.value[0]?.id || "";
  editing.value = false;
  dialogOpen.value = true;
}
function saveTaskSettings() {
  if (!taskSettings.value.timezone.trim()) { ElMessage.error("请选择默认时区"); return; }
  localStorage.setItem("panel-schedule-defaults", JSON.stringify(taskSettings.value));
  taskSettingsOpen.value = false;
  ElMessage.success("新建任务默认值已保存到当前浏览器");
}
function chooseKind(kind: Schedule["kind"]) {
  draft.value.kind = kind;
  draft.value.script_site_id = "";
  if (kind === "admin_script") {
    draft.value.target_id = "00000000000000000000000000000000";
    draft.value.retention_count = 1;
    draft.value.timeout_seconds ||= 30;
  } else {
    draft.value.target_id =
      kind !== "database_backup"
        ? readySites.value[0]?.id || ""
        : draft.value.database_engine === "mariadb"
          ? readyMariaDBDatabases.value[0]?.id || ""
          : readyDatabases.value[0]?.id || "";
  }
  if (kind !== "database_backup" && kind !== "site_backup") {
    draft.value.remote_id = "";
  }
}
function editSchedule(item: Schedule) {
  draft.value = { ...item };
  editing.value = true;
  dialogOpen.value = true;
}
async function save() {
  if (saving.value) return;
  saving.value = true;
  try {
    const path = editing.value ? `/schedules/${draft.value.id}` : "/schedules";
    await props.api(path, editing.value ? "PUT" : "POST", draft.value);
    dialogOpen.value = false;
    await refresh();
    ElMessage.success(editing.value ? "计划任务已更新" : "计划任务已创建");
  } catch (e) {
    ElMessage.error((e as Error).message);
  } finally {
    saving.value = false;
  }
}
async function toggle(item: Schedule, enabled: boolean) {
  try {
    await props.api(`/schedules/${item.id}`, "PUT", { ...item, enabled });
    await refresh();
    ElMessage.success(enabled ? "计划任务已启用" : "计划任务已停用");
  } catch (e) {
    ElMessage.error((e as Error).message);
  }
}
function selectSchedules(rows: Schedule[]) {
  if (window.innerWidth <= 760) return;
  selectedScheduleIDs.value = rows.map(item => item.id);
}
function selectScheduleCard(id: string, checked: boolean) {
  selectedScheduleIDs.value = checked ? [...new Set([...selectedScheduleIDs.value, id])] : selectedScheduleIDs.value.filter(value => value !== id);
}
async function batchSetEnabled(enabled: boolean) {
  const targets = selectedSchedules.value;
  if (!targets.length || batchBusy.value) return;
  if (targets.length > 50) { ElMessage.error("一次最多处理 50 个计划任务"); return; }
  try {
    await ElMessageBox.confirm(`将${enabled ? '启用' : '停用'}所选 ${targets.length} 个计划任务；已处于目标状态的任务会跳过。`, `批量${enabled ? '启用' : '停用'}任务`, { type: "warning", confirmButtonText: "确认执行", cancelButtonText: "取消" });
  } catch { return; }
  batchBusy.value = true;
  let changed = 0, skipped = 0, failed = 0;
  for (const item of targets) {
    if (item.enabled === enabled) { skipped++; continue; }
    try {
      await props.api(`/schedules/${item.id}`, "PUT", { ...item, enabled });
      changed++;
    } catch { failed++; }
  }
  selectedScheduleIDs.value = [];
  scheduleTable.value?.clearSelection();
  await refresh();
  batchBusy.value = false;
  const summary = `已${enabled ? '启用' : '停用'} ${changed} 项，跳过 ${skipped} 项，失败 ${failed} 项`;
  if (failed) ElMessage.error(summary);
  else ElMessage.success(summary);
}
function openScheduleLogs(item: Schedule) {
  scheduleLogsTarget.value = item;
  scheduleLogsOpen.value = true;
}
async function runNow(item: Schedule) {
  try {
    await props.api(`/schedules/${item.id}/run`, "POST", {});
    await refresh();
    ElMessage.success("已加入执行队列");
    runPickerOpen.value = false;
  } catch (e) {
    ElMessage.error((e as Error).message);
  }
}
async function remove(item: Schedule) {
  try {
    const { value } = await ElMessageBox.prompt(
      `删除后不会再自动执行；已成功保留的备份仍归数据库管理。请输入“${item.name}”确认。`,
      "删除计划任务",
      {
        confirmButtonText: "删除",
        cancelButtonText: "取消",
        type: "warning",
        inputValidator: (value) =>
          value === item.name || "请输入完全一致的计划名称",
      },
    );
    await props.api(`/schedules/${item.id}`, "DELETE", {
      revision: item.revision,
      confirm_name: value,
    });
    await refresh();
    ElMessage.success("计划任务已删除");
  } catch (e) {
    if (e !== "cancel" && e !== "close") ElMessage.error((e as Error).message);
  }
}
let timer: ReturnType<typeof setInterval>;
onMounted(() => {
  void refresh();
  timer = setInterval(() => { if (!selectedScheduleIDs.value.length && !batchBusy.value) void refresh(); }, 5000);
});
onUnmounted(() => clearInterval(timer));
defineExpose({ refresh, createSchedule, openRunPicker: () => { runPickerOpen.value = true; }, openTaskSettings: () => { taskSettingsOpen.value = true; } });
</script>

<template>
  <div class="schedule-page">
    <el-alert
      v-if="error"
      :title="error"
      type="error"
      :closable="false"
      show-icon
    />
    <section class="panel-card schedule-toolbar">
      <div>
        <h2>计划任务</h2>
        <p>
          按小时、每天或每周执行备份、日志维护、Shell 和网站 PHP
          脚本；同一计划不会并发。
        </p>
      </div>
      <el-button type="primary" @click="createSchedule">创建计划任务</el-button>
    </section>
    <div class="schedule-summary">
      <article class="panel-card">
        <span class="schedule-summary-icon green"
          ><el-icon><Calendar /></el-icon
        ></span>
        <div>
          <small>总任务</small><strong>{{ schedules.length }}</strong
          ><span>全部计划任务数量</span>
        </div>
      </article>
      <article class="panel-card">
        <span class="schedule-summary-icon green"
          ><el-icon><VideoPlay /></el-icon
        ></span>
        <div>
          <small>启用中</small
          ><strong>{{ schedules.filter((item) => item.enabled).length }}</strong
          ><span>正在启用的任务</span>
        </div>
      </article>
      <article class="panel-card">
        <span class="schedule-summary-icon blue"
          ><el-icon><Clock /></el-icon
        ></span>
        <div>
          <small>今日执行</small
          ><strong>{{
            runs.filter(
              (item) =>
                new Date(item.scheduled_for * 1000).toDateString() ===
                new Date().toDateString(),
            ).length
          }}</strong
          ><span>今日已触发次数</span>
        </div>
      </article>
      <article class="panel-card">
        <span class="schedule-summary-icon red"
          ><el-icon><WarningFilled /></el-icon
        ></span>
        <div>
          <small>失败任务</small
          ><strong>{{
            runs.filter((item) => item.state === "failed").length
          }}</strong
          ><span>当前记录中的失败数</span>
        </div>
      </article>
    </div>
    <section class="panel-card schedule-list">
      <div class="schedule-filters">
        <label>任务类型：<el-select v-model="kindFilter" aria-label="任务类型筛选"><el-option value="all" label="全部类型" /><el-option value="site_backup" label="网站备份" /><el-option value="database_backup" label="数据库备份" /><el-option value="log_cleanup" label="日志清理" /><el-option value="admin_script" label="系统维护" /></el-select></label>
        <label>任务状态：<el-select v-model="statusFilter" aria-label="任务状态筛选"><el-option value="all" label="全部状态" /><el-option value="enabled" label="启用中" /><el-option value="disabled" label="已停用" /></el-select></label>
        <el-input v-model="searchText" clearable aria-label="搜索任务" placeholder="搜索任务名称或目标..." />
        <el-button :loading="loading" @click="refresh">刷新列表</el-button>
      </div>
      <el-table ref="scheduleTable" :data="filteredSchedules" row-key="id" :empty-text="schedules.length ? '没有符合筛选条件的计划任务。' : '还没有计划任务。'" @selection-change="selectSchedules">
        <el-table-column type="selection" width="45" reserve-selection />
        <el-table-column label="任务名称" min-width="205">
          <template #default="{ row }">
            <strong>{{ row.name }}</strong
            ><span class="table-secondary">{{
              row.kind === "site_backup"
                ? "网站文件自动备份"
                : row.kind === "log_cleanup"
                  ? "网站日志清理"
                  : row.kind === "admin_script"
                    ? (row.script_site_id ? "网站 PHP 脚本" : "Shell 脚本")
                    : row.database_engine === "mariadb"
                      ? "MariaDB 自动备份"
                      : "MySQL 自动备份"
            }} · {{ row.target_name || '受限任务' }} · {{ row.kind === 'admin_script' ? '无备份保留' : `${row.retention_count} ${row.kind === 'log_cleanup' ? '天' : '份'}` }}<template v-if="row.remote_name"> · 远端：{{ row.remote_name }}</template></span>
          </template>
        </el-table-column>
        <el-table-column label="类型" min-width="115"><template #default="{ row }">{{ scheduleKindLabel(row) }}</template></el-table-column>
        <el-table-column label="执行周期" min-width="165">
          <template #default="{ row }">
            {{ scheduleText(row)
            }}<span class="table-secondary">{{ row.timezone }}</span>
          </template>
        </el-table-column>
        <el-table-column label="上次执行" min-width="150">
          <template #default="{ row }">{{ lastRun(row) ? unixTime(lastRun(row)?.finished_at || lastRun(row)?.started_at || lastRun(row)?.scheduled_for) : unixTime(row.last_run_at) }}<span v-if="lastRun(row)" class="table-secondary" :class="lastRun(row)?.state === 'failed' ? 'schedule-last-failed' : 'schedule-last-success'">{{ stateName[lastRun(row)!.state] }}</span></template>
        </el-table-column>
        <el-table-column label="下次执行" min-width="150">
          <template #default="{ row }">{{
            row.enabled ? unixTime(row.next_run_at) : "已停用"
          }}</template>
        </el-table-column>
        <el-table-column label="状态" width="90">
          <template #default="{ row }">
            <el-switch
              :model-value="row.enabled"
              aria-label="启用计划"
              @change="toggle(row, Boolean($event))"
            />
          </template>
        </el-table-column>
        <el-table-column label="操作" min-width="245" fixed="right">
          <template #default="{ row }">
            <el-button link type="primary" @click="runNow(row)"
              >立即执行</el-button
            >
            <el-button link type="primary" @click="editSchedule(row)"
              >编辑</el-button
            >
            <el-button link type="primary" @click="openScheduleLogs(row)">日志</el-button>
            <el-dropdown trigger="click" @command="(command: string) => { if (command === 'delete') remove(row); }"><el-button link type="primary">更多⌄</el-button><template #dropdown><el-dropdown-menu><el-dropdown-item command="delete">删除任务</el-dropdown-item></el-dropdown-menu></template></el-dropdown>
          </template>
        </el-table-column>
      </el-table>
      <div class="schedule-batch-toolbar"><el-dropdown trigger="click" :disabled="!selectedSchedules.length || batchBusy" @command="(command: string) => batchSetEnabled(command === 'enable')"><el-button :disabled="!selectedSchedules.length || batchBusy" :loading="batchBusy">批量操作⌄</el-button><template #dropdown><el-dropdown-menu><el-dropdown-item command="enable">启用选中任务</el-dropdown-item><el-dropdown-item command="disable">停用选中任务</el-dropdown-item></el-dropdown-menu></template></el-dropdown><span>已选 {{ selectedSchedules.length }} 项</span></div>
      <div class="schedule-cards">
        <article v-for="item in filteredSchedules" :key="item.id" class="schedule-card">
          <div class="schedule-card-head">
            <el-checkbox :model-value="selectedScheduleIDs.includes(item.id)" :aria-label="`选择任务 ${item.name}`" @change="selectScheduleCard(item.id, Boolean($event))" />
            <div>
              <strong>{{ item.name }}</strong
              ><small
                >{{ item.target_name
                }}<template v-if="item.remote_name">
                  · {{ item.remote_name }}</template
                ></small
              >
            </div>
            <el-switch
              :model-value="item.enabled"
              aria-label="启用计划"
              @change="toggle(item, Boolean($event))"
            />
          </div>
          <dl>
            <div>
              <dt>执行周期</dt>
              <dd>{{ scheduleText(item) }}</dd>
            </div>
            <div>
              <dt>时区</dt>
              <dd>{{ item.timezone }}</dd>
            </div>
            <div>
              <dt>保留数量</dt>
              <dd>
                {{
                  item.kind === "admin_script"
                    ? "—"
                    : `${item.retention_count} ${item.kind === "log_cleanup" ? "天" : "份"}`
                }}
              </dd>
            </div>
            <div>
              <dt>上次执行</dt>
              <dd>{{ lastRun(item) ? unixTime(lastRun(item)?.finished_at || lastRun(item)?.started_at || lastRun(item)?.scheduled_for) : unixTime(item.last_run_at) }}</dd>
            </div>
            <div>
              <dt>下次执行</dt>
              <dd>
                {{ item.enabled ? unixTime(item.next_run_at) : "已停用" }}
              </dd>
            </div>
          </dl>
          <div class="schedule-card-actions">
            <el-button size="small" type="primary" plain @click="runNow(item)"
              >立即执行</el-button
            >
            <el-button size="small" @click="editSchedule(item)">编辑</el-button>
            <el-button size="small" @click="openScheduleLogs(item)">日志</el-button>
            <el-button size="small" type="danger" plain @click="remove(item)"
              >删除</el-button
            >
          </div>
        </article>
        <el-empty v-if="!filteredSchedules.length" :description="schedules.length ? '没有符合筛选条件的计划任务' : '还没有计划任务'" />
      </div>
    </section>
    <section class="panel-card run-history">
      <div class="card-heading">
        <div>
          <h2>最近执行日志</h2>
        </div>
        <div v-if="historyPages > 1" class="run-history-pages" aria-label="执行记录分页">
          <el-button size="small" :disabled="historyPage === 1" @click="historyPage--">上一页</el-button>
          <span>{{ historyPage }} / {{ historyPages }}</span>
          <el-button size="small" :disabled="historyPage === historyPages" @click="historyPage++">下一页</el-button>
        </div>
      </div>
      <el-table :data="visibleRuns" empty-text="还没有执行记录。">
        <el-table-column label="任务" min-width="170" prop="schedule_name" />
        <el-table-column label="触发方式" width="100">
          <template #default="{ row }">{{
            row.trigger === "manual" ? "手动" : "定时"
          }}</template>
        </el-table-column>
        <el-table-column label="计划时间" min-width="165">
          <template #default="{ row }">{{
            unixTime(row.scheduled_for)
          }}</template>
        </el-table-column>
        <el-table-column label="状态" width="100">
          <template #default="{ row }"
            ><el-tag :type="stateType(row.state)" size="small">{{
              stateName[row.state]
            }}</el-tag></template
          >
        </el-table-column>
        <el-table-column label="结果" min-width="260">
          <template #default="{ row }"
            ><span class="run-result-text" :title="runResult(row)" :class="{ 'run-error': row.error }">{{
              runResult(row)
            }}</span></template
          >
        </el-table-column>
      </el-table>
      <div class="run-cards">
        <article v-for="run in visibleRuns" :key="run.id" class="run-card">
          <div>
            <strong>{{ run.schedule_name }}</strong
            ><el-tag :type="stateType(run.state)" size="small">{{
              stateName[run.state]
            }}</el-tag>
          </div>
          <p>
            {{ run.trigger === "manual" ? "手动触发" : "定时触发" }} ·
            {{ unixTime(run.scheduled_for) }}
          </p>
          <small :class="{ 'run-error': run.error }">{{ runResult(run) }}</small>
        </article>
        <el-empty v-if="!runs.length" description="还没有执行记录" />
      </div>
    </section>
    <section class="panel-card run-statistics">
      <div class="card-heading">
        <div>
          <h2>执行结果统计</h2>
        </div>
        <el-segmented v-model="statisticsDays" aria-label="统计时间范围" :options="[{ label: '近7天', value: 7 }, { label: '近30天', value: 30 }]" />
      </div>
      <div class="run-statistics-body">
        <el-progress
          type="circle"
          :width="135"
          :stroke-width="14"
          color="#08ad5b"
          :percentage="
            statisticsRuns.length
              ? Math.round(
                  (statisticCount('succeeded') /
                    statisticsRuns.length) *
                    100,
                )
              : 0
          "
          ><template #default
            ><strong>{{ statisticsRuns.length }}</strong
            ><small>总执行次数</small></template
          ></el-progress
        >
        <div>
          <span
            ><i class="success"></i>成功
            <b>{{
              statisticCount("succeeded")
            }}</b></span
          ><span
            ><i class="failed"></i>失败
            <b>{{
              statisticCount("failed")
            }}</b></span
          ><span
            ><i class="skipped"></i>跳过
            <b>{{
              statisticCount("skipped")
            }}</b></span
          >
        </div>
      </div>
    </section>
    <el-dialog v-model="runPickerOpen" title="立即执行计划任务" width="520px">
      <p class="run-picker-help">选择一项已启用任务加入执行队列。脚本和备份会在服务器上实际运行。</p>
      <div class="run-picker-list">
        <button v-for="item in schedules.filter((entry) => entry.enabled)" :key="item.id" type="button" @click="runNow(item)"><strong>{{ item.name }}</strong><small>{{ scheduleText(item) }} · {{ item.target_name }}</small></button>
        <el-empty v-if="!schedules.some((item) => item.enabled)" description="暂无已启用的计划任务" />
      </div>
    </el-dialog>
    <el-dialog v-model="scheduleLogsOpen" :title="`${scheduleLogsTarget?.name || '任务'} · 执行日志`" width="min(720px, 96vw)">
      <el-table :data="scheduleLogs" max-height="440" empty-text="该任务暂无执行记录">
        <el-table-column label="时间" min-width="160"><template #default="{ row }">{{ unixTime(row.started_at || row.scheduled_for) }}</template></el-table-column>
        <el-table-column label="触发" width="80"><template #default="{ row }">{{ row.trigger === 'manual' ? '手动' : '计划' }}</template></el-table-column>
        <el-table-column label="结果" width="90"><template #default="{ row }">{{ stateName[row.state] }}</template></el-table-column>
        <el-table-column label="详情" min-width="220" show-overflow-tooltip><template #default="{ row }">{{ runResult(row) }}</template></el-table-column>
      </el-table>
      <template #footer><el-button @click="scheduleLogsOpen = false">关闭</el-button></template>
    </el-dialog>
    <el-dialog v-model="taskSettingsOpen" title="新建任务默认设置" width="460px">
      <p class="run-picker-help">这些默认值保存在当前浏览器，只影响之后新建的任务。已创建任务保持原设置。</p>
      <el-form label-width="100px">
        <el-form-item label="默认时区"><el-select v-model="taskSettings.timezone" aria-label="默认任务时区"><el-option value="Asia/Shanghai" label="Asia/Shanghai" /><el-option value="UTC" label="UTC" /><el-option value="Asia/Hong_Kong" label="Asia/Hong_Kong" /><el-option value="America/Los_Angeles" label="America/Los_Angeles" /></el-select></el-form-item>
        <el-form-item label="每日执行时间"><el-input-number v-model="taskSettings.hour" :min="0" :max="23" aria-label="默认执行小时" /><span class="form-suffix">点</span></el-form-item>
        <el-form-item label="备份保留份数"><el-input-number v-model="taskSettings.retention_count" :min="1" :max="100" aria-label="默认保留份数" /></el-form-item>
      </el-form>
      <template #footer><el-button @click="taskSettingsOpen = false">取消</el-button><el-button type="primary" @click="saveTaskSettings">保存设置</el-button></template>
    </el-dialog>
    <el-dialog
      v-model="dialogOpen"
      :title="editing ? '编辑计划任务' : '创建计划任务'"
      width="560px"
      destroy-on-close
    >
      <el-form label-position="top" @submit.prevent="save">
        <el-form-item label="任务名称" required>
          <el-input
            v-model="draft.name"
            maxlength="60"
            placeholder="例如：商城主库每日备份"
          />
        </el-form-item>
        <el-form-item label="任务类型">
          <el-select
            :model-value="draft.kind"
            class="full"
            @change="chooseKind"
          >
            <el-option value="database_backup" label="数据库自动备份" />
            <el-option value="site_backup" label="网站文件自动备份" />
            <el-option value="log_cleanup" label="网站日志轮转与清理" />
            <el-option value="admin_script" label="Shell / 网站 PHP 脚本" />
          </el-select>
        </el-form-item>
        <el-form-item v-if="draft.kind === 'database_backup'" label="数据库引擎">
          <el-segmented
            v-model="draft.database_engine"
            :options="[{ label: 'MySQL', value: 'mysql' }, { label: 'MariaDB', value: 'mariadb' }]"
            @change="draft.target_id = $event === 'mariadb' ? readyMariaDBDatabases[0]?.id || '' : readyDatabases[0]?.id || ''"
          />
        </el-form-item>
        <el-form-item
          v-if="draft.kind !== 'admin_script'"
          :label="draft.kind !== 'database_backup' ? '目标网站' : '目标数据库'"
          required
        >
          <el-select
            v-model="draft.target_id"
            class="full"
            :placeholder="
              draft.kind !== 'database_backup'
                ? '选择已就绪的网站'
                : '选择运行中的数据库'
            "
          >
            <el-option
              v-for="db in draft.kind === 'database_backup' && draft.database_engine !== 'mariadb'
                ? readyDatabases
                : []"
              :key="db.id"
              :value="db.id"
              :label="`${serverName(db.server_id)} / ${db.name}`"
            />
            <el-option
              v-for="db in draft.kind === 'database_backup' && draft.database_engine === 'mariadb' ? readyMariaDBDatabases : []"
              :key="db.id"
              :value="db.id"
              :label="mariaDBLabel(db)"
            />
            <el-option
              v-for="site in draft.kind === 'site_backup' ||
              draft.kind === 'log_cleanup'
                ? readySites
                : []"
              :key="site.id"
              :value="site.id"
              :label="`${site.name} / ${site.domain}`"
            />
          </el-select>
          <small
            v-if="draft.kind === 'database_backup' && draft.database_engine !== 'mariadb' && !readyDatabases.length"
            class="form-help danger"
            >请先创建并启动 MySQL 实例和数据库。</small
          >
          <small
            v-if="draft.kind === 'database_backup' && draft.database_engine === 'mariadb' && !readyMariaDBDatabases.length"
            class="form-help danger"
            >请先创建并启动 MariaDB 实例和数据库。</small
          >
          <small
            v-if="
              (draft.kind === 'site_backup' || draft.kind === 'log_cleanup') &&
              !readySites.length
            "
            class="form-help danger"
            >请先创建并完成一个网站。</small
          >
        </el-form-item>
        <el-form-item
          v-if="
            draft.kind === 'database_backup' || draft.kind === 'site_backup'
          "
          label="成功后发送到远端（可选）"
        >
          <el-select
            v-model="draft.remote_id"
            class="full"
            clearable
            placeholder="只保留本地备份"
          >
            <el-option
              v-for="remote in remotes"
              :key="remote.id"
              :value="remote.id"
              :label="remote.enabled ? remote.name : `${remote.name}（已停用）`"
              :disabled="!remote.enabled"
            />
          </el-select>
          <small class="form-help"
            >本地备份及 SHA-256 核验成功后进入 WebDAV
            传输队列；远端失败不把本地备份标成失败。</small
          >
        </el-form-item>
        <template v-if="draft.kind === 'admin_script'">
          <el-form-item label="执行环境">
            <el-radio-group :model-value="draft.script_site_id ? 'php' : 'shell'" @change="draft.script_site_id = $event === 'php' ? readyPHPSites[0]?.id || '' : ''; draft.script = $event === 'php' ? 'cron.php' : '#!/bin/bash\necho &quot;计划任务运行正常&quot;\n'">
              <el-radio-button value="shell">Shell</el-radio-button>
              <el-radio-button value="php" :disabled="!readyPHPSites.length">网站 PHP</el-radio-button>
            </el-radio-group>
            <small v-if="!readyPHPSites.length" class="form-help">网站绑定 PHP 后可创建 PHP 脚本任务。</small>
          </el-form-item>
          <el-form-item v-if="draft.script_site_id" label="目标网站" required>
            <el-select v-model="draft.script_site_id" class="full">
              <el-option v-for="site in readyPHPSites" :key="site.id" :value="site.id" :label="`${site.name} / ${site.domain}`" />
            </el-select>
            <small class="form-help">当前版本：{{ scriptSite?.php_version_id?.replace('php-', 'PHP ') }}。每次运行使用该网站绑定的 PHP 版本和设置，以网站用户执行。</small>
          </el-form-item>
          <el-alert v-if="draft.script_site_id" title="填写网站公开目录内的 PHP 文件路径。可访问网络和数据库，只能写入自己的网站目录。每次运行最多一次；切换版本时已开始的任务会保持原版本或报错，请查看执行日志。" type="info" :closable="false" show-icon class="script-alert" />
          <el-alert v-else
            title="脚本以 panel-task 非登录用户运行，没有网络，只能写入 /var/lib/panel-tasks/work。每次运行最多一次；若执行中断且结果未知，系统会拒绝自动重跑。"
            type="warning"
            :closable="false"
            show-icon
            class="script-alert"
          />
          <el-form-item :label="draft.script_site_id ? 'PHP 文件路径' : 'Shell 脚本'" required>
            <el-input
              v-model="draft.script"
              :type="draft.script_site_id ? 'text' : 'textarea'"
              :rows="9"
              :maxlength="draft.script_site_id ? 1024 : 16384"
              show-word-limit
              class="script-editor"
              :placeholder="draft.script_site_id ? '例如 cron/task.php' : '#!/bin/bash'"
            />
          </el-form-item>
          <el-form-item label="超时时间">
            <el-input-number
              v-model="draft.timeout_seconds"
              :min="1"
              :max="60"
            />
            <span class="form-suffix">秒</span>
          </el-form-item>
        </template>
        <div class="form-grid">
          <el-form-item label="执行周期">
            <el-select v-model="draft.schedule_type" class="full">
              <el-option value="hourly" label="每小时" /><el-option
                value="daily"
                label="每天"
              /><el-option value="weekly" label="每周" />
            </el-select>
          </el-form-item>
          <el-form-item v-if="draft.schedule_type === 'weekly'" label="星期">
            <el-select v-model="draft.weekday" class="full">
              <el-option
                v-for="(day, index) in weekdays"
                :key="day"
                :value="index"
                :label="day"
              />
            </el-select>
          </el-form-item>
          <el-form-item v-if="draft.schedule_type !== 'hourly'" label="小时">
            <el-input-number
              v-model="draft.hour"
              :min="0"
              :max="23"
              controls-position="right"
            />
          </el-form-item>
          <el-form-item label="分钟">
            <el-input-number
              v-model="draft.minute"
              :min="0"
              :max="59"
              controls-position="right"
            />
          </el-form-item>
        </div>
        <el-form-item label="时区">
          <el-select
            v-model="draft.timezone"
            filterable
            allow-create
            class="full"
          >
            <el-option
              value="Asia/Shanghai"
              label="Asia/Shanghai（中国标准时间）"
            />
            <el-option value="UTC" label="UTC" />
            <el-option value="America/New_York" label="America/New_York" />
            <el-option value="Europe/London" label="Europe/London" />
          </el-select>
        </el-form-item>
        <el-form-item
          v-if="draft.kind !== 'admin_script'"
          :label="
            draft.kind === 'log_cleanup' ? '日志保留天数' : '保留最近备份'
          "
        >
          <el-input-number
            v-model="draft.retention_count"
            :min="1"
            :max="100"
          />
          <span class="form-suffix">{{
            draft.kind === "log_cleanup" ? "天" : "份"
          }}</span>
          <small v-if="draft.kind !== 'log_cleanup'" class="form-help"
            >只有新的备份成功且完成 SHA-256
            核验后，才清理超出数量的旧计划备份。网站备份只归档公开文件，不把数据库称作同一时刻快照。</small
          >
          <small v-else class="form-help"
            >只轮转所选站点的固定 access/error
            日志，并删除早于保留天数的受管轮转文件。</small
          >
        </el-form-item>
        <el-form-item label="启用状态"
          ><el-switch v-model="draft.enabled" active-text="创建后自动执行"
        /></el-form-item>
      </el-form>
      <template #footer>
        <el-button @click="dialogOpen = false">取消</el-button>
        <el-button
          type="primary"
          :loading="saving"
          :disabled="
            !draft.name.trim() ||
            !draft.target_id ||
            (draft.kind === 'admin_script' && !draft.script?.trim())
          "
          @click="save"
          >保存计划</el-button
        >
      </template>
    </el-dialog>
  </div>
</template>

<style scoped>
.schedule-page {
  display: grid;
  grid-template-columns: minmax(0, 1.67fr) minmax(320px, 1fr);
  gap: 12px;
}
.schedule-page > .el-alert,
.schedule-toolbar,
.schedule-summary,
.schedule-list {
  grid-column: 1 / -1;
}
.schedule-toolbar {
  display: none;
  align-items: center;
  justify-content: space-between;
  gap: 20px;
  padding: 22px 24px;
}
.schedule-summary {
  display: grid;
  grid-template-columns: repeat(4, minmax(0, 1fr));
  gap: 12px;
}
.schedule-summary article {
  min-height: 112px;
  padding: 18px;
  display: flex;
  align-items: center;
  gap: 14px;
}
.schedule-summary article > div {
  display: grid;
  gap: 6px;
}
.schedule-summary-icon {
  width: 60px;
  height: 60px;
  display: grid;
  place-items: center;
  flex: none;
  border-radius: 11px;
  font-size: 30px;
}
.schedule-summary .schedule-summary-icon :deep(.el-icon) { font-size: 32px; }
.schedule-summary-icon.green {
  background: #e4f8ed;
  color: #08ad5b;
}
.schedule-summary-icon.blue {
  background: #e7f2ff;
  color: #2387eb;
}
.schedule-summary-icon.red {
  background: #ffe9e9;
  color: #f04444;
}
.schedule-summary small,
.schedule-summary span {
  color: #6f8097;
  font-size: 11px;
}
.schedule-summary strong {
  color: #10213a;
  font-size: 27px;
  line-height: 1;
}
.schedule-toolbar h2,
.card-heading h2 {
  margin: 0;
  font-size: 18px;
}
.schedule-toolbar p,
.card-heading p {
  margin: 6px 0 0;
  color: #76837d;
  font-size: 13px;
}
.schedule-list,
.run-history {
  padding: 0;
}
.schedule-filters {
  display: flex;
  align-items: center;
  gap: 12px;
  padding: 18px 16px;
  border-bottom: 1px solid #e9eef3;
}
.schedule-filters label { display: flex; align-items: center; gap: 7px; color: #425570; font-size: 12px; white-space: nowrap; }
.schedule-filters label .el-select { width: 170px; }
.schedule-filters > .el-input { width: min(280px, 100%); margin-left: 4px; }
.schedule-filters > .el-button { margin-left: auto; }
.run-picker-help { margin: 0 0 14px; color: #6f8097; font-size: 12px; }
.run-picker-list { display: grid; gap: 8px; max-height: 360px; overflow: auto; }
.run-picker-list button { display: grid; gap: 4px; width: 100%; padding: 12px; border: 1px solid #e4ebf2; border-radius: 6px; background: #fff; color: #10213a; text-align: left; cursor: pointer; }
.run-picker-list button:hover { border-color: #08ad5b; background: #f1fbf6; }
.run-picker-list small { color: #6f8097; }
.schedule-list .card-heading,
.run-history .card-heading {
  margin-bottom: 0;
}
.run-history-pages {
  display: flex;
  align-items: center;
  gap: 8px;
  color: #6f8097;
  font-size: 12px;
  white-space: nowrap;
}
.run-result-text {
  display: block;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}
.schedule-list :deep(.el-table),
.run-history :deep(.el-table) {
  padding: 0 8px 8px;
}
.schedule-batch-toolbar { display: flex; align-items: center; gap: 12px; padding: 8px 16px 12px; border-top: 1px solid #e9eef3; color: #718198; font-size: 12px; }
.schedule-last-success { color: #08a856 !important; }
.schedule-last-failed { color: #e24646 !important; }
.run-statistics {
  min-width: 0;
}
.run-statistics-body {
  min-height: 210px;
  padding: 22px;
  display: flex;
  align-items: center;
  justify-content: center;
  gap: 35px;
}
.run-statistics-body :deep(.el-progress__text) {
  display: grid;
  gap: 4px;
}
.run-statistics-body :deep(.el-progress__text strong) {
  color: #10213a;
  font-size: 24px;
}
.run-statistics-body :deep(.el-progress__text small) {
  color: #77889d;
  font-size: 10px;
}
.run-statistics-body > div:last-child {
  display: grid;
  gap: 16px;
  min-width: 130px;
}
.run-statistics-body span {
  display: grid;
  grid-template-columns: 10px 1fr auto;
  gap: 8px;
  align-items: center;
  color: #52647e;
  font-size: 12px;
}
.run-statistics-body i {
  width: 8px;
  height: 8px;
  border-radius: 50%;
}
.run-statistics-body i.success {
  background: #08ad5b;
}
.run-statistics-body i.failed {
  background: #f04444;
}
.run-statistics-body i.skipped {
  background: #99a6b6;
}
.full {
  width: 100%;
}
.form-grid {
  display: grid;
  grid-template-columns: repeat(2, minmax(0, 1fr));
  gap: 0 14px;
}
.form-help {
  display: block;
  width: 100%;
  margin-top: 7px;
  color: #7b8982;
  font-size: 12px;
  line-height: 1.55;
}
.form-help.danger {
  color: #b84242;
}
.script-alert {
  margin-bottom: 18px;
}
.script-editor :deep(textarea) {
  font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
  font-size: 12px;
  line-height: 1.6;
}
.run-error {
  color: #b84242;
}
.form-suffix {
  margin-left: 8px;
  color: #66756e;
}
.schedule-cards,
.run-cards {
  display: none;
}
.schedule-card,
.run-card {
  border: 1px solid #e3eae6;
  border-radius: 12px;
  padding: 16px;
  background: #fff;
}
.schedule-card-head {
  display: flex;
  align-items: flex-start;
  justify-content: space-between;
  gap: 12px;
}
.schedule-card-head strong,
.schedule-card-head small {
  display: block;
}
.schedule-card-head small {
  margin-top: 5px;
  color: #7a8781;
}
.schedule-card dl {
  margin: 14px 0;
  padding: 12px 0;
  border-block: 1px solid #edf1ef;
}
.schedule-card dl div {
  display: flex;
  justify-content: space-between;
  gap: 12px;
  padding: 4px 0;
}
.schedule-card dt {
  color: #84918b;
}
.schedule-card dd {
  margin: 0;
  text-align: right;
}
.schedule-card-actions {
  display: flex;
  flex-wrap: wrap;
}
.run-card > div {
  display: flex;
  justify-content: space-between;
  gap: 12px;
}
.run-card p {
  margin: 9px 0 5px;
  color: #738079;
  font-size: 12px;
}
.run-card small {
  line-height: 1.5;
}
@media (min-width: 761px) {
  .schedule-list {
    min-height: 380px;
    display: flex;
    flex-direction: column;
  }
  .schedule-batch-toolbar {
    margin-top: auto;
  }
  .run-statistics-body {
    min-height: 160px;
  }
}
@media (max-width: 760px) {
  .schedule-page {
    grid-template-columns: 1fr;
  }
  .schedule-page > * {
    grid-column: 1;
  }
  .schedule-summary {
    grid-template-columns: 1fr 1fr;
  }
  .schedule-toolbar {
    align-items: stretch;
    flex-direction: column;
    padding: 18px;
  }
  .schedule-list,
  .run-history {
    padding: 18px;
  }
  .schedule-filters { flex-wrap: wrap; padding: 0 0 14px; }
  .schedule-filters label { width: 100%; justify-content: space-between; }
  .schedule-filters label .el-select { width: 60%; }
  .schedule-filters > .el-input { width: 100%; margin-left: 0; }
  .schedule-filters > .el-button { margin-left: 0; }
  .schedule-list :deep(.el-table),
  .run-history :deep(.el-table) {
    display: none;
  }
  .schedule-cards,
  .run-cards {
    display: grid;
    gap: 12px;
  }
  .form-grid {
    grid-template-columns: 1fr;
  }
  :deep(.el-dialog) {
    width: calc(100vw - 24px) !important;
    margin-top: 4vh;
  }
}
</style>
