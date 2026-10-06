<script setup lang="ts">
import { computed, ref } from "vue";
import { ElMessage } from "element-plus";
import AppModuleReport from "./AppModuleReport.vue";
import AnalyticsWorkspace from "./AnalyticsWorkspace.vue";
import WafWorkspace from "./WafWorkspace.vue";
type API = <T>(
  path: string,
  method?: string,
  body?: unknown,
  idempotencyKey?: string,
) => Promise<T>;
interface Field {
  key: string;
  label: string;
  kind: string;
}
interface Definition {
  id: string;
  name: string;
  actions: string[];
  fields: Field[] | null;
}
interface Section { id: string; label: string; help: string; fields: string[] | null; actions: string[]; }
interface Guidance {
  description: string;
  workflow: string[];
  limitations: string[];
}
interface Versions {
  catalog: { apps: { id: string; target: string; version: string; sha256: string }[] };
  status: { id: string; installed_version?: string; version_known?: boolean; update_available?: boolean; update_supported?: boolean; update_detail?: string }[];
  source: { stale: boolean; fetched_at?: string; error?: string };
}
const props = defineProps<{ api: API; onJob: (id: string) => Promise<void>; onInstall: (id: string, settings?: Record<string, unknown>) => Promise<string>; registry?: Versions }>();
const activeTab = ref("manage"), localVersions = ref<Versions>();
const versions = computed(() => localVersions.value || props.registry);
const versionApp = computed(() => versions.value?.catalog.apps.find(app => app.target === definition.value?.id));
const versionStatus = computed(() => versions.value?.status.find(status => status.id === versionApp.value?.id));
async function checkVersions() {
  busy.value = true; error.value = "";
  try { localVersions.value = await props.api<Versions>("/app-registry?refresh=1"); }
  catch (e) { error.value = (e as Error).message; }
  finally { busy.value = false; }
}
async function updateVersion() {
  if (!versionApp.value || !versionStatus.value?.update_supported || busy.value) return;
  busy.value = true;
  try {
    const app = versionApp.value;
    const result = await props.api<{job_id:string}>(`/app-registry/${app.id}/update`, "POST", { expected_version: app.version, expected_sha256: app.sha256 });
    visible.value = false;
    await props.onJob(result.job_id);
  } catch (e) { error.value = (e as Error).message; }
  finally { busy.value = false; }
}
const visible = ref(false),
  busy = ref(false),
  error = ref("");
const definition = ref<Definition>(),
  guidance = ref<Guidance>(),
  installed = ref(false),
  healthy = ref(false),
  report = ref<Record<string, any>>();
const form = ref<Record<string, any>>({}),
  sites = ref<{ id: string; name: string; domain: string }[]>([]);
const selectedPlanID = ref("");
const workspace = ref<Section[]>([]), history = ref<Record<string, any>>();
function sectionFields(section: Section) { return (definition.value?.fields || []).filter(field => section.fields?.includes(field.key)); }
async function refreshHistory() {
  if (!definition.value || busy.value) return;
  busy.value = true; error.value = "";
  try { history.value = await props.api<Record<string, any>>(`/app-modules/${definition.value.id}/history`); }
  catch (e) { error.value = (e as Error).message; }
  finally { busy.value = false; }
}
function tabChanged(name: string | number) { if (name === "history") void refreshHistory(); }
const labels: Record<string, string> = {
  run: "刷新报告",
  baseline: "建立基线",
  check: "检查变更",
  restore: "恢复所选文件",
  preview: "同步预览",
  sync: "开始同步",
  save: "保存入口",
  probe: "健康检测",
  remove: "移除入口",
  terminate: "终止所选受管进程",
  create: "创建",
  update: "更新",
  revoke: "撤销会话",
  delete: "删除",
  add: "添加主机",
  "issue-token": "生成只读令牌",
  "revoke-token": "撤销只读令牌",
  mount: "挂载",
  unmount: "卸载挂载",
  start: "启动",
  stop: "停止",
  restart: "重启",
  logs: "读取日志",
  schedule: "保存同步计划",
  "run-plan": "执行所选计划",
  "pause-plan": "暂停所选计划",
  "resume-plan": "恢复所选计划",
  "remove-plan": "移除所选计划",
  history: "查看执行历史",
  policies: "查看监控策略",
  pause: "暂停所选监控",
  resume: "恢复所选监控",
  password: "修改 FTP 密码",
  archive: "读取历史日报目录",
  report: "读取所选日期报告",
};
function setReport(value: any) {
  report.value =
    value?.result && typeof value.result === "object"
      ? value.result
      : value && typeof value === "object"
        ? value
        : { result: value };
}
async function show(id: string) {
  if (busy.value) return;
  busy.value = true;
  error.value = "";
  visible.value = true;
  report.value = undefined;
  definition.value = undefined;
  guidance.value = undefined;
  installed.value = false;
  healthy.value = false;
  form.value = {};
  sites.value = [];
  selectedPlanID.value = "";
  workspace.value = []; history.value = undefined;
  activeTab.value = "manage"; localVersions.value = undefined;
  try {
    const page = await props.api<{
      definition: Definition;
      guidance: Guidance;
      status: { installed: boolean; healthy: boolean };
      report: unknown;
      workspace: Section[];
    }>(`/app-modules/${id}`);
    definition.value = page.definition;
    workspace.value = page.workspace || [{ id: "manage", label: "管理", help: "请更新面板以获取专用管理流程。", fields: (page.definition.fields || []).map(field => field.key), actions: page.definition.actions.filter(action => action !== "history") }];
    activeTab.value = workspace.value[0]?.id || "overview";
    guidance.value = page.guidance;
    installed.value = page.status.installed;
    healthy.value = page.status.healthy;
    if (page.report !== null && page.report !== undefined)
      setReport(page.report);
    sites.value = await props.api<typeof sites.value>("/sites");
    form.value = {
      role: "viewer",
      read_only: true,
      auto_restore: false,
      nodes: [{ address: "127.0.0.1:21001", weight: 1, backup: false }],
      site_ids: [],
      excludes: [],
      status_code: 0,
      min_seconds: 1,
      only_bots: false,
      enabled: true,
      interval: 300,
      expected_revision: 0,
      severity: "",
      instances: 1,
      memory_mb: 256,
    };
  } catch (e) {
    error.value = e instanceof Error ? e.message : String(e);
  } finally {
    busy.value = false;
  }
  if (installed.value && definition.value?.actions.includes("policies")) {
    await execute("policies");
  } else if (
    installed.value &&
    definition.value?.actions.includes("run") &&
    (!(definition.value.fields || []).some((f) => f.kind === "site") ||
      id === "files-sync") &&
    id !== "platform-ops"
  )
    await execute("run");
}
function selected(row: Record<string, any>) {
  const id = definition.value?.id;
  const target = id === "disk-analysis" ? "disk" : id === "daily-report" ? "archive" : id === "task-manager" ? "terminate" : id === "pm2-manager" ? "control" : id === "user-manager" ? "account" : id === "files-sync" ? "plans" : row.path !== undefined && ["website-tamper-proof", "enterprise-tamper-proof"].includes(id || "") ? "restore" : "";
  activeTab.value = workspace.value.find(section => section.id === target)?.id || workspace.value[0]?.id || "overview";
  if (row.site_id !== undefined && row.site_id !== form.value.site_id) {
    form.value.path = "";
    form.value.expected_sha = "";
  }
  for (const f of definition.value?.fields || [])
    if (row[f.key] !== undefined) form.value[f.key] = row[f.key];
  if (row.revision !== undefined) {
    selectedPlanID.value = row.id;
    form.value.expected_revision = row.revision;
  }
  if (row.path !== undefined && ["website-tamper-proof", "enterprise-tamper-proof"].includes(definition.value?.id || "")) form.value.expected_sha = row.after || "";
  if (row.drill && definition.value?.id === "disk-analysis")
    void execute("run");
  else ElMessage.info("已填入所选记录，可执行对应操作");
}
function inputBody(action: string) {
  const body: Record<string, unknown> = {};
  const section = workspace.value.find(section => section.id === activeTab.value && section.actions.includes(action)) || workspace.value.find(section => section.actions.includes(action));
  for (const f of definition.value?.fields || []) {
    if (section && !section.fields?.includes(f.key)) continue;
    const v = f.key === "expected_revision" && form.value.resource_id !== selectedPlanID.value ? 0 : form.value[f.key];
    if (v !== undefined && v !== null && v !== "")
      body[f.key] =
        f.kind === "datetime"
          ? new Date(v).toISOString()
          : f.kind === "json" && typeof v === "string"
            ? JSON.parse(v)
            : v;
  }
  return body;
}
async function execute(action: string) {
  if (!definition.value || busy.value) return;
  busy.value = true;
  error.value = "";
  try {
    const result = await props.api(
      `/app-modules/${definition.value.id}/${action}`,
      "POST",
      inputBody(action),
    );
    setReport(result);
    // Reports are a distinct management section; parameters remain intact.
    if ((result as any)?.plan?.revision !== undefined) {
      selectedPlanID.value = (result as any).plan.id;
      form.value.expected_revision = (result as any).plan.revision;
    }
    if (action === "remove-plan") {
      selectedPlanID.value = "";
      form.value.expected_revision = 0;
    }
    if (!["run", "logs", "probe", "check", "preview"].includes(action))
      ElMessage.success("操作已执行并记录审计");
    for (const f of definition.value.fields || [])
      if (f.kind === "password") form.value[f.key] = "";
    if (
      [
        "create",
        "update",
        "delete",
        "start",
        "stop",
        "restart",
        "mount",
        "unmount",
        "add",
        "remove",
        "revoke",
        "schedule",
        "run-plan",
        "pause-plan",
        "resume-plan",
        "remove-plan",
      ].includes(action) &&
      definition.value.actions.includes("run")
    )
      setReport(
        await props.api(`/app-modules/${definition.value.id}/run`, "POST", {}),
      );
    if (
      ["pause", "resume", "baseline"].includes(action) &&
      definition.value.actions.includes("policies")
    )
      setReport(
        await props.api(
          `/app-modules/${definition.value.id}/policies`,
          "POST",
          {},
        ),
      );
  } catch (e) {
    error.value = e instanceof Error ? e.message : String(e);
  } finally {
    busy.value = false;
  }
}
function exportReport() {
  if (!report.value || report.value.token) return;
  const url = URL.createObjectURL(
    new Blob([JSON.stringify(report.value, null, 2)], {
      type: "application/json",
    }),
  );
  const a = document.createElement("a");
  a.href = url;
  a.download = `${definition.value?.id || "application"}-report.json`;
  a.click();
  URL.revokeObjectURL(url);
}
async function uninstall() {
  if (!definition.value || busy.value) return;
  busy.value = true;
  try {
    const out = await props.api<{ job_id: string }>(
      `/software/${definition.value.id}/uninstall`,
      "POST",
      { settings: {} },
    );
    visible.value = false;
    await props.onJob(out.job_id);
  } catch (e) {
    error.value = e instanceof Error ? e.message : String(e);
  } finally {
    busy.value = false;
  }
}
async function install() {
  if (!definition.value || installed.value || busy.value) return;
  busy.value = true;
  error.value = "";
  try {
    const jobID = await props.onInstall(definition.value.id);
    visible.value = false;
    await props.onJob(jobID);
  } catch (e) {
    error.value = e instanceof Error ? e.message : String(e);
  } finally { busy.value = false; }
}
defineExpose({ show });
</script>
<template>
  <el-dialog
    v-model="visible"
    :title="definition?.name || '应用管理'"
    width="1000px"
    class="app-module-dialog"
    destroy-on-close
  >
    <div v-loading="busy">
      <el-alert v-if="error" :title="error" type="error" :closable="false" />
      <template v-if="definition">
        <p>
          <el-tag :type="healthy ? 'success' : 'warning'">{{
            installed
              ? healthy
                ? "已安装 · 依赖正常"
                : "已安装 · 需要核对"
              : "未安装"
          }}</el-tag>
          <span>实际操作、状态和报告来自服务器，不使用演示数据。</span>
        </p>
        <el-alert v-if="!installed" title="先安装并验证模块依赖，再执行下面的实际操作；此处参数属于当前应用，不使用其他软件的设置模板。" type="info" :closable="false" />
        <AnalyticsWorkspace v-if="definition.id === 'website-analytics'" :api="api" :installed="installed" :sites="sites">
          <template #version>
            <el-descriptions :column="1" border>
              <el-descriptions-item label="已安装版本">{{versionStatus?.installed_version || '版本待核对'}}</el-descriptions-item>
              <el-descriptions-item label="仓库版本">{{versionApp?.version || '未加载'}}</el-descriptions-item>
              <el-descriptions-item label="状态">{{versions?.source.stale ? '未能确认最新版本' : versionStatus?.update_available ? '仓库有新版' : '当前目录未发现新版'}}</el-descriptions-item>
            </el-descriptions>
            <p>{{versionStatus?.update_detail || '应用更新保留采集配置、事件和报告。'}}</p>
            <el-button :disabled="busy" @click="checkVersions">检查更新</el-button>
            <el-button v-if="versionStatus?.update_available" :disabled="busy || !versionStatus.update_supported || versions?.source.stale" @click="updateVersion">{{versionStatus.update_supported ? '更新应用' : '需升级面板'}}</el-button>
          </template>
        </AnalyticsWorkspace>
        <WafWorkspace v-else-if="definition.id === 'apache-waf'" :api="api" engine="apache-waf" :on-install="onInstall" />
        <el-tabs v-else v-model="activeTab" class="module-manager-tabs" @tab-change="tabChanged">
        <el-tab-pane label="概览" name="overview">
        <p v-if="guidance">{{ guidance.description }}</p>
        <ol v-if="guidance" class="module-workflow">
          <li v-for="step in guidance.workflow" :key="step">{{ step }}</li>
        </ol>
        <el-alert
          v-if="guidance?.limitations.length"
          :title="guidance.limitations.join(' ')"
          type="info"
          :closable="false"
          class="module-limits"
        />
        <p>版本、依赖状态来自服务器；功能处理器由签名面板提供。配置、执行报告和升级状态分开管理。</p>
        </el-tab-pane>
        <el-tab-pane v-for="section in workspace" :key="section.id" :label="section.label" :name="section.id">
        <el-alert :title="section.help" type="info" :closable="false" />
        <el-form label-position="top" class="module-fields">
          <el-form-item
            v-for="field in sectionFields(section)"
            :key="field.key"
            :label="field.label"
          >
            <el-input
              v-if="field.kind === 'identity'"
              :model-value="field.key === 'expected_revision' && form.resource_id !== selectedPlanID ? 0 : form[field.key]"
              readonly
            />
            <el-select
              v-else-if="field.kind === 'site'"
              v-model="form[field.key]"
              placeholder="选择网站"
              clearable
              filterable
              ><el-option
                v-for="site in sites"
                :key="site.id"
                :value="site.id"
                :label="`${site.name} · ${site.domain}`"
            /></el-select>
            <el-select
              v-else-if="field.key === 'site_ids'"
              v-model="form.site_ids"
              multiple
              filterable
              placeholder="选择授权网站"
              ><el-option
                v-for="site in sites"
                :key="site.id"
                :value="site.id"
                :label="`${site.name} · ${site.domain}`"
            /></el-select>
            <el-select
              v-else-if="field.key === 'excludes'"
              v-model="form.excludes"
              multiple
              filterable
              allow-create
              default-first-option
              placeholder="输入排除目录并回车"
            />
            <div v-else-if="field.key === 'nodes'" class="node-editor">
              <div
                v-for="(node, index) in form.nodes"
                :key="index"
                class="node-line"
              >
                <el-input
                  v-model="node.address"
                  placeholder="IP:端口"
                  :aria-label="`上游节点 ${Number(index) + 1} 地址`"
                /><el-input-number
                  v-model="node.weight"
                  :min="1"
                  :max="100"
                  :aria-label="`上游节点 ${Number(index) + 1} 权重`"
                /><el-checkbox v-model="node.backup">备用</el-checkbox
                ><el-button
                  size="small"
                  type="danger"
                  :disabled="form.nodes.length === 1"
                  @click="form.nodes.splice(Number(index), 1)"
                  >移除节点</el-button
                >
              </div>
              <el-button
                size="small"
                :disabled="form.nodes.length >= 16"
                @click="
                  form.nodes.push({ address: '', weight: 1, backup: false })
                "
                >添加上游节点</el-button
              >
            </div>
            <el-date-picker
              v-else-if="field.kind === 'datetime'"
              v-model="form[field.key]"
              type="datetime"
              clearable
              placeholder="不限制时间"
            />
            <el-switch
              v-else-if="field.kind === 'boolean'"
              v-model="form[field.key]"
            />
            <el-input-number
              v-else-if="field.kind === 'number' || field.kind === 'decimal'"
              v-model="form[field.key]"
              :min="0"
              :max="
                field.key === 'start_time'
                  ? Number.MAX_SAFE_INTEGER
                  : field.key === 'pid'
                    ? 4194304
                    : field.key === 'status_code'
                      ? 599
                      : field.key === 'min_seconds'
                        ? 3600
                        : field.key === 'interval'
                          ? 86400
                          : 65535
              "
              :precision="field.kind === 'decimal' ? 2 : 0"
            />
            <el-select v-else-if="field.key === 'role'" v-model="form.role"
              ><el-option value="viewer" label="viewer · 只读" /><el-option
                value="operator"
                label="operator · 指定网站操作" /><el-option
                value="admin"
                label="admin · 管理员"
            /></el-select>
            <el-select v-else-if="field.kind === 'severity'" v-model="form.severity"><el-option value="" label="全部风险" /><el-option value="high" label="高风险" /><el-option value="warning" label="警告" /></el-select>
            <el-input
              v-else
              v-model="form[field.key]"
              :type="
                field.kind === 'password'
                  ? 'password'
                  : field.kind === 'json'
                    ? 'textarea'
                    : 'text'
              "
              :show-password="field.kind === 'password'"
              :rows="field.kind === 'json' ? 4 : 1"
              autocomplete="off"
            />
          </el-form-item>
        </el-form>
        <div class="module-actions">
          <el-button
            v-for="action in section.actions"
            :key="action"
            :disabled="
              !installed || busy || (action === 'terminate' && !form.pid)
            "
            :type="
              [
                'delete',
                'terminate',
                'remove',
                'remove-plan',
                'unmount',
              ].includes(action)
                ? 'danger'
                : 'primary'
            "
            @click="execute(action)"
            >{{ labels[action] || action }}</el-button
          >
        </div>
        <section v-if="report !== undefined" class="workflow-result" aria-label="实际执行结果"><h3>服务器返回的实际结果</h3><AppModuleReport :id="definition.id" :report="report" @select="selected" /></section>
        </el-tab-pane>
        <el-tab-pane label="报告与日志" name="reports">
        <section aria-label="执行报告">
          <h3>实际执行结果</h3>
          <p v-if="report === undefined">
            选择参数并执行操作，报告将显示在这里。
          </p>
          <AppModuleReport
            v-else
            :id="definition.id"
            :report="report"
            @select="selected"
          />
        </section>
        </el-tab-pane>
        <el-tab-pane label="执行历史" name="history">
          <p>查看真实执行摘要；不保存输入密码、访问令牌或完整请求正文。</p>
          <el-button :disabled="busy" @click="refreshHistory">刷新历史</el-button>
          <AppModuleReport v-if="history" :id="definition.id" :report="history" />
          <el-empty v-else description="暂无已加载的执行历史" />
        </el-tab-pane>
        <el-tab-pane label="版本与更新" name="version">
          <el-descriptions :column="1" border>
            <el-descriptions-item label="已安装应用版本">{{ versionStatus?.installed_version || '版本待核对' }}</el-descriptions-item>
            <el-descriptions-item label="签名仓库版本">{{ versionApp?.version || '未加载' }}</el-descriptions-item>
            <el-descriptions-item label="更新状态">{{ versions?.source.stale ? '未能确认最新版本' : versionStatus?.update_available ? '仓库有新版' : versionStatus?.version_known ? '当前目录未发现新版' : '版本记录待核对' }}</el-descriptions-item>
          </el-descriptions>
          <p>{{ versionStatus?.update_detail || '更新成功后才记录新版本，不重置现有配置与报告。' }}</p>
          <el-alert v-if="versions?.source.stale" type="warning" :closable="false" :title="versions.source.error || '仓库连接失败，当前使用已验签缓存'" />
          <el-button :disabled="busy" @click="checkVersions">检查更新</el-button>
          <el-button v-if="versionStatus?.update_available" type="warning" :disabled="busy || !versionStatus.update_supported || versions?.source.stale" @click="updateVersion">{{ versionStatus.update_supported ? '更新应用' : '需升级面板' }}</el-button>
        </el-tab-pane>
        </el-tabs>
      </template>
    </div>
    <template #footer
      ><el-button
        v-if="report && !report.token && !['website-analytics', 'apache-waf'].includes(definition?.id || '')"
        :disabled="busy"
        @click="exportReport"
        >导出真实报告</el-button
      ><el-button
        v-if="installed"
        type="danger"
        plain
        :disabled="busy"
        @click="uninstall"
        >卸载模块 · 保留报告和备份</el-button
      ><el-button v-if="definition && !installed" type="primary" :disabled="busy" @click="install">安装并验证</el-button
      ><el-button @click="visible = false">关闭</el-button></template
    >
  </el-dialog>
</template>
<style scoped>
.module-fields {
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: 0 20px;
  margin-top: 16px;
}
.workflow-result { margin-top: 22px; border-top: 1px solid #e7edf1; padding-top: 12px; }
.module-fields .el-select,
.module-fields .el-date-editor {
  width: 100%;
}
.module-actions {
  display: flex;
  flex-wrap: wrap;
  gap: 10px;
}
.module-actions .el-button {
  margin-left: 0;
}
.module-workflow {
  display: flex;
  flex-wrap: wrap;
  gap: 4px 30px;
  padding-left: 20px;
  font-size: 12px;
  color: #657181;
}
.module-limits {
  margin: 12px 0;
}
.node-editor {
  width: 100%;
}
.node-line {
  display: flex;
  flex-wrap: wrap;
  gap: 6px;
  margin-bottom: 8px;
}
.node-line .el-input {
  min-width: 150px;
  flex: 1;
}
.node-line .el-input-number {
  width: 110px;
}
h3 {
  font-size: 15px;
}
p {
  color: #657181;
}
@media (max-width: 600px) {
  .module-fields {
    grid-template-columns: 1fr;
  }
  .module-workflow {
    display: block;
  }
}
</style>
<style>
.app-module-dialog {
  max-width: calc(100vw - 24px) !important;
}
.app-module-dialog .el-dialog__body {
  overflow-x: hidden;
}
</style>
