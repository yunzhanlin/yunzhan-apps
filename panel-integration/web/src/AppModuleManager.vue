<script setup lang="ts">
import { computed, onBeforeUnmount, ref, watch } from "vue";
import { ElMessage } from "element-plus";
import AppModuleReport from "./AppModuleReport.vue";
import AnalyticsWorkspace from "./AnalyticsWorkspace.vue";
import WafWorkspace from "./WafWorkspace.vue";
import { canReadPath, type AccessPlan } from "./menuPermissions";
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
const props = defineProps<{ api: API; onJob: (id: string) => Promise<void>; onInstall: (id: string, settings?: Record<string, unknown>) => Promise<string>; registry?: Versions; access?: AccessPlan | null }>();
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
const certificates = ref<{id:string;name:string;domains:string[];trusted:boolean;status:string}[]>([]);
const selectedPlanID = ref("");
const integrityModule = computed(() => ["file-monitor", "website-tamper-proof", "enterprise-tamper-proof"].includes(definition.value?.id || ""));
const revisionIdentity = computed(() => integrityModule.value ? form.value.site_id : definition.value?.id === "user-manager" ? form.value.username : definition.value?.id === "pure-ftpd" ? "ftp-service" : form.value.resource_id);
const expectedRevision = computed(() => revisionIdentity.value === selectedPlanID.value ? form.value.expected_revision : 0);
const workspace = ref<Section[]>([]), history = ref<Record<string, any>>();
function clearWriteOnlyFields() {
  for (const field of definition.value?.fields || [])
    if (["password", "secret-json"].includes(field.kind)) form.value[field.key] = "";
}
watch(visible, value => { if (!value) clearWriteOnlyFields(); });
onBeforeUnmount(clearWriteOnlyFields);
const menuCatalog = computed(() => (report.value?.menu_catalog || []) as {id:string;label:string;admin_only:boolean}[]);
function roleDefaultMenus() { form.value.menu_ids = menuCatalog.value.filter(menu => (form.value.role === "admin" || !menu.admin_only) && (props.access === undefined || props.access?.menu_ids.includes(menu.id))).map(menu => menu.id); }
watch(() => form.value.role, () => {
  if (definition.value?.id === "user-manager" && Array.isArray(form.value.menu_ids) && menuCatalog.value.length)
    form.value.menu_ids = form.value.menu_ids.filter((id: string) => menuCatalog.value.some(menu => menu.id === id && (form.value.role === "admin" || !menu.admin_only)));
});
const historyFilter = ref({search: "", from_time: "", to_time: "", site_id: "", resource_id: ""});
const historyOffset = ref(0), historyLimit = ref(50);
const scopedHistory = computed(() => !["daily-report", "user-manager", "platform-ops"].includes(definition.value?.id || ""));
function sectionFields(section: Section) { return (definition.value?.fields || []).filter(field => section.fields?.includes(field.key)); }
async function refreshHistory(reset = false) {
  if (!definition.value || busy.value) return;
  if (reset) historyOffset.value = 0;
  busy.value = true; error.value = "";
  try {
    const query = new URLSearchParams({limit: String(historyLimit.value), offset: String(historyOffset.value)});
    for (const [key, value] of Object.entries(historyFilter.value)) {
      if (!value || !scopedHistory.value && ["site_id", "resource_id"].includes(key)) continue;
      query.set(key, key.endsWith("_time") ? new Date(value).toISOString() : value);
    }
    history.value = await props.api<Record<string, any>>(`/app-modules/${definition.value.id}/history?${query}`);
  }
  catch (e) { error.value = (e as Error).message; }
  finally { busy.value = false; }
}
function tabChanged(name: string | number) { if (name === "history") void refreshHistory(true); }
function historyPage(delta: number) { historyOffset.value = Math.max(0, historyOffset.value + delta * historyLimit.value); void refreshHistory(); }
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
  dependencies: "部署锁定依赖",
  deployment: "刷新部署状态",
  "cancel-deployment": "取消部署并恢复",
  "recover-deployment": "恢复中断部署",
	"account-limits": "保存账户限制",
	"recount-quota": "重统计当前网站容量",
  "archive-deployments": "归档旧部署记录",
  schedule: "保存同步计划",
  "run-plan": "执行所选计划",
  "pause-plan": "暂停所选计划",
  "resume-plan": "恢复所选计划",
  "remove-plan": "移除所选计划",
  history: "查看执行历史",
  policies: "查看监控策略",
  pause: "暂停所选监控",
  resume: "恢复所选监控",
  "watch-mode": "保存实时监控设置",
  password: "修改 FTP 密码",
  "service-config": "保存 FTPS 服务配置",
  "recover-service": "恢复中断的 FTPS 配置",
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
  certificates.value = [];
  selectedPlanID.value = "";
  workspace.value = []; history.value = undefined;
  historyFilter.value = {search: "", from_time: "", to_time: "", site_id: "", resource_id: ""}; historyOffset.value = 0;
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
    if (props.access === undefined || canReadPath(props.access, "/sites")) sites.value = await props.api<typeof sites.value>("/sites");
    if (id === "pure-ftpd" && (props.access === undefined || canReadPath(props.access, "/certificates"))) certificates.value = await props.api<typeof certificates.value>("/certificates");
    form.value = {
      role: "viewer",
      read_only: true,
      auto_restore: false,
      realtime: false,
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
      allow_install_scripts: false,
    };
    if (id === "pure-ftpd") Object.assign(form.value, {bind_address: "127.0.0.1", port: 2121, passive_start: 30000, passive_end: 30049, passive_address: "127.0.0.1", max_clients: 20, max_per_ip: 4, idle_minutes: 15});
	if (id === "pure-ftpd") Object.assign(form.value, {quota_mb:0,quota_files:0,upload_kb:0,download_kb:0,max_sessions:0,client_allow:"[]",client_deny:"[]",expected_sha:""});
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
      id === "files-sync" || id === "pure-ftpd") &&
    id !== "platform-ops"
  )
    await execute("run");
}
function selected(row: Record<string, any>) {
  clearWriteOnlyFields();
  const id = definition.value?.id;
  const target = id === "disk-analysis" ? "disk" : id === "daily-report" ? "archive" : id === "task-manager" ? "terminate" : id === "pm2-manager" ? "control" : id === "user-manager" || id === "pure-ftpd" ? "account" : id === "files-sync" ? "plans" : row.path !== undefined && ["website-tamper-proof", "enterprise-tamper-proof"].includes(id || "") ? "restore" : integrityModule.value && row.realtime !== undefined ? "watch" : "";
  activeTab.value = workspace.value.find(section => section.id === target)?.id || workspace.value[0]?.id || "overview";
  if (row.site_id !== undefined && row.site_id !== form.value.site_id) {
    form.value.path = "";
    form.value.expected_sha = "";
  }
  for (const f of definition.value?.fields || [])
    if (row[f.key] !== undefined) form.value[f.key] = f.kind === "json" ? JSON.stringify(row[f.key], null, 2) : row[f.key];
  if (row.revision !== undefined) {
    selectedPlanID.value = integrityModule.value ? row.site_id : definition.value?.id === "user-manager" ? row.username : row.resource_id || row.id;
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
    const v = f.key === "expected_revision" ? expectedRevision.value : form.value[f.key];
    if (v !== undefined && v !== null && v !== "")
      body[f.key] =
        f.kind === "datetime"
          ? new Date(v).toISOString()
          : ["json", "secret-json"].includes(f.kind) && typeof v === "string"
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
    if (definition.value.id === "pure-ftpd" && report.value?.config) {
      for (const [key,value] of Object.entries(report.value.config)) if (key !== "revision") form.value[key] = value;
      form.value.expected_revision = report.value.config.revision;
      selectedPlanID.value = "ftp-service";
      form.value.confirm = "";
    }
    if (definition.value.id === "user-manager" && form.value.menu_ids === undefined && menuCatalog.value.length) roleDefaultMenus();
    // Reports are a distinct management section; parameters remain intact.
    if ((result as any)?.plan?.revision !== undefined) {
      selectedPlanID.value = (result as any).plan.id;
      form.value.expected_revision = (result as any).plan.revision;
    }
    if (integrityModule.value && (result as any)?.revision !== undefined) {
      selectedPlanID.value = (result as any).site_id;
      form.value.expected_revision = (result as any).revision;
    }
    if (action === "remove-plan") {
      selectedPlanID.value = "";
      form.value.expected_revision = 0;
    }
    if (!["run", "logs", "probe", "check", "preview"].includes(action))
      ElMessage.success("操作已执行并记录审计");
    for (const f of definition.value.fields || [])
      if (["password", "secret-json"].includes(f.kind)) form.value[f.key] = "";
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
        "service-config",
        "recover-service",
		"account-limits",
		"recount-quota",
      ].includes(action) &&
      definition.value.actions.includes("run")
    )
      setReport(
        await props.api(`/app-modules/${definition.value.id}/run`, "POST", {}),
      );
    if (definition.value.id === "pure-ftpd" && report.value?.config) {
      for (const [key,value] of Object.entries(report.value.config)) if (key !== "revision") form.value[key] = value;
      form.value.expected_revision = report.value.config.revision; selectedPlanID.value = "ftp-service";
	  const selected = report.value.users?.find((row: Record<string, any>) => row.username === form.value.username);
	  form.value.expected_sha = selected?.expected_sha || "";
    }
    if (definition.value.id === "user-manager" && ["create", "update", "delete"].includes(action)) {
      const selected = report.value?.users?.find((row: Record<string, any>) => row.username === selectedPlanID.value);
      form.value.expected_revision = selected?.revision || 0;
      if (!selected) selectedPlanID.value = "";
    }
    if (definition.value.id === "pm2-manager" && ["create", "update", "delete"].includes(action)) {
      const selected = report.value?.apps?.find((row: Record<string, any>) => row.app.id === form.value.resource_id)?.app;
      form.value.expected_revision = selected?.revision || 0;
      selectedPlanID.value = selected?.id || "";
    }
    if (
      ["pause", "resume", "baseline", "watch-mode"].includes(action) &&
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
        <el-alert v-if="definition.id === 'pure-ftpd' && ['account-limits','quota'].includes(section.id) && report?.account_limits_ready === false" type="warning" :closable="false" title="当前 FTP 尚未更新到受管独立运行时。请先在版本与更新中更新应用；不会静默替换系统 FTP。" />
        <el-form label-position="top" class="module-fields">
          <el-form-item
            v-for="field in sectionFields(section)"
            :key="field.key"
            :label="field.label"
          >
            <el-input
              v-if="field.kind === 'identity'"
              :model-value="field.key === 'expected_revision' ? expectedRevision : form[field.key]"
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
            <div v-else-if="field.kind === 'menus'">
              <el-select v-model="form.menu_ids" multiple placeholder="空列表表示仅保留自身账户安全">
                <el-option v-for="menu in menuCatalog" :key="menu.id" :label="menu.label" :value="menu.id" :disabled="menu.admin_only && form.role !== 'admin' || access !== undefined && !access?.menu_ids.includes(menu.id)" />
              </el-select>
              <el-button link type="primary" @click="roleDefaultMenus">使用角色默认菜单</el-button>
              <small>菜单是原角色权限的上限，不会扩大网站范围。修改后撤销旧会话；至少保留一个完整权限管理员。</small>
            </div>
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
            <div v-else-if="field.kind === 'secret-json'">
              <el-input v-model="form[field.key]" type="textarea" :rows="4" autocomplete="off" spellcheck="false" placeholder='{"API_KEY":"新值","OLD_KEY":null}' />
              <small>仅写入，不回显。留空保留；null 删除；空字符串设为空值。密文保存，运行器保留 HOST/PORT/PATH/加载器配置。程序自身的日志可能包含敏感信息。</small>
            </div>
            <el-select v-else-if="field.kind === 'certificate'" v-model="form[field.key]" clearable filterable placeholder="本地默认证书仅供回环连接">
              <el-option v-for="certificate in certificates" :key="certificate.id" :value="certificate.id" :label="`${certificate.name} · ${certificate.domains.join(', ')} · ${certificate.trusted ? '系统已信任' : '未信任'} · ${certificate.status}`" />
            </el-select>
            <el-date-picker
              v-else-if="field.kind === 'datetime'"
              v-model="form[field.key]"
              type="datetime"
              clearable
              placeholder="不限制时间"
            />
            <div v-else-if="field.key === 'allow_install_scripts'">
              <el-switch v-model="form.allow_install_scripts" />
              <el-alert v-if="form.allow_install_scripts" type="warning" :closable="false" title="将执行此应用及其依赖的第三方安装/构建脚本，权限限于网站用户；只有信任源码时才开启。不会传入应用环境变量或使用 root。" />
            </div>
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
					: ['quota_mb','upload_kb','download_kb'].includes(field.key) ? 1048576
					: field.key === 'quota_files' ? 1000000
					: field.key === 'max_sessions' ? 20
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
              !installed || busy || (action === 'terminate' && !form.pid) || (definition.id === 'pure-ftpd' && ['account-limits','recount-quota'].includes(action) && report?.account_limits_ready === false)
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
          <el-form inline label-position="top">
            <el-form-item label="关键词"><el-input v-model="historyFilter.search" maxlength="128" clearable /></el-form-item>
            <el-form-item label="开始时间"><el-date-picker v-model="historyFilter.from_time" type="datetime" clearable /></el-form-item>
            <el-form-item label="结束时间"><el-date-picker v-model="historyFilter.to_time" type="datetime" clearable /></el-form-item>
            <el-form-item v-if="scopedHistory" label="网站"><el-select v-model="historyFilter.site_id" clearable filterable placeholder="所有网站"><el-option v-for="site in sites" :key="site.id" :value="site.id" :label="`${site.name} · ${site.domain}`" /></el-select></el-form-item>
            <el-form-item v-if="scopedHistory" label="计划／资源标识"><el-input v-model="historyFilter.resource_id" maxlength="64" clearable /></el-form-item>
          </el-form>
          <el-button :disabled="busy" @click="refreshHistory(true)">查询历史</el-button>
          <el-button :disabled="busy || historyOffset === 0" @click="historyPage(-1)">上一页</el-button>
          <el-button :disabled="busy || !history || historyOffset + historyLimit >= Number(history.total || 0)" @click="historyPage(1)">下一页</el-button>
          <span v-if="history">{{history.total}} 条匹配记录 · 第 {{Math.floor(historyOffset / historyLimit) + 1}} 页</span>
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
