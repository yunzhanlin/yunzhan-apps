<script setup lang="ts">
import { computed, onBeforeUnmount, ref, watch } from "vue";
import { ElMessage } from "element-plus";
import AppModuleReport from "./AppModuleReport.vue";
import AnalyticsQueryContext from "./AnalyticsQueryContext.vue";
import { analyticsQueryContext, analyticsQueryMatches, restoreAnalyticsQuery } from "./analyticsQueryContext";
import AnalyticsWorkspace from "./AnalyticsWorkspace.vue";
import WafWorkspace from "./WafWorkspace.vue";
import ThreatIDSRuleFeeds from "./ThreatIDSRuleFeeds.vue";
import ThreatIDSOperations from "./ThreatIDSOperations.vue";
import { idsBackgroundActions, validIDSOperation, validIDSRuleProfile, type IDSRuleProfile } from "./networkIDSOperations";
import { loadBalanceEntryFields } from "./loadBalanceReport";
import {RemoteRequestIdentity, remoteJobTerminal, remoteQueueReplyMatches, validRemoteJob, type RemoteRequestTicket} from "./remoteSync";
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
const idsOperationID = ref(""), idsOperationPending = ref(false);
let idsPendingSubmission: {identity:string;key:string}|undefined, idsAccessGeneration=0;
const pendingRemoteRequests=ref<RemoteRequestTicket[]>([]);
const remoteRequestIdentity=new RemoteRequestIdentity({
  getItem:key=>window.sessionStorage.getItem(key),
  setItem:(key,value)=>window.sessionStorage.setItem(key,value),
  removeItem:key=>window.sessionStorage.removeItem(key),
},undefined,()=>{pendingRemoteRequests.value=remoteRequestIdentity.list();});
const definition = ref<Definition>(),
  guidance = ref<Guidance>(),
  installed = ref(false),
  healthy = ref(false),
  report = ref<Record<string, any>>();
const form = ref<Record<string, any>>({}),
  sites = ref<{ id: string; name: string; domain: string }[]>([]);
const statisticsQuery = computed(()=>definition.value?.id === "website-statistics-v2" ? analyticsQueryContext(report.value) : undefined);
const statisticsDraftChanged = computed(()=>!!statisticsQuery.value && !analyticsQueryMatches(statisticsQuery.value,form.value));
function toggleHTTPHealth(enabled: boolean | string | number) {
  form.value.health_check=enabled ? {path:"/health",interval:30,timeout_ms:1500,expected_status:200,body_contains:"",failures:2,successes:2} : null;
}
function toggleBackendTLS(enabled: boolean | string | number) {
  form.value.backend_tls=enabled ? {server_name:form.value.domain || "",ca_pem:""} : null;
}
function setHTTPHealthScheme(value: string) {
  form.value.health_check.scheme=value;
  if(value==='http')form.value.health_check.ca_pem='';
  else if(!form.value.health_check.check_port)form.value.health_check.check_port=443;
}
function setHTTPHealthPort(value: number | undefined) {
  form.value.health_check.check_port=value ?? 0;
}
const certificates = ref<{id:string;name:string;domains:string[];trusted:boolean;status:string}[]>([]);
const selectedPlanID = ref("");
const selectedQuarantineState = ref("");
function canExecutePHP(action: string) {
  if (definition.value?.id !== "php-code-security") return true;
  if (action === "restore-quarantine") return selectedQuarantineState.value === "quarantined" && form.value.confirm === `RESTORE PHP ${form.value.resource_id}`;
  if (action === "recover-quarantine") return ["prepared", "conflict", "restoring"].includes(selectedQuarantineState.value) && form.value.confirm === `RECOVER PHP ${form.value.resource_id}`;
  if (action === "quarantine") return Boolean(form.value.site_id && form.value.path && form.value.expected_sha && form.value.confirm === `QUARANTINE ${form.value.path}`);
  return true;
}
const integrityModule = computed(() => ["file-monitor", "website-tamper-proof", "enterprise-tamper-proof"].includes(definition.value?.id || ""));
const revisionIdentity = computed(() => definition.value?.id === "files-sync" && activeTab.value.startsWith("remote-") ? form.value.remote_target_id : integrityModule.value ? form.value.site_id : definition.value?.id === "user-manager" ? form.value.username : definition.value?.id === "load-balance" ? form.value.domain : definition.value?.id === "pure-ftpd" ? "ftp-service" : definition.value?.id === "nfs-manager" ? "nfs-server" : definition.value?.id === "network-threat-detection" ? "network-ids" : form.value.resource_id);
const expectedRevision = computed(() => revisionIdentity.value === selectedPlanID.value ? form.value.expected_revision : 0);
const workspace = ref<Section[]>([]), history = ref<Record<string, any>>();
function clearWriteOnlyFields() {
  for (const field of definition.value?.fields || [])
    if (["password", "secret-json", "secret-text"].includes(field.kind)) form.value[field.key] = "";
}
watch(() => props.access, () => { idsAccessGeneration++;idsOperationID.value=""; idsOperationPending.value=false; idsPendingSubmission=undefined; clearWriteOnlyFields(); remoteRequestIdentity.bind((props.access as (AccessPlan & {user_id?:string})|undefined)?.user_id || ""); }, {deep:true,immediate:true});
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
function tabChanged(name: string | number) {
  if (name === "history") void refreshHistory(true);
  if(definition.value?.id==="files-sync" && String(name).startsWith("remote-"))report.value=undefined;
}
function fieldLabel(field:Field,section:Section):string {
  if(definition.value?.id==="files-sync" && section.id.startsWith("remote-")) {
    if(field.key==="enabled")return "启用远端连接";
    if(field.key==="expected_revision")return "连接策略修订号（选择连接自动填写）";
  }
  return field.label;
}
function historyPage(delta: number) { historyOffset.value = Math.max(0, historyOffset.value + delta * historyLimit.value); void refreshHistory(); }
const labels: Record<string, string> = {
  "ids-report":"刷新实际采集与告警", "ids-prepare":"准备或升级引擎（不启用采集）", "ids-config":"保存接口与本机范围", "ids-start":"启动被动采集", "ids-stop":"停止采集（保留日志）", "ids-boot":"保存开机启动选择", "ids-recover":"恢复中断迁移、配置或轮转", "ids-rotate":"立即轮转并保留历史",
  run: "刷新报告",
  "check-http": "立即执行 HTTP 检查",
  baseline: "建立基线",
  check: "检查变更",
  restore: "恢复所选文件",
  "quarantine-list": "刷新隔离箱并验证备份",
  quarantine: "隔离已审查文件",
  "restore-quarantine": "无覆盖恢复所选文件",
  "recover-quarantine": "恢复中断的隔离事务",
  preview: "同步预览",
  sync: "开始同步",
  "remote-targets": "刷新远端连接",
  "save-remote": "保存加密连接策略",
  "probe-remote": "只读验证 SFTP 与主机公钥",
  "remote-preview": "预览远端差异与冲突",
  "queue-remote": "提交远端后台任务",
  "remote-jobs": "刷新持久任务列表",
  "remote-job": "读取所选任务进度",
  "remote-archive": "读取已归档任务",
  "archive-remote-job": "按摘要归档所选终态任务（保留证据）",
  "cancel-remote": "请求停止后续文件交接",
  "recover-remote": "核对并恢复中断交接",
  save: "保存入口",
  probe: "健康检测",
  remove: "移除入口",
  recover: "恢复中断入口事务",
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
  "server-report": "刷新共享服务",
  "server-start": "启动共享服务",
  "server-stop": "停止共享服务",
  "server-probe": "检查真实 NFSv4 RPC",
  "server-recover": "恢复中断共享配置",
  "server-config": "保存共享监听配置",
  "export-save": "保存网站目录导出",
  "export-remove": "移除所选共享导出",
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
  selectedQuarantineState.value = "";
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
      nodes: [{ address: "127.0.0.1:21001", weight: 1, backup: false }, { address: "127.0.0.1:21002", weight: 1, backup: false }],
      health_check: null,
      backend_tls: null,
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
    if (id === "nfs-manager") Object.assign(form.value,{bind_address:"127.0.0.1",port:2049,client_allow:'["127.0.0.1"]',confirm:""});
    if (id === "php-code-security") Object.assign(form.value,{limit:50,offset:0,confirm:""});
    if (id === "files-sync") Object.assign(form.value,{remote_target_id:"",remote_request_id:"",remote_target:{address:"",port:22,username:"",host_key:"",root:"",backup_root:""}});
    if (id === "network-threat-detection") Object.assign(form.value,{network_interface:"",home_networks:"[]",prepare_ids:false,enabled:false,limit:50,offset:0});
    if (id === "website-statistics-v2") {
      const savedQuery=restoreAnalyticsQuery(analyticsQueryContext(report.value),sites.value);
      if (savedQuery) Object.assign(form.value,savedQuery);
    }
  } catch (e) {
    error.value = e instanceof Error ? e.message : String(e);
  } finally {
    busy.value = false;
  }
  if (installed.value && id === "nfs-manager") {
    await execute("server-report");
  } else if (installed.value && definition.value?.actions.includes("policies")) {
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
  if(id==="files-sync" && row.remote_target_id) {
    if(row.remote_target) {
      Object.assign(form.value,{remote_target_id:row.remote_target_id,remote_target:{...row.remote_target},enabled:row.enabled,expected_revision:row.revision});
      selectedPlanID.value=row.remote_target_id;activeTab.value="remote-target";
    } else if(validRemoteJob(row)) {
      Object.assign(form.value,{remote_request_id:row.remote_request_id,remote_target_id:row.remote_target_id,site_id:row.site_id,expected_sha:row.job_sha256||"",confirm:""});
      activeTab.value="remote-jobs";
    }
    ElMessage.info("已选中远端记录；修改或新任务请先核对连接修订号与实际进度");return;
  }
  const target = id === "php-code-security" ? row.state ? "quarantine-restore" : "quarantine" : id === "disk-analysis" ? "disk" : id === "daily-report" ? "archive" : id === "task-manager" ? "terminate" : id === "load-balance" ? Array.isArray(row.nodes) ? "entry" : "health" : id === "pm2-manager" ? "control" : id === "nfs-manager" ? row.clients ? "export" : "unmount" : id === "user-manager" || id === "pure-ftpd" ? "account" : id === "files-sync" ? "plans" : row.path !== undefined && ["website-tamper-proof", "enterprise-tamper-proof"].includes(id || "") ? "restore" : integrityModule.value && row.realtime !== undefined ? "watch" : "";
  activeTab.value = workspace.value.find(section => section.id === target)?.id || workspace.value[0]?.id || "overview";
  if (row.site_id !== undefined && row.site_id !== form.value.site_id) {
    form.value.path = "";
    form.value.expected_sha = "";
  }
  for (const f of definition.value?.fields || [])
    if (row[f.key] !== undefined) form.value[f.key] = f.kind === "json" ? JSON.stringify(row[f.key], null, 2) : row[f.key];
  if (id==="load-balance" && Array.isArray(row.nodes))
    Object.assign(form.value,loadBalanceEntryFields(row));
  if (id === "nfs-manager") {
    if (row.clients) form.value.client_allow=JSON.stringify(row.clients,null,2);
    form.value.confirm="";
  }
  if (id === "php-code-security") {
    selectedQuarantineState.value = row.state || "";
    form.value.expected_sha = row.sha256 || "";
    form.value.confirm = "";
    if (!row.state) { form.value.resource_id = ""; form.value.expected_revision = 0; selectedPlanID.value = ""; }
  }
  if (row.revision !== undefined) {
    selectedPlanID.value = integrityModule.value ? row.site_id : definition.value?.id === "user-manager" ? row.username : definition.value?.id === "load-balance" ? row.domain : row.resource_id || row.id;
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
const canCreateRemoteTask = computed(()=>remoteJobTerminal(report.value?.job) && report.value?.job.remote_request_id===form.value.remote_request_id && (!pendingRemoteRequests.value.some(row=>row.target===report.value?.job.remote_target_id) || pendingRemoteRequests.value.some(row=>row.key===form.value.remote_request_id)));
function createNewRemoteTask() {
  if(!canCreateRemoteTask.value)return;
  try{if(pendingRemoteRequests.value.some(row=>row.target===report.value?.job.remote_target_id))remoteRequestIdentity.release(report.value?.job);}catch(e){error.value=e instanceof Error?e.message:String(e);return;}
  form.value.remote_request_id="";report.value=undefined;activeTab.value="remote-transfer";
  ElMessage.info("已清空旧任务标识；请先核对源网站、排除项和连接修订号，再预览和提交新任务");
}
async function execute(action: string, ruleChoice?: IDSRuleProfile) {
  if (!definition.value || busy.value || !canExecutePHP(action)) return;
  if (definition.value.id === "network-threat-detection" && idsOperationPending.value && idsBackgroundActions.includes(action)) return;
  busy.value = true;
  error.value = "";
  const accessGeneration=idsAccessGeneration;
  try {
    if (definition.value.id === "network-threat-detection" && idsBackgroundActions.includes(action)) {
	  const accessGeneration=idsAccessGeneration;
      const body:Record<string,unknown>={expected_revision:expectedRevision.value};
      const input=inputBody(action);
      if(action==='ids-config') { body.network_interface=input.network_interface;body.home_networks=input.home_networks; }
      if(action==='ids-boot') body.enabled=form.value.enabled;
      if(action==='ids-rules') {
        if(!validIDSRuleProfile(ruleChoice))throw new Error("规则选择缺少明确身份；未提交");
        body.rule_profile=ruleChoice;
      }
      const identity=JSON.stringify({action,body});
      if(!idsPendingSubmission || idsPendingSubmission.identity!==identity) idsPendingSubmission={identity,key:crypto.randomUUID()};
      const result=await props.api(`/app-modules/network-threat-detection/${action}`,"POST",body,idsPendingSubmission.key);
      if(accessGeneration!==idsAccessGeneration)return;
      if(!validIDSOperation(result) || result.action!==action || Object.keys(result.input).length!==Object.keys(body).length || Object.keys(body).some(key=>JSON.stringify((result.input as unknown as Record<string,unknown>)[key])!==JSON.stringify(body[key]))) throw new Error("原生后台回执不能核对；保留原提交键，不重复创建任务");
      idsOperationID.value=result.id;idsOperationPending.value=['queued','running'].includes(result.state);idsPendingSubmission=undefined;
      ElMessage.info("原生后台任务已接受；请查看任务进度和实际报表，尚未宣称完成。");
      return;
    }
    const submitted=inputBody(action);
    if(definition.value.id==="files-sync" && action==="queue-remote") {
      const ticket=remoteRequestIdentity.begin(submitted);
      form.value.remote_request_id=ticket.key;submitted.remote_request_id=ticket.key;
    }
    const result = await props.api(
      `/app-modules/${definition.value.id}/${action}`,
      "POST",
      submitted,
    );
    if(accessGeneration!==idsAccessGeneration)return;
    if(definition.value.id==="files-sync" && action==="queue-remote") {
      if(!remoteQueueReplyMatches((result as any)?.job,submitted))throw new Error("远端任务回执无法核对；保留原任务标识，请读取持久任务，不重复创建");
      ElMessage.info("后台任务已接受；尚未宣称同步完成，请在远端任务中读取实际进度");
    }
    setReport(result);
    if(definition.value.id==="files-sync" && action==="save-remote" && (result as any)?.revision) {
      form.value.expected_revision=(result as any).revision;selectedPlanID.value=(result as any).remote_target_id;
    }
    if (definition.value.id === "network-threat-detection" && action.startsWith("ids-")) {
      if (report.value?.configuration) {
        form.value.network_interface=report.value.configuration.interface;
        form.value.home_networks=JSON.stringify(report.value.configuration.home_networks);
        form.value.expected_revision=report.value.configuration.revision;
        selectedPlanID.value="network-ids";
      } else if(action==='ids-report') {
        selectedPlanID.value="";form.value.expected_revision=0;
        form.value.network_interface="";form.value.home_networks="[]";
      }
      if (typeof report.value?.boot_enabled === "boolean") form.value.enabled=report.value.boot_enabled;
      if (action === "ids-prepare") { form.value.prepare_ids=false; ElMessage.info("准备任务已提交；仅表示开始准备，没有启动采集。稍后刷新实际状态。"); }
      if (report.value?.state === "recovering-runtime") ElMessage.info("引擎迁移恢复已提交，尚未完成；稍后刷新核对，采集保持关闭。");
    }
    if (definition.value.id === "load-balance" && action === "save") {
      form.value.expected_revision = (result as any).revision;selectedPlanID.value = form.value.domain;
    }
    if (definition.value.id === "load-balance" && action === "remove") {
      form.value.expected_revision = 0;selectedPlanID.value = "";
    }
    if (definition.value.id === "nfs-manager" && report.value?.config) {
      form.value.bind_address=report.value.config.bind_address;form.value.port=report.value.config.port;
      form.value.expected_revision=report.value.config.revision;selectedPlanID.value="nfs-server";form.value.confirm="";
    }
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
    if (definition.value.id === "php-code-security" && ["quarantine", "restore-quarantine", "recover-quarantine"].includes(action)) {
      selectedQuarantineState.value = "";
      form.value.confirm = "";
      activeTab.value = "quarantine-list";
      setReport(await props.api(`/app-modules/${definition.value.id}/quarantine-list`, "POST", {site_id:form.value.site_id, limit:50, offset:0}));
      selectedPlanID.value = "";
      form.value.expected_revision = 0;
    }
    if (!["run", "logs", "probe", "check", "preview", "ids-report", "ids-prepare", "queue-remote", "remote-job", "remote-jobs", "remote-archive", "remote-targets", "remote-preview", "probe-remote"].includes(action))
      ElMessage.success("操作已执行并记录审计");
    for (const f of definition.value.fields || [])
      if (["password", "secret-json", "secret-text"].includes(f.kind)) form.value[f.key] = "";
    if (
      [
        "create",
        "save",
        "update",
        "delete",
        "start",
        "stop",
        "restart",
        "mount",
        "unmount",
        "add",
        "remove",
        "recover",
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
        "server-config","server-start","server-stop","server-recover","export-save","export-remove",
      ].includes(action) &&
      definition.value.actions.includes("run")
    )
      setReport(
        await props.api(`/app-modules/${definition.value.id}/${definition.value.id==='nfs-manager' && action!=='mount' && action!=='unmount' ? 'server-report' : 'run'}`, "POST", {}),
      );
    if (definition.value.id === "pure-ftpd" && report.value?.config) {
      for (const [key,value] of Object.entries(report.value.config)) if (key !== "revision") form.value[key] = value;
      form.value.expected_revision = report.value.config.revision; selectedPlanID.value = "ftp-service";
	  const selected = report.value.users?.find((row: Record<string, any>) => row.username === form.value.username);
	  form.value.expected_sha = selected?.expected_sha || "";
    }
    if (definition.value.id === "nfs-manager" && report.value?.config) {
      form.value.expected_revision=report.value.config.revision;selectedPlanID.value="nfs-server";
    }
    if (definition.value.id === "load-balance" && Array.isArray(report.value?.entries)) {
      const entry = report.value.entries.find((row: Record<string, any>) => row.domain === selectedPlanID.value);
      form.value.expected_revision=entry?.revision || 0;
      if (!entry) selectedPlanID.value="";
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
    if(accessGeneration!==idsAccessGeneration)return;
    error.value = e instanceof Error ? e.message : String(e);
  } finally {
    if(definition.value?.id==="files-sync")clearWriteOnlyFields();
    busy.value = false;
  }
}
async function reviewRemoteTicket(ticket:RemoteRequestTicket) {
  if(busy.value || !definition.value || definition.value.id!=="files-sync")return;
  Object.assign(form.value,{remote_request_id:ticket.key,remote_target_id:ticket.target,site_id:ticket.site});
  activeTab.value="remote-jobs";
  await execute("remote-job");
}
async function refreshIDSAfterTask(id: string) {
  if(id!==idsOperationID.value || definition.value?.id!=="network-threat-detection" || !installed.value || !visible.value || !props.access || !canReadPath(props.access,"/app-modules/network-threat-detection/operations"))return;
  // A completed native operation can change the revision/profile. Do not
  // permit a second mutation using the cached old report or invented revision.
  selectedPlanID.value="";form.value.expected_revision=0;
  if(report.value)report.value={...report.value,configuration:null,rule_profile:null};
  if(!busy.value && definition.value.actions.includes("ids-report"))await execute("ids-report");
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
        <ThreatIDSOperations v-if="definition.id === 'network-threat-detection'" :api="api" :operation-id="idsOperationID" :installed="installed" :access="access" @pending="idsOperationPending=$event" @completed="refreshIDSAfterTask" />
        <el-alert v-if="definition.id==='files-sync' && form.remote_request_id" :title="`当前远端任务标识：${form.remote_request_id}。未知回执或执行中保留原标识，读取持久任务核对；恢复前不要提交新的同步。`" type="info" :closable="false" />
        <el-button v-if="definition.id==='files-sync' && form.remote_request_id" :disabled="busy || !canCreateRemoteTask" @click="createNewRemoteTask">已核对旧任务，准备新的同步（不立即执行）</el-button>
        <div v-if="definition.id==='files-sync' && pendingRemoteRequests.length" class="remote-pending-requests" aria-label="本账户待核对远端任务">
          <p>本账户待核对远端任务：关闭对话框或刷新页面仍保留标识；只保存任务身份，不保存密码、私钥或排除路径。</p>
          <el-button v-for="ticket in pendingRemoteRequests" :key="ticket.key" :disabled="busy" @click="reviewRemoteTicket(ticket)">读取原任务 · {{ticket.target}} · {{ticket.key}}</el-button>
        </div>
        <AnalyticsWorkspace v-if="definition.id === 'website-analytics'" :api="api" :installed="installed" :installed-version="versionStatus?.version_known ? versionStatus.installed_version : undefined" :sites="sites">
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
        <ThreatIDSRuleFeeds v-if="section.id==='ids-rules' && activeTab==='ids-rules'" :api="api" :installed="installed" :access="access" :on-job="onJob" :revision="expectedRevision" :native-pending="idsOperationPending || busy" :active-profile="report?.rule_profile" :on-select="choice=>execute('ids-rules',choice)" />
        <el-alert v-if="definition.id === 'pure-ftpd' && ['account-limits','quota'].includes(section.id) && report?.account_limits_ready === false" type="warning" :closable="false" title="当前 FTP 尚未更新到受管独立运行时。请先在版本与更新中更新应用；不会静默替换系统 FTP。" />
        <el-form label-position="top" class="module-fields">
          <el-form-item
            v-for="field in sectionFields(section)"
            :key="field.key"
            :label="fieldLabel(field,section)"
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
            <div v-else-if="field.kind === 'remote-sync'" class="http-health-editor">
              <label>固定 IP<el-input v-model="form.remote_target.address" placeholder="服务器 IPv4 / IPv6，不接受域名" /></label>
              <label>SFTP 端口<el-input-number v-model="form.remote_target.port" :min="1" :max="65535" /></label>
              <label>受限非 root 账户<el-input v-model="form.remote_target.username" maxlength="32" /></label>
              <label>已独立核实的 SSH 主机公钥<el-input v-model="form.remote_target.host_key" type="textarea" :rows="3" maxlength="2048" placeholder="ssh-ed25519 AAAA…；不得从首次连接自动信任" /></label>
              <label>目标普通绝对目录<el-input v-model="form.remote_target.root" maxlength="512" placeholder="/srv/sites/example/public" /></label>
              <label>公开目录之外的私有备份目录（0700）<el-input v-model="form.remote_target.backup_root" maxlength="512" placeholder="/srv/private/yunzhan-sync" /></label>
            </div>
            <div v-else-if="field.kind === 'secret-text'">
              <el-input v-model="form[field.key]" type="textarea" :rows="5" maxlength="32768" autocomplete="off" spellcheck="false" placeholder="仅本次写入；提交、关闭或选择记录后清除，不回显、不保存到浏览器存储" />
            </div>
            <div v-else-if="field.kind === 'menus'">
              <el-select v-model="form.menu_ids" multiple placeholder="空列表表示仅保留自身账户安全">
                <el-option v-for="menu in menuCatalog" :key="menu.id" :label="menu.label" :value="menu.id" :disabled="menu.admin_only && form.role !== 'admin' || access !== undefined && !access?.menu_ids.includes(menu.id)" />
              </el-select>
              <el-button link type="primary" @click="roleDefaultMenus">使用角色默认菜单</el-button>
              <small>菜单是原角色权限的上限，不会扩大网站范围。修改后撤销旧会话；至少保留一个完整权限管理员。</small>
            </div>
            <div v-else-if="field.kind === 'backend-tls'" class="http-health-editor">
              <el-switch :model-value="Boolean(form.backend_tls)" aria-label="启用 HTTPS 后端转发" @update:model-value="toggleBackendTLS" />
              <template v-if="form.backend_tls">
                <label>后端证书名称 / SNI / Host<el-input v-model="form.backend_tls.server_name" aria-label="HTTPS 后端证书名称" maxlength="253" placeholder="backend.example.com" /></label>
                <label>入口专用公共 CA PEM（必填）<el-input v-model="form.backend_tls.ca_pem" type="textarea" :rows="5" maxlength="16384" aria-label="HTTPS 后端公共 CA PEM" placeholder="最多 4 个公共 CA 证书；不接受私钥或路径" /></label>
                <small>真实业务请求使用节点的固定 IP 与转发端口，通过 TLS 1.2/1.3 并验证证书名称、链和有效期。CA 仅作用于本入口，不修改系统信任；失败不会退回明文 HTTP。默认关闭，保存后生效。配置、清单与 CA 三文件事务可恢复；健康检查为独立策略，不自动摘除节点。</small>
              </template>
            </div>
            <div v-else-if="field.kind === 'http-health'" class="http-health-editor">
              <el-switch :model-value="Boolean(form.health_check)" aria-label="启用持续 HTTP 应用检查" @update:model-value="toggleHTTPHealth" />
              <template v-if="form.health_check">
                <label>检查协议<el-select :model-value="form.health_check.scheme || 'http'" aria-label="应用检查协议" @update:model-value="setHTTPHealthScheme">
                  <el-option value="http" label="HTTP" /><el-option value="https" label="HTTPS（验证证书）" />
                </el-select></label>
                <label>独立就绪端口（HTTP 的 0 沿用转发端口）<el-input-number :model-value="form.health_check.check_port || 0" @update:model-value="setHTTPHealthPort" aria-label="应用检查独立端口" :min="form.health_check.scheme==='https' ? 1 : 0" :max="65535" :precision="0" /></label>
                <label v-if="form.health_check.scheme==='https'">入口专用 CA（可选）<el-input v-model="form.health_check.ca_pem" type="textarea" :rows="4" maxlength="16384" aria-label="HTTPS 检查公共 CA PEM" placeholder="仅公共 CA PEM，留空使用系统信任库；不接受私钥" /></label>
                <label>相对请求路径<el-input v-model="form.health_check.path" aria-label="HTTP 检查相对路径" maxlength="512" placeholder="/health" /></label>
                <label>检查间隔（秒）<el-input-number v-model="form.health_check.interval" aria-label="HTTP 检查间隔秒" :min="30" :max="3600" :precision="0" /></label>
                <label>请求超时（毫秒）<el-input-number v-model="form.health_check.timeout_ms" aria-label="HTTP 检查超时毫秒" :min="500" :max="5000" :precision="0" /></label>
                <label>预期 HTTP 状态<el-input-number v-model="form.health_check.expected_status" aria-label="HTTP 检查预期状态码" :min="200" :max="299" :precision="0" /></label>
                <label>响应包含的内容<el-input v-model="form.health_check.body_contains" aria-label="HTTP 检查内容包含" maxlength="256" placeholder="可留空，最多 256 字节" /></label>
                <label>连续失败次数<el-input-number v-model="form.health_check.failures" aria-label="连续失败阈值" :min="1" :max="10" :precision="0" /></label>
                <label>连续恢复次数<el-input-number v-model="form.health_check.successes" aria-label="连续恢复阈值" :min="1" :max="10" :precision="0" /></label>
                <small>检查与业务转发分别配置。HTTP 转发的 HTTPS 检查须用独立就绪端口；HTTPS 后端可在同一端口检查。检查仍验证入口域名（可与后端名称不同）、证书链和有效期，最低 TLS 1.2；检查 CA 独立于后端 CA。保存后只观测、不自动改动流量。</small>
              </template>
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
            v-for="action in section.actions.filter(action=>action!=='ids-rules')"
            :key="action"
            :disabled="
              !installed || busy || !canExecutePHP(action) || (definition.id === 'network-threat-detection' && idsOperationPending && idsBackgroundActions.includes(action)) || (action === 'terminate' && !form.pid) || (definition.id === 'pure-ftpd' && ['account-limits','recount-quota'].includes(action) && report?.account_limits_ready === false)
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
        <section v-if="report !== undefined" class="workflow-result" aria-label="实际执行结果">
          <h3>服务器返回的实际结果</h3>
          <template v-if="definition.id === 'website-statistics-v2'">
            <el-alert v-if="statisticsDraftChanged" type="warning" :closable="false" title="筛选条件已修改，尚未刷新：下方仍是已返回查询范围的报告，不是当前表单的结果。" />
            <AnalyticsQueryContext :report="report" />
          </template>
          <AppModuleReport :id="definition.id" :report="report" @select="selected" />
        </section>
        </el-tab-pane>
        <el-tab-pane label="报告与日志" name="reports">
          <AnalyticsQueryContext v-if="definition.id === 'website-statistics-v2' && report !== undefined" :report="report" />
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
        <el-tab-pane v-if="definition.id === 'network-threat-detection' && !workspace.some(section=>section.id==='ids-rules')" label="规则数据" name="rule-feeds" lazy>
          <ThreatIDSRuleFeeds :api="api" :installed="installed" :access="access" :on-job="onJob" :revision="expectedRevision" :native-pending="idsOperationPending || busy" :active-profile="report?.rule_profile" :on-select="definition.actions.includes('ids-rules') ? choice=>execute('ids-rules',choice) : undefined" />
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
.http-health-editor { width:100%; display:flex; flex-direction:column; gap:10px; }
.http-health-editor small { color:#657181; line-height:1.6; }
.http-health-editor label { display:flex; flex-direction:column; gap:5px; font-size:12px; color:#526373; }
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
