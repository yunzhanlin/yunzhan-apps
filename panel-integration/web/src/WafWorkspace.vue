<script setup lang="ts">
import { computed, onMounted, onUnmounted, ref, watch } from "vue";
import { ElMessage } from "element-plus";
import { formatPanelDateTime } from "./panelTime";
import { createRotationRefresh } from "./wafRotationRefresh";
import { bodyInventoryPresentation } from "./wafBodyInventory";
import WafBodyRetention from "./WafBodyRetention.vue";
type API = <T>(path: string, method?: string, body?: unknown, key?: string) => Promise<T>;
interface Entry { id: string; value: string; site_id?: string }
interface Rule { id: string; name: string; site_id?: string; field: string; operator: string; value: string; action: string; enabled: boolean }
interface SitePolicy { site_id: string; mode: string; rate_per_second: number; burst: number; cc_enabled?: boolean; groups?: Record<string, boolean> }
interface CCRule { id: string; site_id?: string; path: string; prefix: boolean; rate_per_second: number; burst: number; enabled: boolean }
interface BodyPolicy { mode: string; paranoia_level: number; inbound_threshold: number; body_limit_kib: number; non_file_limit_kib: number; json_depth: number; argument_limit: number }
interface BodySite { site_id: string; policy: BodyPolicy }
interface EngineStatus { job_id: string; state: string; error?: string; architecture?: string; engine_version?: string; crs_version?: string; nginx_version?: string; integrity_verified: boolean; module_abi_validated: boolean; build_only: boolean; steps: { time: string; message: string }[] }
interface Preview { http_config: string; server_config: string; settings: Config; changes?: {path: string; action: string}[]; body_rules?: {site_id: string; configuration: string}[] }
interface TrustedProxy { enabled: boolean; header: "X-Forwarded-For" | "X-Real-IP"; recursive: boolean; trusted_cidrs: string[]; acknowledge_header_control: boolean }
interface BodyLogRotation { enabled:boolean; rotate_mib:number; max_age_minutes:number }
interface BodyLogRetention {enabled:boolean;days:number;keep_latest:number;confirm_delete_completed_snapshots:boolean}
interface Config { profile: string; rate_per_second: number; body?: {engine_job_id: string; sites: BodySite[]}; trusted_proxy?: TrustedProxy; body_log_rotation?:BodyLogRotation; body_log_retention?:BodyLogRetention; policy: { schema_version: number; revision: number; mode: string; cc_enabled: boolean; burst: number; groups: Record<string, boolean>; lists: Record<string, Entry[]>; rules: Rule[]; sites: SitePolicy[]; cc_rules: CCRule[] } }
interface Status { installed: boolean; healthy: boolean; enabled: boolean; version?: string; detail: string }
interface Site { id: string; name: string; domain: string; status?: string; settings?: { waf_enabled?: boolean; web_server?: string } }
interface Dimension { name: string; count: number }
interface Event { time: string; site: string; site_id?: string; ip: string; peer?: string; path?: string; method: string; status: number; reason: string; action: string; rate?: string }
interface Report { events: Event[]; total: number; blocked: number; observed: number; sources: number; partial: boolean; scanned: number; rules: Dimension[]; ips: Dimension[]; sites: Dimension[]; hours: Dimension[]; from: string; to: string }
interface BodyEvent { time: string; site_id: string; rule_id: number; phase: number; severity: number; disruptive_mark: boolean }
interface BodyReport { events: BodyEvent[]; rule_matches: number; available: boolean; partial: boolean; rejected_lines: number; scanned: number; counting_contract: string; log_bytes: number; max_bytes: number; capacity_exhausted: boolean; legacy_log: boolean; metadata_best_effort: boolean }
interface BodyArchive {id:string;captured_at:string;bytes:number;sha256:string;state:string}
interface BodyRecovery {archive:BodyArchive;index_sha256:string;snapshot_sha256:string;snapshot_bytes:number;snapshot_missing:boolean}
interface BodyRotationRecord { id:string; state:string; checked_at:string; window_started_at:string; last_rotation_at?:string; log_bytes:number; archive_count:number; policy_revision:number; history:{id:string;at:string;outcome:string;archive?:BodyArchive}[] }
interface BodyRotationStatus { available:boolean; enabled:boolean; stale:boolean; sha256?:string; record?:BodyRotationRecord; message?:string; history_limit:number; automatic_archive_deletion:boolean }
interface History { id: string; kind: string; state: string; error: string; created_at: string }
const props = defineProps<{ api: API; engine?: "nginx-waf" | "apache-waf"; onInstall: (id: string, settings: Record<string, unknown>) => Promise<string> }>();
const engine = props.engine || "nginx-waf";
const apache = engine === "apache-waf";
const engineName = apache ? "Apache" : "Nginx";
const endpoint = (operation: string) => `/software/${engine}/${operation}`;
const groups = [ { id: "method", name: "危险请求方法", hint: "阻断 TRACE / TRACK" }, { id: "sql", name: "SQL 注入特征", hint: "URI / 查询参数中的常见注入特征" }, { id: "xss", name: "XSS 特征", hint: "脚本标签与危险协议特征" }, { id: "command", name: "命令执行特征", hint: "常见脚本执行与下载命令特征" }, { id: "traversal", name: "敏感路径访问", hint: "路径穿越、.git / .env 等暴露" }, { id: "scanner", name: "扫描器识别", hint: "已知扫描器 User-Agent 特征" }, { id: "cookie", name: "Cookie 特征检查", hint: "可选；匹配特征但不记录 Cookie 内容" } ];
const listKinds = [ { id: "ip_allow", name: "IP 白名单" }, { id: "ip_deny", name: "IP 黑名单" }, { id: "url_allow", name: "URL 白名单" }, { id: "url_deny", name: "URL 黑名单" }, { id: "ua_allow", name: "UA 白名单" }, { id: "ua_deny", name: "UA 黑名单" } ];
const fields = [{ id: "uri", name: "请求路径" }, { id: "args", name: "查询参数" }, { id: "user_agent", name: "User-Agent" }, { id: "method", name: "请求方法" }, { id: "cookie", name: "Cookie" }];
const modeLabel = (mode: string) => ({ block: "阻断", observe: "观察", off: "停用", inherit: "继承全局" }[mode] || mode);
const clone = <T,>(v: T): T => JSON.parse(JSON.stringify(v)) as T;
const newID = () => crypto.randomUUID().replaceAll("-", "");
const cfg = ref<Config>(), applied = ref<Config>(), status = ref<Status>(), sites = ref<Site[]>([]), implementation = ref("");
const ccObservationSupported = computed(() => !apache && status.value?.installed && ["2.3.0","2.4.0","2.5.0","2.5.1"].includes(status.value.version || ""));
const bodyRotationSupported = computed(() => !apache && status.value?.installed && ["2.4.0","2.5.0","2.5.1"].includes(status.value.version || ""));
const bodyRetentionSupported = computed(() => !apache && status.value?.installed && ["2.5.0","2.5.1"].includes(status.value.version || ""));
const rateOutcome = (value?: string) => ({REJECTED:"已拒绝",REJECTED_DRY_RUN:"模拟拒绝（放行）",DELAYED_DRY_RUN:"模拟延迟（放行）",DELAYED:"已延迟",PASSED:"通过"}[value || ""] || "—");
const defaults = ref<Config>();
const tab = ref("overview"), busy = ref(false), reportBusy = ref(false), error = ref(""), saved = ref(""), preview = ref("");
const report = ref<Report>(), history = ref<History[]>([]), jsonInput = ref("");
const engines = ref<EngineStatus[]>([]), engineJob = ref<EngineStatus>(), engineBusy = ref(false), bodySite = ref("");
const bodyReport = ref<BodyReport>(), bodyReportBusy = ref(false), bodyPage = ref(1), bodyFilter = ref({site_id:"",rule:"",phase:""});
const bodyArchives = ref<BodyArchive[]>([]), bodyLogBusy = ref(false);
const bodyInventoryKnown = ref(false);
const bodyInventoryView = computed(() => bodyInventoryPresentation(bodyInventoryKnown.value, bodyArchives.value.length));
const bodyRotation = ref<BodyRotationStatus>(), bodyRotationError = ref("");
const bodyRetentionSafety = ref({blocked:false,unverified:true,busy:false});
const bodyRetentionPreventRotation = computed(() => bodyRetentionSupported.value && (bodyRetentionSafety.value.blocked || bodyRetentionSafety.value.unverified || bodyRetentionSafety.value.busy));
let bodyRotationTimer: ReturnType<typeof setTimeout> | undefined;
const bodyRotationState = (v?:string) => ({idle:"等待触发",rotating:"轮转中，结果尚未确认",completed:"备份与轮转已核对",blocked:"暂停，历史保留",unknown:"结果未知，需核对",retained_unknown:"未知结果已保留，未宣称成功"}[v || ""] || "尚无调度记录");
function toggleBodyRotation(value: string | number | boolean) {
  if (!cfg.value || !bodyRotationSupported.value) return;
  cfg.value.body_log_rotation ||= {enabled:false,rotate_mib:16,max_age_minutes:60};
  cfg.value.body_log_rotation.enabled = value === true;
}
const refreshBodyRotation = createRotationRefresh<BodyRotationStatus>({
  supported: () => !disposed && !!bodyRotationSupported.value,
  readStatus: () => props.api<BodyRotationStatus>(endpoint("body-log/rotation")),
  applyStatus: value => { bodyRotation.value = value; },
  // The per-minute check time changes even when no rotation occurred. Do not
  // rescan up to 4 MiB merely because that clock advanced.
  fingerprint: value => JSON.stringify([value.available, value.record?.state,
    value.record?.archive_count, value.record?.last_rotation_at, value.record?.history]),
  refreshEvidence: async () => {
    if (disposed || bodyReportBusy.value || bodyLogBusy.value) {
      bodyRotationError.value = "库存与报表尚待刷新，将在下一次状态检查重试";
      return false;
    }
    const [reportRead] = await Promise.all([refreshBodyReport(true), refreshBodyArchives()]);
    if (!reportRead) throw new Error("规则报表尚未核验，库存与报表不能当成最新状态");
    return true;
  },
  clearError: () => { bodyRotationError.value = ""; },
  onError: e => { bodyRotationError.value = (e as Error).message; },
});
function scheduleBodyRotationStatus() {
  if(bodyRotationTimer)clearTimeout(bodyRotationTimer);
  if(disposed || tab.value!=="body" || !bodyRotationSupported.value)return;
  bodyRotationTimer=setTimeout(async()=>{await refreshBodyRotation();scheduleBodyRotationStatus();},30000);
}
async function retainAutomaticRotation() {
  if(bodyLogBusy.value || !bodyRotation.value?.sha256)return;
  bodyLogBusy.value=true;error.value="";
  try {await props.api(endpoint("body-log/rotation/retain"),"POST",{sha256:bodyRotation.value.sha256,acknowledge_unknown_rotation_not_repeated:true},newID());await refreshBodyRotation();saved.value="已按摘要保留未知轮转结果；当前日志与快照没有删除或再次截断。";}
  catch(e){error.value=(e as Error).message;}finally{bodyLogBusy.value=false;}
}
type BodyIndexStage = {id:string;bytes:number;sha256:string};
const bodyRecovery = ref<BodyRecovery[]>([]), bodyInventoryWarning = ref(""), bodyIndexStages = ref<BodyIndexStage[]>([]);
const bodyArchiveState = (state:string) => ({completed:"备份与轮转完成",prepared:"轮转未确认完成",copying:"复制未完成",removing:"删除未完成，可按原摘要重试",retained:"证据已保留，轮转结果未知","retained-incomplete":"不完整快照已保留","retained-missing":"快照缺失，仅保留原意图"}[state] || state);
const bodyBytes = (bytes:number) => bytes < 1024 ? `${bytes} 字节` : bytes < 1048576 ? `${(bytes/1024).toFixed(2)} KiB` : `${(bytes/1048576).toFixed(2)} MiB`;
const exportedBodyArchives = ref<string[]>([]);
const bodyRange = ref<[Date, Date]>();
let engineTimer: ReturnType<typeof setTimeout> | undefined;
let disposed = false;
watch([tab,bodyRotationSupported],()=>scheduleBodyRotationStatus());
const verifiedEngines = computed(() => engines.value.filter(x => x.state === "ready" && x.integrity_verified && x.module_abi_validated && x.build_only));
const bodyDefault = (): BodyPolicy => ({ mode: "observe", paranoia_level: 1, inbound_threshold: 5, body_limit_kib: 1024, non_file_limit_kib: 256, json_depth: 64, argument_limit: 256 });
const buildState = (s: string) => ({ queued:"排队", running:"构建中", ready:"程序已验证", succeeded:"构建任务完成", failed:"构建失败", needs_attention:"需要核对" }[s] || s);
const filter = ref({ site_id: "", ip: "", rule: "", action: "" }), range = ref<[Date, Date]>(), page = ref(1), limit = 50;
const listKind = ref("ip_deny"), listScope = ref(""), listValue = ref(""), siteSearch = ref(""), selectedSite = ref("");
const newRule = ref<Omit<Rule, "id">>({ name: "", site_id: "", field: "uri", operator: "contains", value: "", action: "block", enabled: true });
const newCC = ref<Omit<CCRule, "id">>({ site_id: "", path: "", prefix: false, rate_per_second: 5, burst: 10, enabled: true });
const dirty = computed(() => !!cfg.value && JSON.stringify(cfg.value) !== JSON.stringify(applied.value));
const disabledTrustedProxy = (): TrustedProxy => ({ enabled:false, header:"X-Forwarded-For", recursive:false, trusted_cidrs:[], acknowledge_header_control:false });
function toggleTrustedProxy(value: string | number | boolean) {
  if (!cfg.value) return;
  cfg.value.trusted_proxy ||= disabledTrustedProxy();
  cfg.value.trusted_proxy.enabled = value === true;
  cfg.value.trusted_proxy.acknowledge_header_control = false;
}
function changeTrustedProxyHeader(value: string) {
  if (!cfg.value?.trusted_proxy || !["X-Forwarded-For","X-Real-IP"].includes(value)) return;
  cfg.value.trusted_proxy.header = value as TrustedProxy["header"];
  cfg.value.trusted_proxy.acknowledge_header_control = false;
  if (value === "X-Real-IP") cfg.value.trusted_proxy.recursive = false;
}
function changeTrustedProxyRecursive() { if (cfg.value?.trusted_proxy) cfg.value.trusted_proxy.acknowledge_header_control = false; }
// Keep raw textarea edits separate so Enter and a partially typed CIDR are
// not erased by a normalizing computed setter. Normalize only the payload.
const trustedProxyCIDRs = ref("");
watch(cfg, value => { trustedProxyCIDRs.value = (value?.trusted_proxy?.trusted_cidrs || []).join("\n"); }, {flush:"sync"});
function editTrustedProxyCIDRs(value: string) {
  if (!cfg.value?.trusted_proxy) return;
  cfg.value.trusted_proxy.trusted_cidrs = value.split(/\r?\n/).map(x=>x.trim()).filter(Boolean);
  cfg.value.trusted_proxy.acknowledge_header_control = false;
}
const listCount = computed(() => Object.values(cfg.value?.policy.lists || {}).reduce((sum, xs) => sum + xs.length, 0));
const scopedSites = computed(() => sites.value.filter(s => !siteSearch.value || `${s.name} ${s.domain}`.toLowerCase().includes(siteSearch.value.toLowerCase())));
const siteName = (id?: string) => !id ? "全部受管站点" : sites.value.find(s => s.id === id)?.domain || `失效站点 ${id}`;
const reasonName = (id: string) => groups.find(g => g.id === id)?.name || ({ cc: "CC 请求限速", "ip-deny": "IP 黑名单", "url-deny": "URL 黑名单", "ua-deny": "UA 黑名单", "legacy-args": "旧版参数规则", "legacy-uri": "旧版地址规则" }[id]) || cfg.value?.policy.rules.find(r => `custom-${r.id}` === id)?.name || id;
async function loadConfig() {
  const out = await props.api<{ settings: Config; defaults: Config; status: Status; implementation_version: string }>(endpoint("config"));
  defaults.value = clone(out.defaults);
  cfg.value = clone(out.settings); applied.value = clone(out.settings); status.value = out.status; implementation.value = out.implementation_version;
}
function reportURL(exportAll = false) {
  const q = new URLSearchParams({ page: String(exportAll ? 1 : page.value), limit: String(exportAll ? 5000 : limit) });
  for (const [k, v] of Object.entries(filter.value)) if (v) q.set(k, v);
  if (range.value) { q.set("from", range.value[0].toISOString()); q.set("to", range.value[1].toISOString()); }
  return `${endpoint("report")}?${q}`;
}
async function refreshReport(reset = false) {
  if (!status.value?.installed || reportBusy.value) return;
  if (reset) page.value = 1;
  reportBusy.value = true;
  try { report.value = await props.api<Report>(reportURL()); }
  catch (e) { error.value = (e as Error).message; }
  finally { reportBusy.value = false; }
}
async function refreshHistory() { try { history.value = (await props.api<{ entries: History[] }>(endpoint("history"))).entries; } catch (e) { error.value = (e as Error).message; } }
async function refreshEngines() { if (apache) return; engines.value = (await props.api<{entries: EngineStatus[]}>(endpoint("engines"))).entries; }
function bodyReportURL(exportAll = false) {
  const query = new URLSearchParams({page:String(exportAll ? 1 : bodyPage.value),limit:String(exportAll ? 5000 : 50)});
  for(const [key,value] of Object.entries(bodyFilter.value)) if(value) query.set(key,value);
  if(bodyRange.value) {query.set("from",bodyRange.value[0].toISOString());query.set("to",bodyRange.value[1].toISOString());}
  return `${endpoint("body-report")}?${query}`;
}
async function refreshBodyReport(reset = false) { if(apache || !status.value?.installed || bodyReportBusy.value) return false; if(reset) bodyPage.value=1; bodyReportBusy.value=true; try { bodyReport.value=await props.api<BodyReport>(bodyReportURL()); return true; } catch(e) { error.value=(e as Error).message; return false; } finally {bodyReportBusy.value=false;} }
async function exportBodyReport() { if(bodyReportBusy.value) return;bodyReportBusy.value=true;try {download("yunzhan-waf-body-rule-matches.json",await props.api<BodyReport>(bodyReportURL(true)));}catch(e){error.value=(e as Error).message;}finally{bodyReportBusy.value=false;} }
async function refreshBodyArchives(){
  if(apache||!status.value?.installed)return;
  try {
    const out=await props.api<{entries:BodyArchive[];recovery_entries:BodyRecovery[];index_stages:BodyIndexStage[];inventory_warning:string}>(endpoint("body-log/archives"));
    if(!Array.isArray(out.entries) || out.entries.length>8 || typeof out.inventory_warning!=="string")throw new Error("备份库存响应无法核验");
    bodyArchives.value=out.entries;bodyRecovery.value=out.recovery_entries||[];bodyIndexStages.value=out.index_stages||[];bodyInventoryWarning.value=out.inventory_warning;
    bodyInventoryKnown.value=!out.inventory_warning;
  } catch(e) {bodyInventoryKnown.value=false;throw e;}
}
async function retainBodyIndexStage(item:BodyIndexStage){if(bodyLogBusy.value)return;bodyLogBusy.value=true;error.value="";try{await props.api(endpoint(`body-log/index-stages/${item.id}/retain`),"POST",{sha256:item.sha256,acknowledge_uncommitted_index_not_applied:true},newID());await refreshBodyArchives();saved.value="已按摘要保留未提交索引的原始文件；没有将它接管为有效索引，也未修改当前日志。";}catch(e){error.value=(e as Error).message;}finally{bodyLogBusy.value=false;}}
async function retainBodySnapshot(item:BodyRecovery){if(bodyLogBusy.value)return;bodyLogBusy.value=true;error.value="";try{await props.api(endpoint(`body-log/archives/${item.archive.id}/retain`),"POST",{index_sha256:item.index_sha256,snapshot_sha256:item.snapshot_sha256,snapshot_missing:item.snapshot_missing,acknowledge_unknown_rotation_and_incomplete_snapshot:true},newID());await refreshBodyArchives();saved.value="已保留未完成快照及恢复证据；没有再次截断当前日志，也未把未知结果标成成功。";}catch(e){error.value=(e as Error).message;}finally{bodyLogBusy.value=false;}}
function exportBodyRecovery(item:BodyRecovery){download(`yunzhan-waf-log-recovery-${item.archive.id}.json`,{observed:item,contract:"intent_and_digest_only_not_a_rule_event_export"});exportedBodyArchives.value.push(item.archive.id);}
async function rotateBodyLog(){if(bodyLogBusy.value||bodyRetentionPreventRotation.value)return;bodyLogBusy.value=true;error.value="";try{await props.api(endpoint("body-log/rotate"),"POST",{},newID());await Promise.all([refreshBodyReport(true),refreshBodyArchives()]);saved.value="已持久化私有备份并轮转当前元数据日志；Nginx 未重载，历史未删除。";}catch(e){error.value=(e as Error).message;}finally{bodyLogBusy.value=false;}}
async function exportBodyArchive(id:string){if(bodyLogBusy.value)return;bodyLogBusy.value=true;try{download(`yunzhan-waf-body-snapshot-${id}.json`,await props.api(endpoint(`body-log/archives/${id}`)));exportedBodyArchives.value.push(id);}catch(e){error.value=(e as Error).message;}finally{bodyLogBusy.value=false;}}
async function removeBodyArchive(archive:BodyArchive){if(bodyLogBusy.value||!exportedBodyArchives.value.includes(archive.id))return;bodyLogBusy.value=true;error.value="";try{await props.api(endpoint(`body-log/archives/${archive.id}/remove`),"POST",{sha256:archive.sha256,acknowledge_bounded_export_and_permanent_removal:true},newID());await refreshBodyArchives();saved.value="已永久删除明确选中的日志快照；当前日志和其它备份未修改。";}catch(e){error.value=(e as Error).message;}finally{bodyLogBusy.value=false;}}
async function pollEngine(id: string) {
  if (disposed) return;
  engineTimer=undefined;
  try {
    engineJob.value = await props.api<EngineStatus>(endpoint(`engine/jobs/${id}`));
    await refreshEngines();
    if (["queued", "running"].includes(engineJob.value.state)) engineTimer = setTimeout(() => pollEngine(id), 5000);
    else { await refreshHistory(); if (engineJob.value.state === "ready") saved.value = "原生程序已完成 ABI 与完整性验证，尚未启用任何网站。选择引擎和网站策略后预览、保存才会应用。"; }
  } catch(e) { error.value = `暂时无法核实构建状态，未宣称成功：${(e as Error).message}`; engineTimer = setTimeout(() => pollEngine(id), 15000); }
}
async function buildEngine() {
  if (apache || engineBusy.value || busy.value || engineJob.value && ["queued", "running"].includes(engineJob.value.state)) return;
  engineBusy.value = true; error.value = "";
  try { const out = await props.api<{job_id:string}>(endpoint("engine/build"), "POST", {}, newID()); await pollEngine(out.job_id); }
  catch(e) { error.value = (e as Error).message; }
  finally { engineBusy.value = false; }
}
async function stopEngine() {
  const id=engineJob.value?.job_id;
  if(!id || engineBusy.value || !["queued","running"].includes(engineJob.value?.state || "")) return;
  engineBusy.value=true;error.value="";
  try { await props.api(endpoint(`engine/jobs/${id}/cancel`),"POST",{},newID()); await pollEngine(id);saved.value="已请求停止专用构建；原有网站不受影响。失败/中断记录和目录保留，新建任务才能重新构建。"; }
  catch(e){error.value=(e as Error).message;}
  finally{engineBusy.value=false;}
}
function selectBodyEngine(id: string) { if (!cfg.value) return; cfg.value.body ||= {engine_job_id:"",sites:[]}; cfg.value.body.engine_job_id=id; }
function addBodySite() {
  if (!cfg.value || !bodySite.value) return;
  if (!cfg.value.body?.engine_job_id) { error.value = "请先选择已核实的本机原生引擎"; return; }
  if (cfg.value.body.sites.length>=64 || cfg.value.body.sites.some(x=>x.site_id===bodySite.value)) { error.value="请求体网站重复或已达到 64 个上限"; return; }
  cfg.value.body.sites.push({site_id:bodySite.value,policy:bodyDefault()}); bodySite.value="";
}
function previewText(out: Preview) { return out.http_config + "\n# 每个受管站点的 server 规则\n" + out.server_config + (out.changes?.length ? "\n# 实际文件变更计划\n"+out.changes.map(x=>`# ${x.action}: ${x.path}`).join("\n") : "") + (out.body_rules || []).map(x=>`\n# ${siteName(x.site_id)} 请求体规则\n${x.configuration}`).join(""); }
async function refresh() {
  if (busy.value) return;
  if (dirty.value) { error.value = "存在未保存的草稿。请先保存，或使用“放弃草稿”再刷新。"; return; }
  busy.value = true; error.value = "";
  try {
    await loadConfig();
    const out = await props.api<Site[] | { sites: Site[] }>("/sites"); sites.value = (Array.isArray(out) ? out : out.sites).filter(s => !apache || s.settings?.web_server === "apache");
    await Promise.all([refreshReport(), refreshHistory(), refreshEngines(), refreshBodyReport(),refreshBodyArchives()]);
    await refreshBodyRotation();
    const running = engines.value.find(x=>["queued", "running"].includes(x.state))?.job_id || history.value.find(x=>x.kind==="waf_engine_build" && ["queued","running"].includes(x.state))?.id;
    if (running && !engineTimer) await pollEngine(running);
  } catch (e) { error.value = (e as Error).message; } finally { busy.value = false; }
}
async function validate() {
  if (!cfg.value) return;
  const out = await props.api<Preview>(endpoint("preview"), "POST", { settings: cfg.value });
  cfg.value = clone(out.settings); preview.value = previewText(out);
}
async function showPreview() { if (busy.value) return; busy.value = true; error.value = ""; try { await validate(); tab.value = "config"; } catch (e) { error.value = (e as Error).message; } finally { busy.value = false; } }
async function apply() {
  if (!cfg.value || busy.value) return;
  busy.value = true; error.value = ""; saved.value = "";
  try {
    await validate();
    const settings = clone(cfg.value) as unknown as Record<string, unknown>;
    const id = status.value?.installed ? (await props.api<{ job_id: string }>(endpoint("configure"), "POST", { settings }, newID())).job_id : await props.onInstall(engine, settings);
    let completed = false;
    for (let n = 0; n < 120; n++) {
      const job = await props.api<{ state: string; error: string }>(`/jobs/${id}`);
      if (job.state === "failed" || job.state === "cancelled") throw new Error(job.error || "配置任务失败；请核对操作记录与当前生效配置。");
      if (job.state === "succeeded") { completed = true; break; }
      await new Promise(resolve => setTimeout(resolve, 1000));
    }
    if (!completed) throw new Error("任务仍在执行，未宣称已生效。请在操作记录中核对后再刷新。");
    await loadConfig(); saved.value = `配置已备份、通过 ${engineName} 原生检查和重载核对；现显示实际生效配置。`;
    await Promise.all([refreshHistory(), refreshReport(), refreshBodyReport(),refreshBodyArchives()]);
    await refreshBodyRotation();
  } catch (e) { error.value = (e as Error).message; await refreshHistory(); }
  finally { busy.value = false; }
}
function discard() { if (applied.value) cfg.value = clone(applied.value); preview.value = ""; error.value = ""; saved.value = ""; }
function restoreDraft() { if (!defaults.value || !applied.value) return; cfg.value = clone(defaults.value); cfg.value.policy.revision = applied.value.policy.revision; if(!apache && applied.value.trusted_proxy) cfg.value.trusted_proxy = disabledTrustedProxy(); saved.value = "默认配置已载入草稿，会清空独立策略、名单与自定义规则并停用本应用的可信代理配置；尚未应用。可放弃草稿恢复生效配置。"; preview.value = ""; }
function addSite() {
  if (!cfg.value || !selectedSite.value) return;
  if (cfg.value.policy.sites.some(p => p.site_id === selectedSite.value)) { ElMessage.warning("该站点已存在策略"); return; }
  cfg.value.policy.sites.push({ site_id: selectedSite.value, mode: "inherit", rate_per_second: 0, burst: 0, groups: {} });
}
function siteGroup(p: SitePolicy, id: string, value: string) { p.groups ||= {}; if (value === "inherit") delete p.groups[id]; else p.groups[id] = value === "on"; }
function addList() {
  if (!cfg.value || !listValue.value.trim()) return;
  const entries = listValue.value.split(/\r?\n/).map(x => x.trim()).filter(Boolean);
  if (listCount.value + entries.length > 500) { error.value = "全部名单最多 500 条"; return; }
  cfg.value.policy.lists[listKind.value] ||= [];
  for (const value of entries) if (!cfg.value.policy.lists[listKind.value].some(x => x.value === value && (x.site_id || "") === listScope.value)) cfg.value.policy.lists[listKind.value].push({ id: newID(), value, site_id: listScope.value });
  listValue.value = "";
}
function addRule() { if (!cfg.value || !newRule.value.name.trim() || !newRule.value.value) { error.value = "请填写规则名称和匹配内容"; return; } if (cfg.value.policy.rules.length >= 64) { error.value = "自定义规则最多 64 条"; return; } cfg.value.policy.rules.push({ ...clone(newRule.value), id: newID() }); newRule.value.name = ""; newRule.value.value = ""; }
function addCC() { if (!cfg.value || !newCC.value.path.startsWith("/")) { error.value = "请填写以 / 开头的路径"; return; } if (cfg.value.policy.cc_rules.length >= 20) { error.value = "URL CC 规则最多 20 条"; return; } cfg.value.policy.cc_rules.push({ ...clone(newCC.value), id: newID() }); newCC.value.path = ""; }
async function importConfig() {
  if (!cfg.value || busy.value) return;
  busy.value = true; error.value = "";
  try {
    if (new TextEncoder().encode(jsonInput.value).length > 128 * 1024) throw new Error("配置超过 128 KiB");
    const imported = JSON.parse(jsonInput.value) as Config;
    if (!imported || typeof imported !== "object" || !imported.policy || typeof imported.policy !== "object") throw new Error("请输入包含 policy 的配置对象");
    imported.policy.revision = applied.value?.policy.revision || 0;
    const out = await props.api<Preview>(endpoint("preview"), "POST", { settings: imported });
    cfg.value = clone(out.settings); preview.value = previewText(out); saved.value = "导入配置已通过字段校验，仅载入草稿；点击保存才会修改防护。";
  } catch (e) { error.value = (e as Error).message; } finally { busy.value = false; }
}
function download(name: string, value: unknown) { const url = URL.createObjectURL(new Blob([JSON.stringify(value, null, 2)], { type: "application/json" })); const a = document.createElement("a"); a.href = url; a.download = name; a.click(); setTimeout(() => URL.revokeObjectURL(url), 500); }
async function exportLogs() { if (reportBusy.value) return; reportBusy.value = true; try { download("yunzhan-waf-events.json", await props.api<Report>(reportURL(true))); } catch (e) { error.value = (e as Error).message; } finally { reportBusy.value = false; } }
onMounted(refresh);
onUnmounted(() => { disposed=true; if(engineTimer) clearTimeout(engineTimer); if(bodyRotationTimer)clearTimeout(bodyRotationTimer); });
</script>

<template>
  <section class="waf-workspace" v-loading="busy">
    <div class="waf-heading"><div><h3>{{ engineName }} 请求防火墙</h3><p>请求防护 · 站点策略 · {{ apache ? "独立名单" : "CC 限速" }} · 审计与报表</p></div><div class="waf-actions"><el-tag :type="status?.healthy ? 'success' : 'warning'">{{ !status ? (busy ? '正在读取真实状态' : '状态尚未核实') : !status.installed ? '未安装' : status.healthy ? `已加载 · ${modeLabel(applied?.policy.mode || '')}` : '需要核对' }}</el-tag><el-tag type="info">v{{ status?.version || implementation || '—' }}</el-tag><el-button :disabled="busy || dirty" @click="refresh">刷新状态</el-button></div></div>
    <el-alert v-if="error" :title="error" type="error" :closable="false" />
    <el-alert v-if="saved" :title="saved" type="success" :closable="false" />
    <el-alert v-if="status?.installed && !status.healthy" :title="status.detail" type="warning" :closable="false" />
    <template v-if="cfg">
      <div class="waf-toolbar"><span>{{ dirty ? '存在未保存草稿' : '当前显示生效配置' }} · 修订 {{ applied?.policy.revision }} · {{ cfg.policy.sites.length }} 个独立站点策略 · {{ listCount }} 条名单</span><div><el-button :disabled="busy || !dirty" @click="discard">放弃草稿</el-button><el-button :disabled="busy" @click="showPreview">预览配置</el-button><el-button type="primary" :disabled="busy" @click="apply">{{ status?.installed ? '保存并应用' : '安装并验证' }}</el-button></div></div>
      <el-tabs v-model="tab" class="waf-tabs">
        <el-tab-pane label="防护概览" name="overview">
          <div class="waf-metrics"><article v-for="m in [{name:'防护事件',value:report?.total},{name:'已阻断',value:report?.blocked},{name:'仅观察',value:report?.observed},{name:'来源 IP',value:report?.sources}]" :key="m.name"><span>{{m.name}}</span><strong>{{m.value ?? '—'}}</strong><small>筛选时间内真实日志</small></article></div>
          <p class="waf-muted">{{ report ? `${formatPanelDateTime(report.from)} — ${formatPanelDateTime(report.to)}；已读取最近 ${report.scanned} 条日志` : '安装后读取真实日志，不使用演示数据' }}。概览与防护日志共用筛选条件。</p>
          <el-alert v-if="report?.partial" title="日志读取达到最近 4 MiB / 5000 条上限；统计不是全历史总数，更早记录仍在服务器日志中。" type="warning" :closable="false" />
          <div class="waf-two"><section><h4>命中规则排行</h4><el-table :data="report?.rules || []" max-height="220" empty-text="暂无命中"><el-table-column label="规则"><template #default="{row}">{{reasonName(row.name)}}</template></el-table-column><el-table-column prop="count" label="次数" width="80"/></el-table></section><section><h4>来源 IP 排行</h4><el-table :data="report?.ips || []" max-height="220" empty-text="暂无来源"><el-table-column prop="name" :label="apache ? '网络对端 IP' : '生效客户端 IP'"/><el-table-column prop="count" label="次数" width="80"/></el-table></section></div>
          <h4>每小时防护事件（UTC）</h4><div class="waf-trend" v-if="report?.hours.length"><div v-for="h in report.hours.slice(-48)" :key="h.name" :title="`${h.name} UTC · ${h.count} 次`"><span :style="{height: `${Math.max(3, h.count / Math.max(...report.hours.map(x=>x.count)) * 90)}px`}"></span><small>{{h.name.slice(-5)}}</small></div></div><el-empty v-else description="暂无防护事件；没有事件不代表已完成安全审计" :image-size="64"/>
          <el-alert :title="apache ? 'Apache 当前为独立请求元数据防护，不包含原生请求体引擎。观察模式不阻断 WAF 命中，但服务器原生拒绝仍有效。' : '元数据防护与原生请求体防护独立配置。请求体防护使用固定版本 ModSecurity / OWASP CRS，须先构建兼容引擎，再逐网站明确启用；概览和防护日志当前统计元数据事件，不将 CRS 规则命中数伪装成 HTTP 阻断次数。'" type="info" :closable="false" />
        </el-tab-pane>
        <el-tab-pane label="全局防护" name="global">
          <el-form label-position="top" class="waf-two"><el-form-item label="运行模式"><el-select v-model="cfg.policy.mode"><el-option label="阻断：规则命中立即拒绝" value="block"/><el-option label="观察：只记录，不阻断或限速" value="observe"/><el-option label="停用：所有站点不阻断或限速" value="off"/></el-select></el-form-item><el-form-item label="特征策略"><el-select v-model="cfg.profile"><el-option label="平衡：常见攻击特征" value="balanced"/><el-option label="严格：扩展特征，可能增加误报" value="strict"/></el-select></el-form-item></el-form>
          <el-alert v-if="cfg.policy.mode !== 'block'" :title="cfg.policy.mode === 'off' ? '全局停用优先于所有站点策略；保存后停止防护。' : '观察模式会放行检测到的攻击请求；适用于上线前误报评估。'" type="warning" :closable="false"/>
          <div class="waf-group-grid"><article v-for="g in groups" :key="g.id"><div><strong>{{g.name}}</strong><small>{{g.hint}}</small></div><el-switch v-model="cfg.policy.groups[g.id]" :aria-label="g.name"/></article></div>
          <h4>规则优先级与安全边界</h4><p>IP 白名单 → IP 黑名单 → UA 白名单 → UA 黑名单 → URL 白名单 → URL 黑名单 → 分类规则与自定义规则。{{ apache ? "白名单跳过后续元数据检查" : "白名单同时跳过 CC 限速" }}，务必谨慎添加。</p><p>URL 匹配服务器规范化路径，查询参数按原始参数特征检测；不承诺覆盖任意编码或未知攻击。{{ apache ? "Apache 原生请求校验、静态文件访问限制仍然有效，观察模式不能绕过它们；IP 为实际网络对端，经过 Nginx 代理时为回环地址，不盲目信任 X-Forwarded-For。" : "健康探针自动豁免，不会阻断面板核验。" }}</p>
        </el-tab-pane>
        <el-tab-pane label="站点策略" name="sites">
          <div class="waf-filter"><el-input v-model="siteSearch" placeholder="搜索站点名称 / 域名" aria-label="搜索防护站点"/><el-select v-model="selectedSite" filterable placeholder="选择独立配置站点"><el-option v-for="s in scopedSites" :key="s.id" :value="s.id" :label="s.domain"/></el-select><el-button @click="addSite">添加站点策略</el-button></div>
          <p>未列出的受管 {{ engineName }} 站点继承全局策略。{{ apache ? "本页只管理 Apache 防护，不修改 Nginx 入口策略。" : "网站设置里的 WAF 关闭状态仍然有效，本页不会自动打开它。" }}</p>
          <el-table :data="cfg.policy.sites" empty-text="所有站点继承全局策略" max-height="450"><el-table-column type="expand"><template #default="{row}"><div class="waf-site-groups"><el-form-item v-for="g in groups" :key="g.id" :label="g.name"><el-select :model-value="row.groups?.[g.id] === undefined ? 'inherit' : row.groups[g.id] ? 'on' : 'off'" @change="(value: string)=>siteGroup(row,g.id,value)"><el-option label="继承" value="inherit"/><el-option label="开启" value="on"/><el-option label="关闭" value="off"/></el-select></el-form-item></div></template></el-table-column><el-table-column label="站点" min-width="210"><template #default="{row}"><strong>{{siteName(row.site_id)}}</strong><small class="waf-site-warning" v-if="!apache && sites.find(s=>s.id===row.site_id)?.settings?.waf_enabled === false">网站设置已关闭 WAF，本策略不会生效</small></template></el-table-column><el-table-column label="模式" width="125"><template #default="{row}"><el-select v-model="row.mode"><el-option v-for="m in ['inherit','block','observe','off']" :key="m" :label="modeLabel(m)" :value="m"/></el-select></template></el-table-column><el-table-column v-if="!apache" label="CC 防护" width="125"><template #default="{row}"><el-select :model-value="row.cc_enabled === undefined ? 'inherit' : row.cc_enabled ? 'on' : 'off'" @change="(v: string)=>{if(v==='inherit')delete row.cc_enabled;else row.cc_enabled=v==='on'}"><el-option label="继承" value="inherit"/><el-option label="开启" value="on"/><el-option label="关闭" value="off"/></el-select></template></el-table-column><el-table-column v-if="!apache" label="速率 / 秒" width="150"><template #default="{row}"><el-input-number v-model="row.rate_per_second" :min="0" :max="200" controls-position="right"/></template></el-table-column><el-table-column v-if="!apache" label="突发容量" width="150"><template #default="{row}"><el-input-number v-model="row.burst" :min="0" :max="1000" controls-position="right"/></template></el-table-column><el-table-column width="75"><template #default="{row}"><el-button text type="danger" @click="cfg.policy.sites=cfg.policy.sites.filter(p=>p!==row)">移除</el-button></template></el-table-column></el-table><p class="waf-muted">展开每行可覆盖规则分类；{{ apache ? "Apache 不提供独立 CC 速率。" : "速率 / 突发值为 0 表示继承，独立速率须为 5–200。" }}移除策略只恢复继承，不删除网站。</p>
        </el-tab-pane>
        <el-tab-pane v-if="!apache" label="CC 防护" name="cc">
          <el-form label-position="top" class="waf-three"><el-form-item label="启用 CC 限速"><el-switch v-model="cfg.policy.cc_enabled" aria-label="启用 CC 限速"/></el-form-item><el-form-item label="每站点 / 每 IP 速率（次 / 秒）"><el-input-number v-model="cfg.rate_per_second" :min="5" :max="200"/></el-form-item><el-form-item label="突发容量（阻断模式超额返回 429）"><el-input-number v-model="cfg.policy.burst" :min="1" :max="1000"/></el-form-item></el-form>
          <p>使用 Nginx 原生漏桶限速，站点之间不共享同一 IP 的额度；URL 规则与站点限速同时生效。{{ ccObservationSupported ? "阻断模式超额返回 429；观察模式使用原生 dry-run，超额继续放行并记录为 CC 观察事件。停用模式与白名单不消耗额度。" : "此已安装版本在观察 / 停用模式与白名单下不计 CC 额度；升级到 2.3.0 后，观察模式才会记录真实超限事件。" }}</p>
          <el-alert v-if="ccObservationSupported" title="每个网站独立应用观察模式。网站有外部 include 或其它独立限速配置时，拒绝将其切换为观察，不会静默解除管理员原有限速。CC 防护关闭的网站也不会记录模拟超限。" type="info" :closable="false"/>
          <h4>URL 独立限速（最多 20 条）</h4><div class="waf-editor"><el-select v-model="newCC.site_id" filterable aria-label="URL 限速范围"><el-option value="" label="全部受管站点"/><el-option v-for="s in sites" :key="s.id" :value="s.id" :label="s.domain"/></el-select><el-input v-model="newCC.path" placeholder="/api/login" aria-label="URL 限速路径"/><el-checkbox v-model="newCC.prefix">路径前缀</el-checkbox><el-input-number v-model="newCC.rate_per_second" :min="1" :max="200" aria-label="URL 速率"/><el-input-number v-model="newCC.burst" :min="1" :max="1000" aria-label="URL 突发容量"/><el-button @click="addCC">添加规则</el-button></div>
          <el-table :data="cfg.policy.cc_rules" empty-text="暂无 URL 独立限速"><el-table-column label="范围"><template #default="{row}">{{siteName(row.site_id)}}</template></el-table-column><el-table-column prop="path" label="路径"/><el-table-column label="匹配"><template #default="{row}">{{row.prefix?'前缀':'精确'}}</template></el-table-column><el-table-column prop="rate_per_second" label="次 / 秒" width="85"/><el-table-column prop="burst" label="突发" width="70"/><el-table-column label="启用" width="80"><template #default="{row}"><el-switch v-model="row.enabled"/></template></el-table-column><el-table-column width="75"><template #default="{row}"><el-button text type="danger" @click="cfg.policy.cc_rules=cfg.policy.cc_rules.filter(r=>r!==row)">删除</el-button></template></el-table-column></el-table>
          <el-alert title="CC 和 IP 名单使用 Nginx 生效客户端地址。使用 CDN / 反向代理时，请在“可信反代来源”明确配置受信任的网络对端；不要直接信任任意浏览器提交的转发头。" type="warning" :closable="false"/>
        </el-tab-pane>
        <el-tab-pane v-if="!apache" label="可信反代来源" name="trusted-proxy">
          <el-alert v-if="status?.installed && status.version !== implementation" title="当前安装的 WAF 版本尚不支持此配置，请先在应用商店执行签名升级。面板程序更新不代表应用已升级。" type="warning" :closable="false"/>
          <el-alert title="默认不启用。本策略只写入参与 WAF 的受管 server 块，不改变全局 Nginx、退出 WAF 的网站或负载均衡入口。保存前核实当前程序包含 real_ip 模块，缺失时拒绝应用，不自动重编译。" type="info" :closable="false"/>
          <el-form label-position="top">
            <el-form-item label="启用本应用的可信代理地址识别"><el-switch :model-value="cfg.trusted_proxy?.enabled || false" aria-label="启用可信代理识别" @change="toggleTrustedProxy"/></el-form-item>
            <template v-if="cfg.trusted_proxy">
              <el-form-item label="可信代理网络对端 CIDR（每行一个，最多 32 个）"><el-input v-model="trustedProxyCIDRs" type="textarea" :rows="5" :disabled="!cfg.trusted_proxy.enabled" aria-label="可信代理 CIDR" placeholder="例如 192.0.2.10/32 或 2001:db8:100::/48；不要填写网站域名" @input="editTrustedProxyCIDRs"/></el-form-item>
              <div class="waf-two">
                <el-form-item label="由可信代理控制的客户端地址请求头"><el-select :model-value="cfg.trusted_proxy.header" :disabled="!cfg.trusted_proxy.enabled" aria-label="可信代理地址请求头" @change="changeTrustedProxyHeader"><el-option value="X-Forwarded-For" label="X-Forwarded-For（地址链）"/><el-option value="X-Real-IP" label="X-Real-IP（单个地址）"/></el-select></el-form-item>
                <el-form-item label="递归寻找地址链中最后一个非可信地址"><el-switch v-model="cfg.trusted_proxy.recursive" :disabled="!cfg.trusted_proxy.enabled || cfg.trusted_proxy.header !== 'X-Forwarded-For'" aria-label="递归可信代理地址链" @change="changeTrustedProxyRecursive"/></el-form-item>
              </div>
              <el-checkbox class="waf-proxy-ack" v-model="cfg.trusted_proxy.acknowledge_header_control" :disabled="!cfg.trusted_proxy.enabled">我已确认这些代理会删除、重写或安全追加该请求头，且所列 CIDR 不包含不受信任的客户端。</el-checkbox>
            </template>
          </el-form>
          <p>仅接受规范的 IPv4 / IPv6 网络 CIDR，拒绝重复、重叠、映射地址和过宽网络；IPv4 至少 /8，IPv6 至少 /32。未列入的网络对端不能凭转发头修改身份。开启递归后采用地址链中最后一个非可信地址；关闭时采用末尾地址。</p>
          <el-alert title="将回环地址列为可信来源，意味着本机能连接该端口的程序可以提供客户端身份。CDN 网段和代理部署会变化，请按你实际控制的网络维护，不能把公开网段列表当成授权证明。错误的信任配置可能绕过 IP 名单和 CC 限速。" type="warning" :closable="false"/>
          <p class="waf-muted">停用并保存会删除本应用生成的 real_ip 指令，保留草稿中的 CIDR 便于核对；不会删除管理员在其它配置中手写的 real_ip 设置，外部继承设置仍可能影响客户端地址。日志分别展示生效客户端 IP 与原始网络对端；旧日志没有原始对端时明确显示“未记录”。</p>
        </el-tab-pane>
        <el-tab-pane v-if="!apache" label="请求体防护" name="body">
          <el-alert title="原生引擎构建不会自动修改网站或加载模块。仅使用固定摘要的开源程序及规则；固定单路编译，最多 1 CPU / 640 MiB 内存，576 MiB 回收水位，最长 4 小时，可能排队等待其他源码构建。不会自动添加交换分区或增大预算；保留失败证据，重试需新建任务。" type="info" :closable="false"/>
          <div class="waf-actions"><h4>本机兼容引擎</h4><div><el-button :loading="engineBusy" :disabled="engineJob && ['queued','running'].includes(engineJob.state)" @click="buildEngine">构建兼容引擎</el-button><el-button v-if="engineJob && ['queued','running'].includes(engineJob.state)" :loading="engineBusy" type="warning" @click="stopEngine">停止构建并保留证据</el-button><el-button @click="refreshEngines().catch(e=>error=e.message)">核对引擎状态</el-button></div></div>
          <el-alert v-if="engineJob" :title="`${buildState(engineJob.state)} · ${engineJob.job_id}${engineJob.error ? ' · '+engineJob.error : ''}`" :type="engineJob.state==='ready' ? 'success' : 'info'" :closable="false"/>
          <ol v-if="engineJob?.steps.length"><li v-for="step in engineJob.steps" :key="step.time+step.message">{{formatPanelDateTime(step.time)}} · {{step.message}}</li></ol>
          <el-table :data="engines" max-height="250" empty-text="未构建原生引擎；元数据防护不受影响"><el-table-column prop="job_id" label="构建任务" min-width="220" show-overflow-tooltip/><el-table-column label="程序"><template #default="{row}">ModSecurity {{row.engine_version || '—'}} / CRS {{row.crs_version || '—'}}<small class="waf-muted"> Nginx {{row.nginx_version || '待核对'}} · {{row.architecture}}</small></template></el-table-column><el-table-column label="状态" min-width="170"><template #default="{row}">{{buildState(row.state)}}<small class="waf-site-warning" v-if="row.error">{{row.error}}</small></template></el-table-column></el-table>
          <el-form label-position="top"><el-form-item label="选择已核对的兼容引擎"><el-select :model-value="cfg.body?.engine_job_id || ''" @change="selectBodyEngine" placeholder="不会默认选择或自动激活"><el-option v-for="item in verifiedEngines" :key="item.job_id" :label="`Nginx ${item.nginx_version} · ${item.architecture} · ${item.job_id.slice(0,12)}`" :value="item.job_id"/></el-select></el-form-item></el-form>
          <el-alert v-if="cfg.body?.engine_job_id && !verifiedEngines.some(x=>x.job_id===cfg?.body?.engine_job_id)" title="已保存引擎当前未通过核对，不能启用新策略；请检查完整性或构建新引擎。" type="warning" :closable="false"/>
          <div class="waf-filter"><el-select v-model="bodySite" filterable placeholder="选择明确启用的网站"><el-option v-for="s in sites" :key="s.id" :value="s.id" :label="s.domain"/></el-select><el-button @click="addBodySite">添加请求体策略</el-button></div>
          <p>默认新增策略为观察模式。全局/站点停用与观察模式优先；网站停用或网站设置关闭 WAF 时，策略暂停。元数据白名单不会跳过请求体检查。删除本页策略并保存将移除对应网站的请求体配置，不删除网站。</p>
          <p class="waf-muted">Nginx 重载提交前核实旧工作进程已关闭监听套接字，再验证新规则指纹。重载前已接收的请求或长连接继续使用原配置，不强制断开；停用或切换观察模式不会追溯撤销已经开始的请求检查。</p>
          <el-table :data="cfg.body?.sites || []" empty-text="没有网站启用请求体防护" max-height="470"><el-table-column type="expand"><template #default="{row}"><el-form label-position="top" class="waf-three"><el-form-item label="CRS 检测级别（1–4，越高误报可能越多）"><el-input-number v-model="row.policy.paranoia_level" :min="1" :max="4"/></el-form-item><el-form-item label="入站异常分数阈值"><el-input-number v-model="row.policy.inbound_threshold" :min="5" :max="100"/></el-form-item><el-form-item label="请求体上限（KiB）"><el-input-number v-model="row.policy.body_limit_kib" :min="64" :max="8192"/></el-form-item><el-form-item label="非文件部分上限（KiB）"><el-input-number v-model="row.policy.non_file_limit_kib" :min="64" :max="Math.min(2048,row.policy.body_limit_kib)"/></el-form-item><el-form-item label="JSON 最大深度"><el-input-number v-model="row.policy.json_depth" :min="4" :max="128"/></el-form-item><el-form-item label="请求参数上限"><el-input-number v-model="row.policy.argument_limit" :min="16" :max="1000"/></el-form-item></el-form></template></el-table-column><el-table-column label="网站" min-width="220"><template #default="{row}">{{siteName(row.site_id)}}<small v-if="sites.find(s=>s.id===row.site_id)?.status==='stopped' || sites.find(s=>s.id===row.site_id)?.settings?.waf_enabled===false" class="waf-site-warning">网站已停用或退出 WAF，当前策略暂停</small></template></el-table-column><el-table-column label="模式" width="140"><template #default="{row}"><el-select v-model="row.policy.mode"><el-option v-for="m in ['observe','block','off']" :key="m" :value="m" :label="modeLabel(m)"/></el-select></template></el-table-column><el-table-column label="请求体预算" width="140"><template #default="{row}">{{row.policy.body_limit_kib}} KiB</template></el-table-column><el-table-column width="85"><template #default="{row}"><el-button text type="danger" @click="cfg.body!.sites=cfg.body!.sites.filter(p=>p!==row)">移除</el-button></template></el-table-column></el-table>
          <p class="waf-muted">固定请求体解析覆盖表单、JSON、XML 与 multipart 的规则检测；禁用 XML 外部实体和请求体审计日志，不保存 Cookie、POST 内容或响应体。不是防病毒扫描，也不保证覆盖未知攻击。普通 Nginx 错误日志仍可能包含请求 URI，应单独管理其隐私与保留策略。</p>
          <h4>请求体规则命中日志</h4><el-alert title="每行是一条规则命中，不是一次 HTTP 请求或一次实际阻断；一个请求可能命中多条规则，中断标记也不是 HTTP 结果。为保护隐私，此日志不保存 IP、URI、请求标识、Cookie 或请求体。" type="info" :closable="false"/>
          <div class="waf-filter"><el-select v-model="bodyFilter.site_id" filterable aria-label="请求体日志网站"><el-option label="全部网站标识" value=""/><el-option v-for="s in sites" :key="s.id" :value="s.id" :label="s.domain"/></el-select><el-input v-model="bodyFilter.rule" placeholder="数字规则号，如 941100" aria-label="请求体规则号"/><el-select v-model="bodyFilter.phase" aria-label="规则处理阶段"><el-option label="全部阶段" value=""/><el-option v-for="n in 5" :key="n" :label="`阶段 ${n}`" :value="String(n)"/></el-select></div>
          <div class="waf-filter"><el-date-picker v-model="bodyRange" type="datetimerange" start-placeholder="开始时间" end-placeholder="结束时间"/><el-button :loading="bodyReportBusy" @click="refreshBodyReport(true)">查询规则日志</el-button><el-button :disabled="bodyReportBusy || !status?.installed" @click="exportBodyReport">导出规则命中</el-button></div>
          <p v-if="bodyReport?.available">筛选范围 {{bodyReport.rule_matches}} 条规则命中 · 最近读取 {{bodyReport.scanned}} 条 · 拒绝解析 {{bodyReport.rejected_lines}} 行格式异常内容</p><el-alert v-else title="请求体元数据日志尚未生成或未读取，不能据此判断攻击为零或防护已启用。" type="info" :closable="false"/>
          <el-alert v-if="bodyReport?.partial" title="仅查询最近 4 MiB / 5000 条；导出同样有上限，不是完整历史备份。" type="warning" :closable="false"/>
          <el-alert v-if="bodyReport?.metadata_best_effort" title="规则元数据为尽力记录；并发争用、容量或磁盘故障可能漏记，不能作为完整请求取证或准确攻击总数。" type="info" :closable="false"/>
          <el-alert v-if="bodyReport?.legacy_log" title="正在读取保留的旧日志；它不具备本版写入硬上限。安全应用新引擎后使用独立受保护日志，不会删除旧文件。" type="warning" :closable="false"/>
          <el-alert v-if="bodyReport?.capacity_exhausted" title="当前元数据日志已达到 32 MiB 写入上限，后续可能漏记；防护继续执行。请备份并轮转后核对新记录。" type="error" :closable="false"/>
          <WafBodyRetention :api="props.api" :settings="cfg" :supported="!!bodyRetentionSupported" :active="tab==='body'" :parent-busy="busy || bodyLogBusy" @safety-state="bodyRetentionSafety=$event" @inventory-changed="refreshBodyArchives().catch(e=>error=(e as Error).message)"/>
          <h4>自动轮转请求体数值日志</h4>
          <el-alert v-if="!bodyRotationSupported" title="先从应用商店升级 Nginx WAF 至 2.4.0 才能配置自动轮转。升级不会自动启用，原有日志与备份保留。" type="info" :closable="false"/>
          <el-form label-position="top" class="waf-three">
            <el-form-item label="启用自动轮转（默认关闭）"><el-switch :model-value="cfg.body_log_rotation?.enabled || false" :disabled="!bodyRotationSupported || !cfg.body?.engine_job_id" aria-label="启用请求体数值日志自动轮转" @change="toggleBodyRotation"/></el-form-item>
            <el-form-item v-if="cfg.body_log_rotation" label="文件大小触发（MiB）"><el-input-number v-model="cfg.body_log_rotation.rotate_mib" :min="1" :max="28" :disabled="!bodyRotationSupported" aria-label="自动轮转大小阈值"/></el-form-item>
            <el-form-item v-if="cfg.body_log_rotation" label="非空日志时间触发（分钟）"><el-input-number v-model="cfg.body_log_rotation.max_age_minutes" :min="10" :max="1440" :disabled="!bodyRotationSupported" aria-label="自动轮转时间阈值"/></el-form-item>
          </el-form>
          <p class="waf-muted">须先选择已核验的请求体引擎。保存草稿后才生效，每分钟检查一次；大小或时间任一达到阈值且日志非空时轮转。保留当前写入 inode，不重载 Nginx，只处理受保护的数字规则日志；普通防护、访问、错误日志不在此范围。最多 8 份快照，满额暂停；轮转自身不删除历史。仅独立的保留期清理经明确启用后，才会删除超过保留期且核对完成的快照。</p>
          <div v-if="bodyRotationSupported" class="waf-actions"><span>服务器自动轮转：{{bodyRotation?.enabled ? '已启用' : '未启用'}} · {{bodyRotationState(bodyRotation?.record?.state)}}</span><el-button :disabled="bodyLogBusy" @click="refreshBodyRotation">刷新自动轮转状态</el-button></div>
          <el-alert v-if="bodyRotationError" :title="bodyRotationError+'；状态未核验，不能当成成功或未发生。'" type="error" :closable="false"/>
          <el-alert v-if="bodyRotation?.stale" title="调度记录未及时更新或策略修订已变化，请检查执行服务；这里不宣称自动轮转正在正常运行。" type="warning" :closable="false"/>
          <el-descriptions v-if="bodyRotation?.record" :column="3" border><el-descriptions-item label="最近检查">{{formatPanelDateTime(bodyRotation.record.checked_at)}}</el-descriptions-item><el-descriptions-item label="时间窗口起点">{{formatPanelDateTime(bodyRotation.record.window_started_at)}}</el-descriptions-item><el-descriptions-item label="最近核验完成">{{bodyRotation.record.last_rotation_at ? formatPanelDateTime(bodyRotation.record.last_rotation_at) : '尚无已核验轮转'}}</el-descriptions-item></el-descriptions>
          <el-alert v-if="bodyRotation?.message" :title="bodyRotation.message" :type="['unknown','rotating','blocked'].includes(bodyRotation.record?.state || '') ? 'warning' : 'info'" :closable="false"/>
          <el-popconfirm v-if="['unknown','rotating'].includes(bodyRotation?.record?.state || '')" title="按当前摘要记录未知结果？不会再次截断日志，不会删除快照，也不会标成成功。" confirm-button-text="保留未知结果" @confirm="retainAutomaticRotation"><template #reference><el-button :disabled="bodyLogBusy || bodyRecovery.length>0 || bodyIndexStages.length>0 || !!bodyInventoryWarning || !bodyRotation?.sha256" :loading="bodyLogBusy">核对并保留自动轮转未知结果</el-button></template></el-popconfirm>
          <el-table v-if="bodyRotation?.record?.history.length" :data="bodyRotation.record.history" max-height="180"><el-table-column label="记录时间" min-width="170"><template #default="{row}">{{formatPanelDateTime(row.at)}}</template></el-table-column><el-table-column label="结果" min-width="190"><template #default="{row}">{{row.outcome==='completed'?'备份与轮转已核对':'未知结果保留，未宣称成功'}}</template></el-table-column><el-table-column prop="id" label="操作标识" min-width="220"/></el-table>
          <p v-if="bodyRotation?.record" class="waf-muted">最多保留 16 条调度结果摘要；未知结果不会自动清除。快照库存和完整摘要在下方单独核验，不以调度摘要代替完整取证。</p>
          <div class="waf-actions"><span v-if="bodyReport?.available">当前文件 {{bodyBytes(bodyReport.log_bytes)}}<span v-if="bodyReport.max_bytes"> / {{bodyBytes(bodyReport.max_bytes)}}</span> · {{bodyInventoryView.label}}</span><el-button :loading="bodyLogBusy" :disabled="!bodyInventoryView.verified || bodyRetentionPreventRotation || !bodyReport?.available || bodyReport.legacy_log || !bodyReport.log_bytes || bodyRecovery.length>0 || bodyIndexStages.length>0 || bodyArchives.length>=8 || ['unknown','rotating'].includes(bodyRotation?.record?.state || '')" @click="rotateBodyLog">备份并轮转元数据日志</el-button></div>
          <el-alert v-if="bodyIndexStages.length" title="发现未提交索引残件，请先保留其原始文件。残件不会当成有效备份或成功轮转，也不会自动应用或丢弃。" type="warning" :closable="false"/>
          <el-table v-if="bodyIndexStages.length" :data="bodyIndexStages" max-height="180"><el-table-column prop="id" label="索引残件标识" min-width="220"/><el-table-column prop="bytes" label="实际字节" width="100"/><el-table-column prop="sha256" label="摘要" min-width="220"/><el-table-column width="190"><template #default="{row}"><el-popconfirm title="按摘要保留此残件的原始文件？不接管为有效索引，不修改当前日志。" confirm-button-text="保留原始证据" @confirm="retainBodyIndexStage(row)"><template #reference><el-button text :disabled="bodyLogBusy">保留索引写入残件</el-button></template></el-popconfirm></template></el-table-column></el-table>
          <el-alert v-if="bodyInventoryWarning" :title="bodyInventoryWarning+'；完整备份列表暂不展示，请先核对下方恢复记录。'" type="warning" :closable="false"/>
          <el-alert v-if="bodyRecovery.length" title="发现未完成日志事务。快照可能不完整，轮转结果不能确认；恢复只保留证据，不会再次截断当前日志。缺失快照不会显示成零攻击。" type="warning" :closable="false"/>
          <el-table v-if="bodyRecovery.length" :data="bodyRecovery" max-height="230"><el-table-column label="待恢复快照" min-width="220"><template #default="{row}">{{row.archive.id}}<small class="waf-muted">{{bodyArchiveState(row.archive.state)}}</small></template></el-table-column><el-table-column label="实际快照" min-width="150"><template #default="{row}">{{row.snapshot_missing?'文件缺失':bodyBytes(row.snapshot_bytes)}}</template></el-table-column><el-table-column min-width="360"><template #default="{row}"><el-button text :disabled="bodyLogBusy" @click="exportBodyRecovery(row)">导出恢复记录</el-button><el-button v-if="!row.snapshot_missing && row.archive.state!=='copying' && row.snapshot_bytes===row.archive.bytes && row.snapshot_sha256===row.archive.sha256" text :disabled="bodyLogBusy" @click="exportBodyArchive(row.archive.id)">导出实际元数据</el-button><el-popconfirm v-if="row.archive.state!=='removing'" title="保留可能不完整的快照并记录未知轮转结果？不会修改当前日志。" confirm-button-text="保留并记录" @confirm="retainBodySnapshot(row)"><template #reference><el-button text :disabled="bodyLogBusy||bodyIndexStages.length>0">保留失败快照</el-button></template></el-popconfirm><el-popconfirm v-else title="按原摘要继续永久删除此快照？当前日志和其它备份不会删除。" confirm-button-text="重试永久删除" @confirm="removeBodyArchive(row.archive)"><template #reference><el-button text type="danger" :disabled="bodyLogBusy||bodyIndexStages.length>0||!exportedBodyArchives.includes(row.archive.id)">重试明确删除</el-button></template></el-popconfirm></template></el-table-column></el-table>
          <p class="waf-muted">轮转不重载 Nginx，不修改普通访问/错误日志。每份备份是截断前的独立快照；失败时可能重叠，不合并成流量总数。最多保留 8 份，轮转自身不会自动丢弃历史；另行启用保留期清理后，符合策略的已完成快照会被永久删除。导出仅含最近 4 MiB / 5000 条数字元数据。</p>
          <el-table v-if="bodyInventoryView.verified" :data="bodyArchives" :empty-text="bodyInventoryView.empty" max-height="200"><el-table-column label="备份时间" min-width="170"><template #default="{row}">{{formatPanelDateTime(row.captured_at)}}</template></el-table-column><el-table-column label="实际快照 / 原意图" min-width="185"><template #default="{row}">{{row.state==='retained-missing'?`缺失；原意图 ${bodyBytes(row.bytes)}`:bodyBytes(row.bytes)}}</template></el-table-column><el-table-column label="状态" min-width="160"><template #default="{row}">{{bodyArchiveState(row.state)}}</template></el-table-column><el-table-column width="235"><template #default="{row}"><el-button :disabled="bodyLogBusy" text @click="exportBodyArchive(row.id)">{{row.state==='retained-missing'?'导出原意图':'导出元数据'}}</el-button><el-popconfirm title="导出仅含最近 4 MiB / 5000 条。永久删除整份服务器快照且不可恢复？" confirm-button-text="永久删除" cancel-button-text="保留" @confirm="removeBodyArchive(row)"><template #reference><el-button :disabled="bodyLogBusy || bodyIndexStages.length>0 || !exportedBodyArchives.includes(row.id)" text type="danger">删除快照</el-button></template></el-popconfirm></template></el-table-column></el-table>
          <p v-else class="waf-muted" role="status">{{bodyInventoryView.empty}}</p>
          <el-table :data="bodyReport?.events || []" v-loading="bodyReportBusy" max-height="350" empty-text="没有符合筛选条件的规则元数据"><el-table-column label="时间" width="170"><template #default="{row}">{{formatPanelDateTime(row.time)}}</template></el-table-column><el-table-column label="网站标识" min-width="210"><template #default="{row}">{{row.site_id==='unmanaged'?'非受管标识':siteName(row.site_id)}}</template></el-table-column><el-table-column prop="rule_id" label="规则号" width="110"/><el-table-column prop="phase" label="阶段" width="70"/><el-table-column prop="severity" label="级别值" width="80"/><el-table-column label="规则中断标记" width="130"><template #default="{row}">{{row.disruptive_mark?'1':'0'}}</template></el-table-column></el-table><el-pagination v-model:current-page="bodyPage" :page-size="50" :total="bodyReport?.rule_matches || 0" layout="total, prev, pager, next" @current-change="refreshBodyReport()"/>
        </el-tab-pane>
        <el-tab-pane label="名单管理" name="lists">
          <div class="waf-filter"><el-select v-model="listKind" aria-label="名单类型"><el-option v-for="k in listKinds" :key="k.id" :value="k.id" :label="k.name"/></el-select><el-select v-model="listScope" filterable aria-label="名单范围"><el-option label="全部受管站点" value=""/><el-option v-for="s in sites" :key="s.id" :value="s.id" :label="s.domain"/></el-select></div>
          <p>{{listKind.startsWith('ip_')?'支持 IPv4、IPv6 和 CIDR；保存时规范化网段，不接受域名。':listKind.startsWith('url_')?'URL 为 / 开头的路径前缀，不包含 ? 查询参数或 #。':'UA 为不区分大小写的字面包含匹配，不支持任意正则。'}} 可按行批量添加，所有名单合计最多 500 条。</p><el-input v-model="listValue" type="textarea" :rows="3" :maxlength="16000" aria-label="名单内容" placeholder="每行一个条目"/><el-button class="waf-add" @click="addList">添加至草稿</el-button>
          <el-table :data="cfg.policy.lists[listKind] || []" max-height="310" empty-text="此名单为空"><el-table-column prop="value" label="内容" show-overflow-tooltip/><el-table-column label="适用范围"><template #default="{row}">{{siteName(row.site_id)}}</template></el-table-column><el-table-column width="80"><template #default="{row}"><el-button text type="danger" @click="cfg.policy.lists[listKind]=cfg.policy.lists[listKind].filter(x=>x!==row)">删除</el-button></template></el-table-column></el-table>
        </el-tab-pane>
        <el-tab-pane label="自定义规则" name="rules">
          <p>使用固定字段、字面匹配构建规则，不执行任意正则、脚本或 Nginx 指令。名称只用于管理；规则命中写入稳定标识。最多 64 条。</p>
          <el-form label-position="top" class="waf-three"><el-form-item label="规则名称"><el-input v-model="newRule.name" :maxlength="80"/></el-form-item><el-form-item label="适用范围"><el-select v-model="newRule.site_id" filterable><el-option value="" label="全部受管站点"/><el-option v-for="s in sites" :key="s.id" :value="s.id" :label="s.domain"/></el-select></el-form-item><el-form-item label="检测字段"><el-select v-model="newRule.field"><el-option v-for="f in fields" :key="f.id" :value="f.id" :label="f.name"/></el-select></el-form-item><el-form-item label="匹配方式（不区分大小写）"><el-select v-model="newRule.operator"><el-option value="exact" label="精确匹配"/><el-option value="prefix" label="前缀匹配"/><el-option value="contains" label="包含"/></el-select></el-form-item><el-form-item label="匹配内容"><el-input v-model="newRule.value" :maxlength="256"/></el-form-item><el-form-item label="命中动作"><el-select v-model="newRule.action"><el-option value="block" label="阻断（403）"/><el-option value="observe" label="仅记录"/></el-select></el-form-item></el-form><el-button @click="addRule">添加规则</el-button>
          <el-table :data="cfg.policy.rules" max-height="320" empty-text="暂无自定义规则"><el-table-column prop="name" label="名称"/><el-table-column label="范围"><template #default="{row}">{{siteName(row.site_id)}}</template></el-table-column><el-table-column label="匹配" min-width="190" show-overflow-tooltip><template #default="{row}">{{fields.find(f=>f.id===row.field)?.name}} · {{row.operator}} · {{row.value}}</template></el-table-column><el-table-column label="动作" width="85"><template #default="{row}">{{row.action==='observe'?'仅记录':'阻断'}}</template></el-table-column><el-table-column label="启用" width="80"><template #default="{row}"><el-switch v-model="row.enabled"/></template></el-table-column><el-table-column width="75"><template #default="{row}"><el-button text type="danger" @click="cfg.policy.rules=cfg.policy.rules.filter(r=>r!==row)">删除</el-button></template></el-table-column></el-table>
        </el-tab-pane>
        <el-tab-pane label="防护日志" name="logs">
          <div class="waf-filter"><el-select v-model="filter.site_id" filterable aria-label="日志站点"><el-option value="" label="全部站点"/><el-option v-for="s in sites" :key="s.id" :value="s.id" :label="s.domain"/></el-select><el-input v-model="filter.ip" placeholder="精确来源 IP" aria-label="来源 IP"/><el-select v-model="filter.action" aria-label="日志动作"><el-option label="全部动作" value=""/><el-option label="已阻断" value="block"/><el-option label="仅观察" value="observe"/></el-select><el-select v-model="filter.rule" filterable aria-label="命中规则"><el-option label="全部规则" value=""/><el-option v-for="r in [...groups.map(g=>({id:g.id,name:g.name})),...cfg.policy.rules.map(r=>({id:`custom-${r.id}`,name:r.name})),...(!apache ? [{id:'cc',name:'CC 限速'}] : []),{id:'ip-deny',name:'IP 黑名单'},{id:'url-deny',name:'URL 黑名单'},{id:'ua-deny',name:'UA 黑名单'}]" :key="r.id" :label="r.name" :value="r.id"/></el-select></div>
          <div class="waf-filter"><el-date-picker v-model="range" type="datetimerange" start-placeholder="开始时间" end-placeholder="结束时间"/><el-button :loading="reportBusy" @click="refreshReport(true)">查询</el-button><el-button :disabled="reportBusy || !status?.installed" @click="exportLogs">导出筛选结果</el-button></div>
          <el-alert v-if="report?.partial" title="此结果来自最近 4 MiB / 5000 条，已截断。导出同样受此上限约束，不等于完整历史备份。" type="warning" :closable="false"/>
          <el-table :data="report?.events || []" v-loading="reportBusy" max-height="350" empty-text="没有符合筛选条件的真实事件"><el-table-column label="时间" width="160"><template #default="{row}">{{formatPanelDateTime(row.time)}}</template></el-table-column><el-table-column prop="site" label="站点" min-width="130" show-overflow-tooltip/><el-table-column prop="ip" :label="apache ? '网络对端 IP' : '生效客户端 IP'" min-width="130"/><el-table-column v-if="!apache" label="原始网络对端" min-width="130"><template #default="{row}">{{row.peer || '未记录'}}</template></el-table-column><el-table-column label="规则" min-width="120"><template #default="{row}">{{reasonName(row.reason)}}</template></el-table-column><el-table-column prop="path" label="路径" min-width="150" show-overflow-tooltip/><el-table-column prop="method" label="方法" width="75"/><el-table-column prop="status" label="状态" width="65"/><el-table-column v-if="!apache" label="CC 结果" min-width="175"><template #default="{row}">{{rateOutcome(row.rate)}}</template></el-table-column><el-table-column label="动作" width="80"><template #default="{row}"><el-tag :type="row.action==='observe'?'info':'danger'">{{row.action==='observe'?'观察':'阻断'}}</el-tag></template></el-table-column></el-table><el-pagination v-model:current-page="page" :page-size="limit" :total="report?.total || 0" layout="total, prev, pager, next" @current-change="refreshReport()"/><p class="waf-muted">默认最近 24 小时，最多查询 90 天。仅记录时间、站点、生效来源 IP、规范化路径和命中原因；Nginx 启用本应用的可信代理时额外记录原始网络对端，不保存查询参数、Cookie、UA 或请求体；IPv4 / IPv6 属于敏感运维数据，日志仅管理员可读。</p>
        </el-tab-pane>
        <el-tab-pane label="配置与版本" name="config">
          <el-descriptions :column="3" border><el-descriptions-item label="已安装版本">{{status?.version || '未安装'}}</el-descriptions-item><el-descriptions-item label="处理器版本">{{implementation}}</el-descriptions-item><el-descriptions-item label="配置修订">{{applied?.policy.revision}}</el-descriptions-item></el-descriptions><p>应用商店检查 GitHub 签名目录后提示更新；新版处理器由签名面板提供。WAF 升级会实际迁移并校验规则，不只改版本号。</p>
          <h4>安全配置导入 / 导出</h4><el-button type="warning" plain @click="restoreDraft">恢复默认草稿（不立即生效）</el-button><el-button @click="download('yunzhan-waf-applied.json',applied)">导出生效配置</el-button><el-button @click="download('yunzhan-waf-draft.json',cfg)">导出草稿</el-button><p>仅接受本应用的 JSON 配置，128 KiB 上限；拒绝未知字段、任意服务器配置及不支持的网站。导入不会立即改变服务器。</p><el-input v-model="jsonInput" type="textarea" :rows="4" aria-label="导入 JSON 配置" placeholder="粘贴配置 JSON"/><el-button class="waf-add" @click="importConfig">校验并载入草稿</el-button>
          <h4>生成的 {{ engineName }} 配置（只读预览）</h4><el-button @click="showPreview">生成预览</el-button><pre v-if="preview" class="waf-code">{{preview}}</pre><p>保存前自动留下受限权限的完整配置备份，通过 {{ engineName }} 原生校验后才重载，并核对生效指纹；失败恢复旧文件。保存使用修订号检查，防止旧页面覆盖新配置。备份最多 100 份，达到上限拒绝修改，需管理员先归档。</p>
        </el-tab-pane>
        <el-tab-pane label="操作记录" name="history"><div class="waf-actions"><p>最近 50 次持久化任务，包括安装、升级、配置与失败原因。</p><el-button @click="refreshHistory">刷新记录</el-button></div><el-table :data="history" max-height="420" empty-text="尚无操作记录"><el-table-column label="时间" width="170"><template #default="{row}">{{formatPanelDateTime(row.created_at)}}</template></el-table-column><el-table-column prop="kind" label="操作"/><el-table-column prop="state" label="状态"/><el-table-column prop="error" label="错误 / 结果" min-width="240" show-overflow-tooltip/><el-table-column prop="id" label="任务标识" min-width="220" show-overflow-tooltip/></el-table></el-tab-pane>
      </el-tabs>
    </template>
  </section>
</template>

<style scoped>
.waf-proxy-ack{height:auto;max-width:100%;align-items:flex-start}.waf-proxy-ack :deep(.el-checkbox__label){white-space:normal;line-height:1.6}.waf-proxy-ack :deep(.el-checkbox__input){margin-top:4px}
.waf-workspace{color:#30475b;font-size:13px}.waf-heading,.waf-toolbar,.waf-actions{display:flex;align-items:center;justify-content:space-between;gap:12px;flex-wrap:wrap}.waf-heading{padding-bottom:14px;border-bottom:1px solid #e6edf2}.waf-heading h3{font-size:22px;color:#173e35;margin:0 0 7px}.waf-heading p{margin:0;color:#77899d}.waf-toolbar{margin:16px 0;padding:12px 14px;background:#f3f8f6;border:1px solid #e0eee7;border-radius:7px}.waf-toolbar>span{font-size:12px;color:#527165}.waf-workspace :deep(.el-alert){margin:12px 0}.waf-workspace :deep(.el-tabs__item){padding:0 12px;font-size:13px}.waf-workspace h4{margin:20px 0 10px;color:#263e51}.waf-workspace p{line-height:1.7}.waf-two,.waf-three{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:16px}.waf-three{grid-template-columns:repeat(3,minmax(0,1fr))}.waf-metrics{display:grid;grid-template-columns:repeat(4,1fr);gap:14px;padding-top:12px}.waf-metrics article{border:1px solid #e1ebe7;border-radius:8px;padding:17px;background:linear-gradient(120deg,#f5faf7,#fff)}.waf-metrics span,.waf-metrics small,.waf-metrics strong{display:block}.waf-metrics strong{font-size:30px;color:#127848;margin:7px 0}.waf-metrics small,.waf-muted{font-size:12px;color:#73869b}.waf-group-grid{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:12px;margin-top:12px}.waf-group-grid article{display:flex;align-items:center;justify-content:space-between;padding:16px;border:1px solid #e6edf2;border-radius:6px}.waf-group-grid small{display:block;margin-top:6px;color:#73869b}.waf-filter,.waf-editor{display:flex;gap:10px;align-items:center;flex-wrap:wrap;margin:12px 0}.waf-filter>.el-input,.waf-filter>.el-select{width:220px}.waf-editor>.el-input,.waf-editor>.el-select{width:200px}.waf-site-groups{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:12px;padding:15px}.waf-site-groups .el-form-item{display:block}.waf-site-warning{display:block;color:#b86521;margin-top:5px}.waf-add{margin:12px 0}.waf-code{white-space:pre-wrap;overflow-wrap:anywhere;max-height:320px;overflow:auto;background:#152b32;color:#dcefe4;padding:15px;border-radius:7px;font-size:12px}.waf-trend{display:flex;align-items:flex-end;gap:8px;height:125px;overflow:auto;border-bottom:1px solid #e1e9ed;padding-bottom:5px}.waf-trend>div{min-width:42px;display:flex;flex-direction:column;align-items:center;gap:8px}.waf-trend span{width:20px;background:#25b479;border-radius:3px 3px 0 0}.waf-trend small{color:#7e8ca0;font-size:10px}.waf-workspace :deep(.el-input-number){max-width:100%}.waf-workspace :deep(.el-select){width:100%}.waf-filter :deep(.el-select),.waf-editor :deep(.el-select){width:220px}@media(max-width:800px){.waf-two,.waf-three,.waf-group-grid,.waf-site-groups{grid-template-columns:1fr}.waf-metrics{grid-template-columns:repeat(2,1fr)}.waf-toolbar>div{display:flex;flex-wrap:wrap;gap:5px}.waf-toolbar .el-button{margin:0}.waf-heading{gap:15px}}
</style>
