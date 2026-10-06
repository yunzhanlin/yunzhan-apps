<script setup lang="ts">
import { computed, onMounted, ref } from "vue";
import { ElMessage } from "element-plus";
import { formatPanelDateTime } from "./panelTime";
type API = <T>(path: string, method?: string, body?: unknown, key?: string) => Promise<T>;
interface Entry { id: string; value: string; site_id?: string }
interface Rule { id: string; name: string; site_id?: string; field: string; operator: string; value: string; action: string; enabled: boolean }
interface SitePolicy { site_id: string; mode: string; rate_per_second: number; burst: number; cc_enabled?: boolean; groups?: Record<string, boolean> }
interface CCRule { id: string; site_id?: string; path: string; prefix: boolean; rate_per_second: number; burst: number; enabled: boolean }
interface Config { profile: string; rate_per_second: number; policy: { schema_version: number; revision: number; mode: string; cc_enabled: boolean; burst: number; groups: Record<string, boolean>; lists: Record<string, Entry[]>; rules: Rule[]; sites: SitePolicy[]; cc_rules: CCRule[] } }
interface Status { installed: boolean; healthy: boolean; enabled: boolean; version?: string; detail: string }
interface Site { id: string; name: string; domain: string; settings?: { waf_enabled?: boolean; web_server?: string } }
interface Dimension { name: string; count: number }
interface Event { time: string; site: string; site_id?: string; ip: string; path?: string; method: string; status: number; reason: string; action: string }
interface Report { events: Event[]; total: number; blocked: number; observed: number; sources: number; partial: boolean; scanned: number; rules: Dimension[]; ips: Dimension[]; sites: Dimension[]; hours: Dimension[]; from: string; to: string }
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
const defaults = ref<Config>();
const tab = ref("overview"), busy = ref(false), reportBusy = ref(false), error = ref(""), saved = ref(""), preview = ref("");
const report = ref<Report>(), history = ref<History[]>([]), jsonInput = ref("");
const filter = ref({ site_id: "", ip: "", rule: "", action: "" }), range = ref<[Date, Date]>(), page = ref(1), limit = 50;
const listKind = ref("ip_deny"), listScope = ref(""), listValue = ref(""), siteSearch = ref(""), selectedSite = ref("");
const newRule = ref<Omit<Rule, "id">>({ name: "", site_id: "", field: "uri", operator: "contains", value: "", action: "block", enabled: true });
const newCC = ref<Omit<CCRule, "id">>({ site_id: "", path: "", prefix: false, rate_per_second: 5, burst: 10, enabled: true });
const dirty = computed(() => !!cfg.value && JSON.stringify(cfg.value) !== JSON.stringify(applied.value));
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
async function refresh() {
  if (busy.value) return;
  if (dirty.value) { error.value = "存在未保存的草稿。请先保存，或使用“放弃草稿”再刷新。"; return; }
  busy.value = true; error.value = "";
  try {
    await loadConfig();
    const out = await props.api<Site[] | { sites: Site[] }>("/sites"); sites.value = (Array.isArray(out) ? out : out.sites).filter(s => !apache || s.settings?.web_server === "apache");
    await Promise.all([refreshReport(), refreshHistory()]);
  } catch (e) { error.value = (e as Error).message; } finally { busy.value = false; }
}
async function validate() {
  if (!cfg.value) return;
  const out = await props.api<{ http_config: string; server_config: string; settings: Config }>(endpoint("preview"), "POST", { settings: cfg.value });
  cfg.value = clone(out.settings); preview.value = out.http_config + "\n# 每个受管站点的 server 规则\n" + out.server_config;
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
    await Promise.all([refreshHistory(), refreshReport()]);
  } catch (e) { error.value = (e as Error).message; await refreshHistory(); }
  finally { busy.value = false; }
}
function discard() { if (applied.value) cfg.value = clone(applied.value); preview.value = ""; error.value = ""; }
function restoreDraft() { if (!defaults.value || !applied.value) return; cfg.value = clone(defaults.value); cfg.value.policy.revision = applied.value.policy.revision; saved.value = "默认配置已载入草稿，会清空独立策略、名单与自定义规则；尚未应用。可放弃草稿恢复生效配置。"; preview.value = ""; }
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
    const out = await props.api<{ settings: Config; http_config: string; server_config: string }>(endpoint("preview"), "POST", { settings: imported });
    cfg.value = clone(out.settings); preview.value = out.http_config + "\n" + out.server_config; saved.value = "导入配置已通过字段校验，仅载入草稿；点击保存才会修改防护。";
  } catch (e) { error.value = (e as Error).message; } finally { busy.value = false; }
}
function download(name: string, value: unknown) { const url = URL.createObjectURL(new Blob([JSON.stringify(value, null, 2)], { type: "application/json" })); const a = document.createElement("a"); a.href = url; a.download = name; a.click(); setTimeout(() => URL.revokeObjectURL(url), 500); }
async function exportLogs() { if (reportBusy.value) return; reportBusy.value = true; try { download("yunzhan-waf-events.json", await props.api<Report>(reportURL(true))); } catch (e) { error.value = (e as Error).message; } finally { reportBusy.value = false; } }
onMounted(refresh);
</script>

<template>
  <section class="waf-workspace" v-loading="busy">
    <div class="waf-heading"><div><h3>{{ engineName }} 请求防火墙</h3><p>请求防护 · 站点策略 · {{ apache ? "独立名单" : "CC 限速" }} · 审计与报表</p></div><div class="waf-actions"><el-tag :type="status?.healthy ? 'success' : 'warning'">{{ !status?.installed ? '未安装' : status.healthy ? `已加载 · ${modeLabel(applied?.policy.mode || '')}` : '需要核对' }}</el-tag><el-tag type="info">v{{ status?.version || implementation || '—' }}</el-tag><el-button :disabled="busy || dirty" @click="refresh">刷新状态</el-button></div></div>
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
          <div class="waf-two"><section><h4>命中规则排行</h4><el-table :data="report?.rules || []" max-height="220" empty-text="暂无命中"><el-table-column label="规则"><template #default="{row}">{{reasonName(row.name)}}</template></el-table-column><el-table-column prop="count" label="次数" width="80"/></el-table></section><section><h4>来源 IP 排行</h4><el-table :data="report?.ips || []" max-height="220" empty-text="暂无来源"><el-table-column prop="name" label="网络对端 IP"/><el-table-column prop="count" label="次数" width="80"/></el-table></section></div>
          <h4>每小时防护事件（UTC）</h4><div class="waf-trend" v-if="report?.hours.length"><div v-for="h in report.hours.slice(-48)" :key="h.name" :title="`${h.name} UTC · ${h.count} 次`"><span :style="{height: `${Math.max(3, h.count / Math.max(...report.hours.map(x=>x.count)) * 90)}px`}"></span><small>{{h.name.slice(-5)}}</small></div></div><el-empty v-else description="暂无防护事件；没有事件不代表已完成安全审计" :image-size="64"/>
          <el-alert title="当前为独立请求元数据防护：不包含完整 POST/JSON/上传内容解析、商业规则订阅、地区数据库或木马隔离。观察模式不阻断 WAF 命中，但服务器原生拒绝仍有效。" type="info" :closable="false" />
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
          <el-form label-position="top" class="waf-three"><el-form-item label="启用 CC 限速"><el-switch v-model="cfg.policy.cc_enabled" aria-label="启用 CC 限速"/></el-form-item><el-form-item label="每站点 / 每 IP 速率（次 / 秒）"><el-input-number v-model="cfg.rate_per_second" :min="5" :max="200"/></el-form-item><el-form-item label="突发容量（超额立即返回 429）"><el-input-number v-model="cfg.policy.burst" :min="1" :max="1000"/></el-form-item></el-form>
          <p>使用 Nginx 原生漏桶限速，站点之间不共享同一 IP 的额度；URL 规则与站点限速同时生效。观察 / 停用模式与白名单不限速。</p>
          <h4>URL 独立限速（最多 20 条）</h4><div class="waf-editor"><el-select v-model="newCC.site_id" filterable aria-label="URL 限速范围"><el-option value="" label="全部受管站点"/><el-option v-for="s in sites" :key="s.id" :value="s.id" :label="s.domain"/></el-select><el-input v-model="newCC.path" placeholder="/api/login" aria-label="URL 限速路径"/><el-checkbox v-model="newCC.prefix">路径前缀</el-checkbox><el-input-number v-model="newCC.rate_per_second" :min="1" :max="200" aria-label="URL 速率"/><el-input-number v-model="newCC.burst" :min="1" :max="1000" aria-label="URL 突发容量"/><el-button @click="addCC">添加规则</el-button></div>
          <el-table :data="cfg.policy.cc_rules" empty-text="暂无 URL 独立限速"><el-table-column label="范围"><template #default="{row}">{{siteName(row.site_id)}}</template></el-table-column><el-table-column prop="path" label="路径"/><el-table-column label="匹配"><template #default="{row}">{{row.prefix?'前缀':'精确'}}</template></el-table-column><el-table-column prop="rate_per_second" label="次 / 秒" width="85"/><el-table-column prop="burst" label="突发" width="70"/><el-table-column label="启用" width="80"><template #default="{row}"><el-switch v-model="row.enabled"/></template></el-table-column><el-table-column width="75"><template #default="{row}"><el-button text type="danger" @click="cfg.policy.cc_rules=cfg.policy.cc_rules.filter(r=>r!==row)">删除</el-button></template></el-table-column></el-table>
          <el-alert title="IP 取自 Nginx 可信网络对端，不直接信任浏览器提交的 X-Forwarded-For。使用 CDN / 反向代理时，应由管理员先配置可信 real_ip 来源，避免把 CDN 节点当作单个访客。" type="warning" :closable="false"/>
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
          <el-table :data="report?.events || []" v-loading="reportBusy" max-height="350" empty-text="没有符合筛选条件的真实事件"><el-table-column label="时间" width="160"><template #default="{row}">{{formatPanelDateTime(row.time)}}</template></el-table-column><el-table-column prop="site" label="站点" min-width="130" show-overflow-tooltip/><el-table-column prop="ip" label="来源 IP" min-width="130"/><el-table-column label="规则" min-width="120"><template #default="{row}">{{reasonName(row.reason)}}</template></el-table-column><el-table-column prop="path" label="路径" min-width="150" show-overflow-tooltip/><el-table-column prop="method" label="方法" width="75"/><el-table-column prop="status" label="状态" width="65"/><el-table-column label="动作" width="80"><template #default="{row}"><el-tag :type="row.action==='observe'?'info':'danger'">{{row.action==='observe'?'观察':'阻断'}}</el-tag></template></el-table-column></el-table><el-pagination v-model:current-page="page" :page-size="limit" :total="report?.total || 0" layout="total, prev, pager, next" @current-change="refreshReport()"/><p class="waf-muted">默认最近 24 小时，最多查询 90 天。仅记录时间、站点、网络对端、规范化路径和命中原因，不保存查询参数、Cookie、UA 或请求体；IPv4 / IPv6 属于敏感运维数据，日志仅管理员可读。</p>
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
.waf-workspace{color:#30475b;font-size:13px}.waf-heading,.waf-toolbar,.waf-actions{display:flex;align-items:center;justify-content:space-between;gap:12px;flex-wrap:wrap}.waf-heading{padding-bottom:14px;border-bottom:1px solid #e6edf2}.waf-heading h3{font-size:22px;color:#173e35;margin:0 0 7px}.waf-heading p{margin:0;color:#77899d}.waf-toolbar{margin:16px 0;padding:12px 14px;background:#f3f8f6;border:1px solid #e0eee7;border-radius:7px}.waf-toolbar>span{font-size:12px;color:#527165}.waf-workspace :deep(.el-alert){margin:12px 0}.waf-workspace :deep(.el-tabs__item){padding:0 12px;font-size:13px}.waf-workspace h4{margin:20px 0 10px;color:#263e51}.waf-workspace p{line-height:1.7}.waf-two,.waf-three{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:16px}.waf-three{grid-template-columns:repeat(3,minmax(0,1fr))}.waf-metrics{display:grid;grid-template-columns:repeat(4,1fr);gap:14px;padding-top:12px}.waf-metrics article{border:1px solid #e1ebe7;border-radius:8px;padding:17px;background:linear-gradient(120deg,#f5faf7,#fff)}.waf-metrics span,.waf-metrics small,.waf-metrics strong{display:block}.waf-metrics strong{font-size:30px;color:#127848;margin:7px 0}.waf-metrics small,.waf-muted{font-size:12px;color:#73869b}.waf-group-grid{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:12px;margin-top:12px}.waf-group-grid article{display:flex;align-items:center;justify-content:space-between;padding:16px;border:1px solid #e6edf2;border-radius:6px}.waf-group-grid small{display:block;margin-top:6px;color:#73869b}.waf-filter,.waf-editor{display:flex;gap:10px;align-items:center;flex-wrap:wrap;margin:12px 0}.waf-filter>.el-input,.waf-filter>.el-select{width:220px}.waf-editor>.el-input,.waf-editor>.el-select{width:200px}.waf-site-groups{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:12px;padding:15px}.waf-site-groups .el-form-item{display:block}.waf-site-warning{display:block;color:#b86521;margin-top:5px}.waf-add{margin:12px 0}.waf-code{white-space:pre-wrap;overflow-wrap:anywhere;max-height:320px;overflow:auto;background:#152b32;color:#dcefe4;padding:15px;border-radius:7px;font-size:12px}.waf-trend{display:flex;align-items:flex-end;gap:8px;height:125px;overflow:auto;border-bottom:1px solid #e1e9ed;padding-bottom:5px}.waf-trend>div{min-width:42px;display:flex;flex-direction:column;align-items:center;gap:8px}.waf-trend span{width:20px;background:#25b479;border-radius:3px 3px 0 0}.waf-trend small{color:#7e8ca0;font-size:10px}.waf-workspace :deep(.el-input-number){max-width:100%}.waf-workspace :deep(.el-select){width:100%}.waf-filter :deep(.el-select),.waf-editor :deep(.el-select){width:220px}@media(max-width:800px){.waf-two,.waf-three,.waf-group-grid,.waf-site-groups{grid-template-columns:1fr}.waf-metrics{grid-template-columns:repeat(2,1fr)}.waf-toolbar>div{display:flex;flex-wrap:wrap;gap:5px}.waf-toolbar .el-button{margin:0}.waf-heading{gap:15px}}
</style>
