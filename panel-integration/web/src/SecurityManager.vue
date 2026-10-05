<script setup lang="ts">
import { formatPanelDate, formatPanelDateTime } from "./panelTime";
import { computed, onMounted, ref } from "vue";
import { ElMessage, ElMessageBox } from "element-plus";

interface Rule {
  id: string;
  name: string;
  protocol: "tcp" | "udp";
  source: string;
  port_from: number;
  port_to: number;
  action: "accept" | "drop";
  enabled: boolean;
}
interface Config {
  enabled: boolean;
  default_action: "accept" | "drop";
  rules: Rule[];
  revision: number;
  updated_at: string;
}
interface Status {
  available: boolean;
  active: boolean;
  pending: boolean;
  deadline?: number;
  detail: string;
}
interface Page {
  config: Config;
  status: Status;
}
interface SSH {
  available: boolean;
  active: boolean;
  enabled: boolean;
  ports: number[];
  password_authentication: string;
  permit_root_login: string;
  pubkey_authentication: string;
  max_auth_tries: number;
  x11_forwarding: string;
  allow_tcp_forwarding: string;
  warnings: string[];
  checked_at: string;
}
interface Apply {
  change_id: string;
  deadline: number;
  config: string;
}
interface Certificate {
  id: string;
  name: string;
  domains: string[];
  issuer: string;
  not_after: string;
  status: string;
  references: number;
}
interface LoginEvent {
  id: number;
  username: string;
  ip: string;
  result: string;
  created_at: string;
}
interface ScanFinding { path: string; rule: string; severity: string; description: string }
interface ScanSite { site_id: string; domain: string; status: string; error?: string; findings: ScanFinding[] }
interface ScanReport { scanned_at: string; partial: boolean; sites: ScanSite[] }
interface Fail2banJail { name: string; currently_banned: number; total_banned: number; banned_ips: string[] }
interface Fail2banStatus { installed: boolean; active: boolean; jails: Fail2banJail[]; detail?: string }

const props = defineProps<{
  api: <T>(path: string, method?: string, body?: unknown) => Promise<T>;
}>();
const emit = defineEmits<{ navigate: [view: string] }>();
const page = ref<Page | null>(null),
  ssh = ref<SSH | null>(null),
  certificates = ref<Certificate[]>([]),
  loginEvents = ref<LoginEvent[]>([]),
  certificatesReady = ref(false),
  loginEventsReady = ref(false),
  scanReady = ref(false),
  sourceErrors = ref<string[]>([]),
  scanReport = ref<ScanReport>({ scanned_at: "", partial: false, sites: [] }),
  fail2ban = ref<Fail2banStatus>({ installed: false, active: false, jails: [] }),
  scanBusy = ref(false),
  scanOpen = ref(false),
  scanListOpen = ref(false),
  scanListPage = ref(1),
  banListOpen = ref(false),
  banListPage = ref(1),
  suggestionListOpen = ref(false),
  alertListOpen = ref(false),
  alertListPage = ref(1),
  loginLogOpen = ref(false),
  selectedScan = ref<ScanSite | null>(null);
const loading = ref(false),
  saving = ref(false),
  error = ref(""),
  preview = ref(""),
  previewOpen = ref(false),
  editorOpen = ref(false),
  pending = ref<Apply | null>(null);
const draft = ref<Config>({
  enabled: false,
  default_action: "accept",
  rules: [],
  revision: 1,
  updated_at: "",
});
const deadlineText = computed(() =>
  pending.value
    ? new Date(pending.value.deadline * 1000).toLocaleTimeString("zh-CN", {
        hour12: false,
      })
    : "",
);
const yes = (value: string) =>
  value === "yes" ? "是" : value === "no" ? "否" : value;
const committedFirewall = computed<Config>(() => page.value?.config || { enabled: false, default_action: "accept", rules: [], revision: 0, updated_at: "" });
const openRiskCount = computed(() => {
  const ranges: Record<"tcp" | "udp", Array<[number, number]>> = { tcp: [], udp: [] };
  for (const rule of committedFirewall.value.rules) {
    if (rule.enabled && rule.action === "accept" && ["0.0.0.0/0", "::/0"].includes(rule.source)
      && ["tcp", "udp"].includes(rule.protocol) && rule.port_from >= 1 && rule.port_to >= rule.port_from && rule.port_to <= 65535)
      ranges[rule.protocol].push([rule.port_from, rule.port_to]);
  }
  let count = 0;
  for (const protocol of ["tcp", "udp"] as const) {
    const sorted = ranges[protocol].sort((a, b) => a[0] - b[0]);
    let start = -1, end = -1;
    const add = () => {
      if (start < 0) return;
      count += end - start + 1;
      if (protocol === "tcp")
        count -= [22, 80, 443, ...(ssh.value?.ports || [])].filter((port, index, all) => all.indexOf(port) === index && port >= start && port <= end).length;
    };
    for (const [from, to] of sorted) {
      if (from > end + 1) { add(); start = from; end = to; }
      else end = Math.max(end, to);
    }
    add();
  }
  return count;
});
const attentionCerts = computed(() => certificates.value.filter((c) => c.status !== "valid").length);
const expiringCerts = computed(
  () =>
    certificates.value.filter(
      (c) => c.status === "expiring" || c.status === "expired",
    ).length,
);
const notYetValidCerts = computed(() => certificates.value.filter((c) => c.status === "not_yet_valid").length);
const unknownCerts = computed(() => certificates.value.filter((c) => !["valid", "expiring", "expired", "not_yet_valid"].includes(c.status)).length);
const scanRiskCount = computed(() => scanReport.value.sites.reduce((count, site) => count + site.findings.length, 0));
const totalBanned = computed(() => fail2ban.value.jails.reduce((count, jail) => count + jail.total_banned, 0));
const allBannedAddresses = computed(() => fail2ban.value.jails.flatMap((jail) => jail.banned_ips.map((ip) => ({ jail: jail.name, ip }))));
const bannedAddresses = computed(() => allBannedAddresses.value.slice(0, 5));
const pagedBannedAddresses = computed(() => allBannedAddresses.value.slice((banListPage.value - 1) * 20, banListPage.value * 20));
const pagedScanSites = computed(() => scanReport.value.sites.slice((scanListPage.value - 1) * 10, scanListPage.value * 10));
// These ports match the executor's fixed nftables rule, even when the
// configurable firewall policy is in allow mode.
const fixedFirewallRows = [
  { protocol: "TCP", port: "22", source: "任意来源", policy: "固定允许", note: "预留 SSH 端口" },
  { protocol: "TCP", port: "80", source: "任意来源", policy: "固定允许", note: "网站 HTTP" },
  { protocol: "TCP", port: "443", source: "任意来源", policy: "固定允许", note: "网站 HTTPS" },
  { protocol: "全部", port: "全部", source: "本机回环", policy: "固定允许", note: "面板管理与本机救援" },
];
const riskPortsAssessable = computed(() => !!page.value && committedFirewall.value.enabled && committedFirewall.value.default_action === "drop");
const suggestions = computed(() => {
  const rows: string[] = [];
  if (page.value && (!committedFirewall.value.enabled || committedFirewall.value.default_action === "accept"))
    rows.push("防火墙当前为允许模式，建议核对后启用基础拦截策略");
  if (openRiskCount.value)
    rows.push(`检测到 ${openRiskCount.value} 个公网开放的非常用端口`);
  if (ssh.value?.warnings?.length) rows.push(...ssh.value.warnings);
  if (expiringCerts.value)
    rows.push(`${expiringCerts.value} 张证书已过期或即将到期`);
  if (notYetValidCerts.value)
    rows.push(`${notYetValidCerts.value} 张证书尚未生效`);
  if (unknownCerts.value)
    rows.push(`${unknownCerts.value} 张证书状态需要核对`);
  if (scanRiskCount.value) rows.push(`${scanRiskCount.value} 项网站目录安全线索需要核对`);
  return rows;
});
const allSecurityAlerts = computed(() => {
  const denied = loginEvents.value.filter((item) => item.result !== "success").map((item) => ({
    title: item.result === "rate_limited" ? "面板登录触发限流" : "面板登录失败",
    detail: `${item.ip} · ${item.username}`,
    time: item.created_at,
    severity: "danger",
  }));
  const config = suggestions.value.map((item) => ({ title: item, detail: "当前配置", time: "", severity: "warning" }));
  return [...denied, ...config];
});
const securityAlerts = computed(() => allSecurityAlerts.value.slice(0, 5));
const pagedSecurityAlerts = computed(() => allSecurityAlerts.value.slice((alertListPage.value - 1) * 20, alertListPage.value * 20));
function clone(v: Config) {
  draft.value = JSON.parse(JSON.stringify(v));
}
function openEditor() {
  if (page.value) clone(page.value.config);
  editorOpen.value = true;
}
function addRule() {
  draft.value.rules.push({
    id: "",
    name: "新规则",
    protocol: "tcp",
    source: "0.0.0.0/0",
    port_from: 8080,
    port_to: 8080,
    action: "accept",
    enabled: true,
  });
}
function removeRule(index: number) {
  draft.value.rules.splice(index, 1);
}
async function refresh() {
  if (loading.value) return;
  loading.value = true;
  error.value = "";
  try {
    const [f, s, c, events, scan, bans] = await Promise.allSettled([
      props.api<Page>("/security/firewall"),
      props.api<SSH>("/security/ssh"),
      props.api<Certificate[]>("/certificates"),
      props.api<LoginEvent[]>("/security/login-events"),
      props.api<ScanReport>("/security/site-scan"),
      props.api<Fail2banStatus>("/security/fail2ban"),
    ]);
    const unavailable: string[] = [];
    if (f.status === "fulfilled") { page.value = f.value; clone(f.value.config); }
    else { page.value = null; unavailable.push("防火墙"); }
    if (s.status === "fulfilled") ssh.value = s.value;
    else { ssh.value = null; unavailable.push("SSH"); }
    certificatesReady.value = c.status === "fulfilled";
    certificates.value = c.status === "fulfilled" ? c.value : [];
    if (!certificatesReady.value) unavailable.push("证书");
    loginEventsReady.value = events.status === "fulfilled";
    loginEvents.value = events.status === "fulfilled" ? events.value : [];
    if (!loginEventsReady.value) unavailable.push("登录记录");
    scanReady.value = scan.status === "fulfilled";
    scanReport.value = scan.status === "fulfilled" ? scan.value : { scanned_at: "", partial: false, sites: [] };
    if (!scanReady.value) unavailable.push("网站扫描");
    fail2ban.value = bans.status === "fulfilled" ? bans.value : { installed: false, active: false, jails: [], detail: "封禁状态暂不可用" };
    if (bans.status !== "fulfilled") unavailable.push("Fail2ban");
    sourceErrors.value = unavailable;
    error.value = unavailable.length ? `部分安全数据暂不可用：${unavailable.join("、")}` : "";
  } catch (e) {
    error.value = (e as Error).message;
  } finally {
    loading.value = false;
  }
}
async function scanNow() {
  if (scanBusy.value) return;
  scanBusy.value = true;
  try {
    scanReport.value = await props.api<ScanReport>("/security/site-scan", "POST", {});
    scanReady.value = true;
    sourceErrors.value = sourceErrors.value.filter(item => item !== "网站扫描");
    error.value = sourceErrors.value.length ? `部分安全数据暂不可用：${sourceErrors.value.join("、")}` : "";
    ElMessage.success(`已检查 ${scanReport.value.sites.length} 个受管网站`);
  } catch (e) {
    ElMessage.error((e as Error).message);
  } finally {
    scanBusy.value = false;
  }
}
function showScan(site: ScanSite) { scanListOpen.value = false; selectedScan.value = site; scanOpen.value = true; }
async function unban(jail: string, ip: string) {
  try {
    await ElMessageBox.confirm(`确认从 ${jail} 解封 ${ip}？`, "解除 IP 封禁", {
      confirmButtonText: "解除封禁", cancelButtonText: "取消", type: "warning",
    });
  } catch { return; }
  try {
    await props.api("/security/fail2ban/unban", "POST", { jail, ip });
    fail2ban.value = await props.api<Fail2banStatus>("/security/fail2ban");
    banListPage.value = Math.min(banListPage.value, Math.max(1, Math.ceil(allBannedAddresses.value.length / 20)));
    ElMessage.success(`${ip} 已解封`);
  } catch (e) { ElMessage.error((e as Error).message); }
}
async function showPreview() {
  try {
    const r = await props.api<Apply>(
      "/security/firewall/preview",
      "POST",
      draft.value,
    );
    preview.value = r.config;
    previewOpen.value = true;
  } catch (e) {
    ElMessage.error((e as Error).message);
  }
}
async function apply() {
  if (saving.value) return;
  try {
    await ElMessageBox.confirm(
      "规则应用后有 45 秒确认时间。请保持当前页面打开，并从新连接确认可访问。",
      "应用防火墙规则",
      {
        confirmButtonText: "应用并开始计时",
        cancelButtonText: "取消",
        type: "warning",
      },
    );
  } catch {
    return;
  }
  saving.value = true;
  try {
    pending.value = await props.api<Apply>(
      "/security/firewall",
      "PUT",
      draft.value,
    );
    editorOpen.value = false;
    ElMessage.warning("规则已加载，请立即确认新连接可访问");
  } catch (e) {
    ElMessage.error((e as Error).message);
  } finally {
    saving.value = false;
  }
}
async function confirm() {
  if (!pending.value) return;
  saving.value = true;
  try {
    const updated = await props.api<Config>(
      "/security/firewall/confirm",
      "POST",
      { change_id: pending.value.change_id },
    );
    pending.value = null;
    clone(updated);
    await refresh();
    ElMessage.success("新连接验证成功，防火墙配置已提交");
  } catch (e) {
    ElMessage.error((e as Error).message);
  } finally {
    saving.value = false;
  }
}
const date = (v: string) =>
  v ? formatPanelDateTime(v) : "—";
const shortDate = (v: string) =>
  v ? formatPanelDate(v) : "—";
defineExpose({ refresh, scanNow });
onMounted(refresh);
</script>

<template>
  <div class="security-page" v-loading="loading">
    <el-alert v-if="error" :title="error" type="error" :closable="false" />
    <el-alert v-if="pending" type="warning" :closable="false" show-icon>
      <template #title
        >防火墙规则等待新连接确认，{{
          deadlineText
        }}
        前未确认会自动恢复。</template
      >
      <el-button type="warning" :loading="saving" @click="confirm"
        >确认新连接可访问</el-button
      >
    </el-alert>

    <section class="security-summary">
      <article class="panel-card summary-card good">
        <span class="summary-icon"><svg viewBox="0 0 40 40" aria-hidden="true"><path d="M20 3 34 9v11c0 9-5 14-14 18C11 34 6 29 6 20V9L20 3Z" fill="currentColor" stroke="none"/><path d="M20 12v16M12 20h16" stroke="#fff" stroke-width="3" stroke-linecap="round"/></svg></span>
        <div>
          <small>防火墙状态</small
          ><strong>{{ page ? committedFirewall.enabled ? "已开启" : "允许模式" : "—" }}</strong>
          <p>{{ page ? `内核规则表 ${page.status.active ? "已加载" : "未加载"}` : "防火墙状态暂不可用" }}</p>
        </div>
      </article>
      <article
        class="panel-card summary-card"
        :class="riskPortsAssessable ? (openRiskCount ? 'danger' : 'good') : 'neutral'"
      >
        <span class="summary-icon"><svg viewBox="0 0 40 40" aria-hidden="true"><circle cx="20" cy="20" r="17" fill="currentColor" stroke="none"/><path d="M20 10v14" stroke="#fff" stroke-width="3.5" stroke-linecap="round"/><circle cx="20" cy="30" r="2.1" fill="#fff" stroke="none"/></svg></span>
        <div>
          <small>风险端口</small><strong>{{ riskPortsAssessable ? openRiskCount : '—' }}</strong>
          <p>{{ !page ? '防火墙状态暂不可用' : riskPortsAssessable ? `共检查 ${committedFirewall.rules.length} 条自定义规则` : '允许模式，不能仅凭规则判断' }}</p>
        </div>
      </article>
      <article class="panel-card summary-card good">
        <span class="summary-icon"><svg viewBox="0 0 40 40" aria-hidden="true"><rect x="7" y="17" width="26" height="19" rx="3" fill="currentColor" stroke="none"/><path d="M12 18v-6a8 8 0 0 1 16 0v6" stroke="currentColor" stroke-width="4" fill="none"/><circle cx="20" cy="26" r="2" fill="#fff" stroke="none"/></svg></span>
        <div>
        <small>SSL 证书</small><strong>{{ certificatesReady ? certificates.length : '—' }}</strong>
        <p>
          {{
              !certificatesReady ? "证书列表暂不可用" : attentionCerts ? `${attentionCerts} 张需要处理` : certificates.length ? "当前证书状态正常" : "尚未上传证书"
            }}
          </p>
        </div>
      </article>
      <article class="panel-card summary-card attack" :class="fail2ban.active ? 'good' : 'neutral'">
        <span class="summary-icon"><svg viewBox="0 0 40 40" aria-hidden="true"><path d="M20 3 34 9v11c0 9-5 14-14 18C11 34 6 29 6 20V9L20 3Z" fill="currentColor" stroke="none"/><path d="m22 10-9 12h7l-2 10 10-14h-7l1-8Z" fill="#fff" stroke="none"/></svg></span>
        <div>
          <small>攻击拦截</small><strong>{{ fail2ban.active ? totalBanned : "—" }}</strong>
          <p>{{ fail2ban.active ? `Fail2ban 累计封禁 · ${fail2ban.jails.length} 个 Jail` : (fail2ban.detail || "拦截服务未运行") }}</p>
        </div>
      </article>
    </section>

    <section class="security-dashboard">
      <article class="panel-card dashboard-card firewall-card">
        <header>
          <h2>防火墙规则</h2>
          <button :disabled="!page" @click="openEditor">编辑配置 ›</button>
        </header>
        <table v-if="page" class="compact-table">
          <thead>
            <tr>
              <th>协议</th>
              <th>端口</th>
              <th>来源</th>
              <th>策略</th>
              <th>备注</th>
            </tr>
          </thead>
          <tbody>
            <tr v-for="row in fixedFirewallRows" :key="row.port + row.note">
              <td>{{ row.protocol }}</td>
              <td>{{ row.port }}</td>
              <td>{{ row.source }}</td>
              <td><b class="ok">{{ row.policy }}</b></td>
              <td>{{ row.note }}</td>
            </tr>
            <tr
              v-for="rule in committedFirewall.rules.slice(0, 4)"
              :key="rule.id || rule.name"
            >
              <td>{{ rule.protocol.toUpperCase() }}</td>
              <td>
                {{
                  rule.port_from === rule.port_to
                    ? rule.port_from
                    : `${rule.port_from}-${rule.port_to}`
                }}
              </td>
              <td>{{ rule.source }}</td>
              <td>
                <b :class="rule.action === 'accept' ? 'ok' : 'bad'">{{
                  rule.action === "accept" ? "允许" : "拒绝"
                }}</b>
              </td>
              <td>{{ rule.name }}</td>
            </tr>
          </tbody>
        </table>
        <div v-else class="empty-panel"><b>防火墙规则暂不可用</b><p>其他安全数据仍可查看。</p></div>
      </article>

      <article class="panel-card dashboard-card">
        <header>
          <h2>IP 封禁（Fail2ban）</h2>
          <div class="security-header-actions"><span :class="fail2ban.active ? 'ok' : 'warn'">{{ fail2ban.active ? `${fail2ban.jails.length} 个 Jail 运行中` : (fail2ban.detail || '未运行') }}</span><button type="button" @click="banListPage = 1; banListOpen = true">查看全部 ›</button></div>
        </header>
        <table v-if="bannedAddresses.length" class="compact-table">
          <thead><tr><th>IP 地址</th><th>Jail</th><th>状态</th><th>操作</th></tr></thead>
          <tbody><tr v-for="row in bannedAddresses" :key="row.jail + row.ip"><td>{{ row.ip }}</td><td>{{ row.jail }}</td><td class="bad">封禁中</td><td><button class="scan-detail-button" @click="unban(row.jail, row.ip)">解封</button></td></tr></tbody>
        </table>
        <div v-else class="empty-panel">
          <b>{{ fail2ban.active ? '当前没有封禁 IP' : (fail2ban.detail || 'Fail2ban 未运行') }}</b>
          <p>{{ fail2ban.active ? `累计封禁 ${totalBanned} 次，防护服务运行中` : '请在服务器安装并启用 Fail2ban' }}</p>
        </div>
      </article>

      <article class="panel-card dashboard-card">
        <header>
          <h2>SSH 安全设置</h2>
          <span :class="ssh?.active ? 'ok' : 'bad'">{{
            ssh ? ssh.active ? "运行中" : "未运行" : "暂不可用"
          }}</span>
        </header>
        <dl class="key-values">
          <div>
            <dt>SSH 端口</dt>
            <dd>{{ ssh?.ports.join(", ") || "—" }}</dd>
          </div>
          <div>
            <dt>允许 root 登录</dt>
            <dd>{{ ssh?.permit_root_login || "—" }}</dd>
          </div>
          <div>
            <dt>密码登录</dt>
            <dd>{{ yes(ssh?.password_authentication || "—") }}</dd>
          </div>
          <div>
            <dt>密钥登录</dt>
            <dd>{{ yes(ssh?.pubkey_authentication || "—") }}</dd>
          </div>
          <div>
            <dt>最大尝试次数</dt>
            <dd>{{ ssh?.max_auth_tries || "—" }}</dd>
          </div>
        </dl>
      </article>

      <article class="panel-card dashboard-card">
        <header>
          <h2>网站安全扫描</h2>
          <div class="security-header-actions"><button type="button" @click="scanListPage = 1; scanListOpen = true">查看全部 ›</button><button :disabled="scanBusy" @click="scanNow">{{ scanBusy ? '扫描中…' : '立即扫描' }}</button></div>
        </header>
        <table v-if="scanReport.sites.length" class="compact-table"><thead><tr><th>站点</th><th>发现项</th><th>状态</th><th>操作</th></tr></thead><tbody><tr v-for="site in scanReport.sites.slice(0,3)" :key="site.site_id"><td :title="site.domain">{{ site.domain }}</td><td :class="site.findings.length ? 'bad' : 'ok'">{{ site.findings.length }}</td><td>{{ site.status === 'safe' ? '已检查' : site.status === 'partial' ? '部分结果' : site.status === 'unavailable' ? '不可用' : '需核对' }}</td><td><button class="scan-detail-button" @click="showScan(site)">查看</button></td></tr></tbody></table>
        <div v-else class="empty-panel"><b>{{ scanReady ? '尚无扫描结果' : '扫描结果暂不可用' }}</b><p>检查受管网站公开目录两级深度内的敏感文件、备份副本和权限。</p></div>
        <p v-if="scanReport.scanned_at" class="scan-note">上次扫描 {{ date(scanReport.scanned_at) }} · 两级深度、至多 24 个目录及 1200 条目；仅检查风险线索，不判定 CVE</p>
      </article>

      <article class="panel-card dashboard-card">
        <header>
          <h2>SSL 证书部署状态</h2>
          <button type="button" @click="emit('navigate', 'certificates')">查看全部 ›</button>
        </header>
        <table class="compact-table">
          <thead>
            <tr>
              <th>域名</th>
              <th>签发机构</th>
              <th>到期时间</th>
              <th>状态</th>
            </tr>
          </thead>
          <tbody>
            <tr v-for="cert in certificates.slice(0, 4)" :key="cert.id">
              <td>{{ cert.domains[0] || cert.name }}</td>
              <td>{{ cert.issuer || "—" }}</td>
              <td>{{ shortDate(cert.not_after) }}</td>
              <td>
                <b :class="cert.status === 'valid' ? 'ok' : 'warn'">{{
                  cert.status === "valid"
                    ? "正常"
                    : cert.status === "expiring"
                      ? "即将到期"
                      : cert.status === "expired"
                        ? "已过期"
                        : cert.status === "not_yet_valid"
                          ? "未生效"
                          : "需核对"
                }}</b>
              </td>
            </tr>
            <tr v-if="!certificates.length">
              <td colspan="4" class="empty-cell">{{ certificatesReady ? '尚未上传或签发证书' : '证书列表暂不可用' }}</td>
            </tr>
          </tbody>
        </table>
      </article>

      <article class="panel-card dashboard-card">
        <header>
          <h2>安全建议</h2>
          <div class="security-header-actions"><span>{{ suggestions.length ? `${suggestions.length} 项` : "正常" }}</span><button type="button" @click="suggestionListOpen = true">查看全部 ›</button></div>
        </header>
        <ul v-if="suggestions.length" class="suggestions">
          <li v-for="item in suggestions.slice(0, 4)" :key="item">
            <i>!</i><span>{{ item }}</span>
          </li>
        </ul>
        <div v-else class="empty-panel">
          <b>{{ sourceErrors.length ? '部分检查暂不可用' : '未发现常见配置风险' }}</b>
          <p>{{ sourceErrors.length ? '请核对上方数据读取提示。' : '已检查防火墙、SSH 和证书状态。' }}</p>
        </div>
      </article>

      <article class="panel-card dashboard-card audit-card">
        <header>
          <h2>最近登录日志</h2>
          <button type="button" @click="loginLogOpen = true">查看全部 ›</button>
        </header>
        <table class="compact-table">
          <thead>
            <tr>
              <th>时间</th>
              <th>IP 地址</th>
              <th>用户名</th>
              <th>登录方式</th>
              <th>状态</th>
            </tr>
          </thead>
          <tbody>
            <tr v-for="row in loginEvents.slice(0, 5)" :key="row.id">
              <td>{{ date(row.created_at) }}</td>
              <td>{{ row.ip }}</td>
              <td>{{ row.username }}</td>
              <td>面板账户</td>
              <td>
                <b :class="row.result === 'success' ? 'ok' : 'warn'">{{
                  row.result === 'success' ? '成功' : row.result === 'rate_limited' ? '限流' : '失败'
                }}</b>
              </td>
            </tr>
            <tr v-if="!loginEvents.length">
              <td colspan="5" class="empty-cell">{{ loginEventsReady ? '暂无新版本登录记录' : '登录记录暂不可用' }}</td>
            </tr>
          </tbody>
        </table>
      </article>
      <article class="panel-card dashboard-card alerts-card">
        <header><h2>最近安全告警</h2><div class="security-header-actions"><span>{{ allSecurityAlerts.length }} 项</span><button type="button" @click="alertListPage = 1; alertListOpen = true">查看全部 ›</button></div></header>
        <div v-if="securityAlerts.length" class="security-alert-list"><div v-for="(item,index) in securityAlerts" :key="index" :class="item.severity"><i>!</i><span><b>{{ item.title }}</b><small>{{ item.detail }}</small></span><time>{{ item.time ? date(item.time) : '' }}</time></div></div>
        <div v-else class="empty-panel"><b>{{ sourceErrors.length ? '部分告警来源暂不可用' : '暂无安全告警' }}</b><p>{{ sourceErrors.length ? '请核对上方数据读取提示。' : '登录和配置检查目前正常。' }}</p></div>
      </article>
    </section>

    <el-dialog v-model="loginLogOpen" title="登录记录" width="min(700px, 94vw)">
      <p class="security-login-scope">{{ loginEventsReady ? `本次接口返回的最近 ${loginEvents.length} 条面板登录记录。` : '登录记录暂不可用。' }}</p>
      <div class="security-login-history">
        <article v-for="row in loginEvents" :key="row.id">
          <span><strong>{{ row.username }}</strong><small>{{ date(row.created_at) }} · {{ row.ip }}</small></span>
          <b :class="row.result === 'success' ? 'ok' : 'warn'">{{ row.result === 'success' ? '成功' : row.result === 'rate_limited' ? '限流' : '失败' }}</b>
        </article>
        <p v-if="!loginEvents.length" class="empty-cell">{{ loginEventsReady ? '暂无登录记录' : '登录记录暂不可用' }}</p>
      </div>
    </el-dialog>

    <el-dialog v-model="banListOpen" title="IP 封禁记录" width="min(760px, 94vw)">
      <p class="security-login-scope">{{ sourceErrors.includes('Fail2ban') ? '封禁状态暂不可用。' : `当前接口返回 ${allBannedAddresses.length} 个封禁 IP，来自 ${fail2ban.jails.length} 个 Jail；每页 20 条。` }}</p>
      <div class="security-complete-list">
        <article v-for="row in pagedBannedAddresses" :key="row.jail + row.ip"><span><strong>{{ row.ip }}</strong><small>{{ row.jail }} · 封禁中</small></span><button type="button" class="scan-detail-button" @click="unban(row.jail, row.ip)">解封</button></article>
        <p v-if="!allBannedAddresses.length" class="empty-cell">{{ sourceErrors.includes('Fail2ban') ? '封禁状态暂不可用' : '当前没有封禁 IP' }}</p>
      </div>
      <el-pagination v-if="allBannedAddresses.length > 20" v-model:current-page="banListPage" :page-size="20" :total="allBannedAddresses.length" layout="prev, pager, next" background class="security-list-pagination" />
    </el-dialog>

    <el-dialog v-model="scanListOpen" title="网站安全扫描结果" width="min(760px, 94vw)">
      <p class="security-login-scope">{{ scanReady ? `上次扫描 ${scanReport.scanned_at ? date(scanReport.scanned_at) : '尚未执行'} · 本次接口返回 ${scanReport.sites.length} 个站点${scanReport.partial ? '，部分结果未完成' : ''}。` : '网站扫描结果暂不可用。' }}</p>
      <div class="security-complete-list">
        <article v-for="site in pagedScanSites" :key="site.site_id"><span><strong>{{ site.domain }}</strong><small>{{ site.findings.length }} 项线索 · {{ site.status === 'safe' ? '已检查' : site.status === 'partial' ? '部分结果' : site.status === 'unavailable' ? '不可用' : '需核对' }}</small></span><button type="button" class="scan-detail-button" @click="showScan(site)">查看</button></article>
        <p v-if="!scanReport.sites.length" class="empty-cell">{{ scanReady ? '尚无扫描结果' : '扫描结果暂不可用' }}</p>
      </div>
      <el-pagination v-if="scanReport.sites.length > 10" v-model:current-page="scanListPage" :page-size="10" :total="scanReport.sites.length" layout="prev, pager, next" background class="security-list-pagination" />
    </el-dialog>

    <el-dialog v-model="suggestionListOpen" title="全部安全建议" width="min(700px, 94vw)">
      <p class="security-login-scope">根据当前防火墙、SSH、证书与上次网站目录扫描结果生成，共 {{ suggestions.length }} 项。</p>
      <ul v-if="suggestions.length" class="suggestions security-all-suggestions"><li v-for="item in suggestions" :key="item"><i>!</i><span>{{ item }}</span></li></ul>
      <p v-else class="empty-cell">当前没有安全建议</p>
    </el-dialog>

    <el-dialog v-model="alertListOpen" title="安全告警记录" width="min(760px, 94vw)">
      <p class="security-login-scope">当前接口返回的登录失败记录和配置建议，共 {{ allSecurityAlerts.length }} 项；每页 20 条。</p>
      <div class="security-complete-list">
        <article v-for="(item, index) in pagedSecurityAlerts" :key="`${item.title}-${item.time}-${index}`"><span><strong>{{ item.title }}</strong><small>{{ item.detail }}{{ item.time ? ` · ${date(item.time)}` : '' }}</small></span></article>
        <p v-if="!allSecurityAlerts.length" class="empty-cell">当前没有安全告警</p>
      </div>
      <el-pagination v-if="allSecurityAlerts.length > 20" v-model:current-page="alertListPage" :page-size="20" :total="allSecurityAlerts.length" layout="prev, pager, next" background class="security-list-pagination" />
    </el-dialog>

    <el-dialog
      v-model="scanOpen"
      :title="'网站安全扫描 · ' + (selectedScan?.domain || '')"
      width="min(700px, 94vw)"
    ><p class="scan-dialog-note">此扫描检查受管网站公开目录两级深度内的文件名与权限，遇到符号链接不会进入。发现项表示需要核对访问策略，不能单独证明文件可从公网读取。</p><el-table :data="selectedScan?.findings || []" size="small"><el-table-column prop="path" label="路径" min-width="150" /><el-table-column prop="severity" label="级别" width="85" /><el-table-column prop="description" label="检查结果" min-width="290" /></el-table><el-empty v-if="!selectedScan?.findings.length" description="当前检查项未发现线索" :image-size="60" /></el-dialog>
    <el-dialog
      v-model="editorOpen"
      title="防火墙规则配置"
      width="min(1040px, 92vw)"
      destroy-on-close
    >
      <div class="security-heading">
        <p>
          规则只写入独立的 inet panel 表；保存前校验，断连会在 45 秒后自动恢复。
        </p>
        <el-switch
          v-model="draft.enabled"
          aria-label="启用主机防火墙"
          active-text="启用拦截"
        />
      </div>
      <el-alert
        title="本机回环（含面板入口）、已建立连接、ICMP 和网站端口始终允许；默认拒绝时会先读取并保留 SSH 实际端口。"
        type="info"
        :closable="false"
        show-icon
      />
      <div class="policy-row">
        <span>未匹配流量</span
        ><el-radio-group
          v-model="draft.default_action"
          :disabled="!draft.enabled"
          ><el-radio-button value="accept">允许</el-radio-button
          ><el-radio-button value="drop">拒绝</el-radio-button></el-radio-group
        ><el-button @click="addRule">添加规则</el-button>
      </div>
      <div class="rule-list">
        <div v-if="!draft.rules.length" class="empty-rules">
          暂无自定义规则，可先预览并启用安全的基础策略。
        </div>
        <article
          v-for="(rule, index) in draft.rules"
          :key="rule.id || index"
          class="rule-row"
        >
          <el-switch v-model="rule.enabled" /><el-input
            v-model="rule.name"
            aria-label="规则名称"
          /><el-select v-model="rule.protocol"
            ><el-option label="TCP" value="tcp" /><el-option
              label="UDP"
              value="udp" /></el-select
          ><el-input v-model="rule.source" />
          <div class="port-range">
            <el-input-number
              v-model="rule.port_from"
              :min="1"
              :max="65535"
            /><span>—</span
            ><el-input-number v-model="rule.port_to" :min="1" :max="65535" />
          </div>
          <el-select v-model="rule.action"
            ><el-option label="允许" value="accept" /><el-option
              label="拒绝"
              value="drop" /></el-select
          ><el-button type="danger" plain @click="removeRule(index)"
            >删除</el-button
          >
        </article>
      </div>
      <template #footer
        ><el-button @click="editorOpen = false">取消</el-button
        ><el-button @click="showPreview">预览 nftables</el-button
        ><el-button
          type="primary"
          :disabled="!page?.status.available"
          :loading="saving"
          @click="apply"
          >应用规则</el-button
        ></template
      >
    </el-dialog>
    <el-dialog v-model="previewOpen" title="nftables 候选配置" width="760px"
      ><p class="preview-note">预览经过 nft -c 语法校验，不修改内核规则。</p>
      <pre class="security-preview">{{ preview }}</pre>
      <template #footer
        ><el-button type="primary" @click="previewOpen = false"
          >我已检查</el-button
        ></template
      ></el-dialog
    >
  </div>
</template>

<style scoped>
.security-page {
  display: grid;
  gap: 14px;
}
.security-summary {
  display: grid;
  grid-template-columns: repeat(4, minmax(0, 1fr));
  gap: 14px;
}
.summary-card {
  min-height: 126px;
  padding: 20px;
  display: flex;
  align-items: center;
  gap: 18px;
}
.summary-icon {
  display: grid;
  place-items: center;
  width: 64px;
  height: 64px;
  flex: 0 0 64px;
  border-radius: 14px;
  background: #edf2f6;
  color: #8191a2;
  font-size: 24px;
  font-weight: 800;
}
.summary-icon svg { width: 36px; height: 36px; stroke: currentColor; }
.summary-card.attack.good .summary-icon, .summary-card.attack.neutral .summary-icon { color: #1675dc; background: #e6f1ff; }
.summary-card.good .summary-icon {
  background: #dcf8e9;
  color: #08ad5b;
}
.summary-card.danger .summary-icon {
  background: #ffe8e5;
  color: #f04438;
}
.summary-card small {
  display: block;
  color: #53647a;
  font-size: 14px;
}
.summary-card strong {
  display: block;
  margin: 5px 0 4px;
  font-size: 30px;
  line-height: 1;
  color: #11223a;
}
.summary-card.good:first-child strong {
  font-size: 26px;
  color: #08a858;
}
.summary-card p {
  margin: 0;
  color: #7a899a;
  font-size: 12px;
}
.security-dashboard {
  display: grid;
  grid-template-columns: 1.33fr 1.12fr 1fr;
  gap: 14px;
}
.dashboard-card {
  min-width: 0;
  overflow: hidden;
}
.dashboard-card header {
  height: 48px;
  padding: 0 16px;
  border-bottom: 1px solid #e7edf2;
  display: flex;
  align-items: center;
  justify-content: space-between;
}
.dashboard-card header h2 {
  margin: 0;
  font-size: 16px;
}
.dashboard-card header button {
  border: 0;
  background: none;
  color: #08a858;
  cursor: pointer;
}
.dashboard-card header span {
  color: #7b8998;
  font-size: 12px;
}
.security-login-scope { margin: 0 0 12px; color: #63748c; font-size: 12px; }
.security-login-history { max-height: 430px; overflow: auto; border: 1px solid #e5edf4; border-radius: 6px; }
.security-login-history article { display: flex; justify-content: space-between; align-items: center; gap: 14px; padding: 9px 12px; border-bottom: 1px solid #edf1f6; }
.security-login-history article:last-child { border-bottom: 0; }
.security-login-history article span { display: grid; min-width: 0; gap: 3px; }
.security-login-history article strong { color: #263955; font-size: 13px; }
.security-login-history article small { overflow: hidden; text-overflow: ellipsis; white-space: nowrap; color: #71819a; }
.security-login-history article b { flex: none; font-size: 12px; }
.security-header-actions { display: inline-flex; align-items: center; gap: 12px; }
.security-complete-list { max-height: 430px; overflow: auto; border: 1px solid #e5edf4; border-radius: 6px; }
.security-complete-list article { display: flex; justify-content: space-between; align-items: center; gap: 14px; min-height: 48px; padding: 8px 12px; border-bottom: 1px solid #edf1f6; }
.security-complete-list article:last-child { border-bottom: 0; }
.security-complete-list article span { display: grid; gap: 3px; min-width: 0; }
.security-complete-list article strong { overflow: hidden; text-overflow: ellipsis; white-space: nowrap; color: #263955; font-size: 13px; }
.security-complete-list article small { color: #71819a; font-size: 11px; }
.security-list-pagination { justify-content: flex-end; margin-top: 12px; }
.security-all-suggestions { max-height: 430px; overflow: auto; margin: 0; padding: 0 8px; list-style: none; }
.audit-card {
  grid-column: span 2;
}
.security-alert-list { padding: 0 12px; }
.security-alert-list > div { min-height: 45px; padding: 7px 0; border-bottom: 1px solid #edf1f4; display: flex; align-items: center; gap: 8px; }
.security-alert-list > div:last-child { border-bottom: 0; }
.security-alert-list i { width: 20px; height: 20px; flex: none; display: grid; place-items: center; border-radius: 50%; background: #fff0e6; color: #f79009; font-style: normal; font-size: 12px; font-weight: 700; }
.security-alert-list .danger i { background: #ffe8e5; color: #f04438; }
.security-alert-list span { min-width: 0; flex: 1; }
.security-alert-list b,.security-alert-list small { display: block; overflow: hidden; white-space: nowrap; text-overflow: ellipsis; }
.security-alert-list b { color: #344a68; font-size: 11px; font-weight: 600; }
.security-alert-list small { margin-top: 3px; color: #8090a5; font-size: 10px; }
.security-alert-list time { color: #8090a5; font-size: 9px; white-space: nowrap; }
.scan-detail-button { border: 1px solid #d9e7df; border-radius: 4px; padding: 3px 9px; color: #079b4e; background: #fff; cursor: pointer; }
.scan-note { margin: 9px 12px; color: #8796a9; font-size: 10px; }
.scan-dialog-note { margin: 0 0 12px; color: #64758e; font-size: 12px; line-height: 1.5; }
.compact-table {
  width: 100%;
  border-collapse: collapse;
  font-size: 12px;
}
.compact-table th {
  height: 34px;
  text-align: left;
  background: #f4f7fa;
  color: #66778a;
  font-weight: 600;
}
.compact-table th,
.compact-table td {
  padding: 0 12px;
  border-bottom: 1px solid #e9eef2;
  white-space: nowrap;
  overflow: hidden;
  text-overflow: ellipsis;
  max-width: 190px;
}
.compact-table td {
  height: 37px;
  color: #32465f;
}
.compact-table tr:last-child td {
  border-bottom: 0;
}
.ok {
  color: #08ad5b !important;
}
.bad {
  color: #f04438 !important;
}
.warn {
  color: #f79009 !important;
}
.empty-cell {
  text-align: center;
  color: #8d99a7 !important;
}
.empty-panel {
  height: 150px;
  display: grid;
  place-content: center;
  text-align: center;
  color: #7b8998;
}
.empty-panel b {
  color: #53647a;
}
.empty-panel p {
  margin: 7px 0 0;
  font-size: 12px;
}
.key-values {
  margin: 0;
  padding: 6px 16px 10px;
}
.key-values div {
  height: 35px;
  border-bottom: 1px solid #edf1f4;
  display: flex;
  align-items: center;
  justify-content: space-between;
}
.key-values div:last-child {
  border: 0;
}
.key-values dt {
  color: #66778a;
}
.key-values dd {
  margin: 0;
  color: #20354f;
  font-weight: 600;
}
.suggestions {
  list-style: none;
  margin: 0;
  padding: 4px 16px 10px;
}
.suggestions li {
  min-height: 32px;
  border-bottom: 1px solid #edf1f4;
  display: flex;
  align-items: center;
  gap: 9px;
  font-size: 12px;
}
.suggestions i {
  display: grid;
  place-items: center;
  width: 22px;
  height: 22px;
  border-radius: 50%;
  background: #fff1dc;
  color: #f79009;
  font-style: normal;
  font-weight: 700;
}
.security-heading {
  display: flex;
  justify-content: space-between;
  gap: 20px;
  align-items: center;
  margin-bottom: 14px;
}
.security-heading p {
  margin: 0;
  color: #68798c;
}
.policy-row {
  display: flex;
  gap: 16px;
  align-items: center;
  margin: 18px 0;
}
.policy-row > .el-button {
  margin-left: auto;
}
.rule-list {
  display: grid;
  gap: 10px;
  max-height: 44vh;
  overflow: auto;
}
.empty-rules {
  padding: 28px;
  text-align: center;
  border: 1px dashed #cfdbd4;
  border-radius: 7px;
  color: #89958f;
}
.rule-row {
  display: grid;
  grid-template-columns:
    auto minmax(110px, 1fr) 90px minmax(140px, 1.2fr)
    minmax(220px, 1.4fr) 90px auto;
  align-items: center;
  gap: 9px;
  padding: 10px;
  background: #f7f9f8;
  border-radius: 7px;
}
.port-range {
  display: flex;
  align-items: center;
  gap: 6px;
}
.port-range :deep(.el-input-number) {
  width: 104px;
}
.preview-note {
  color: #75817c;
  font-size: 13px;
}
.security-preview {
  max-height: 55vh;
  overflow: auto;
  padding: 16px;
  border-radius: 7px;
  background: #13201c;
  color: #dce8e3;
  font:
    12px/1.65 ui-monospace,
    SFMono-Regular,
    Menlo,
    monospace;
  white-space: pre-wrap;
}
@media (max-width: 1280px) {
  .security-summary {
    grid-template-columns: 1fr 1fr;
  }
  .security-dashboard {
    grid-template-columns: 1fr 1fr;
  }
  .audit-card {
    grid-column: span 2;
  }
}
@media (max-width: 720px) {
  .security-summary,
  .security-dashboard {
    grid-template-columns: 1fr;
  }
  .audit-card {
    grid-column: auto;
  }
  .summary-card {
    min-height: 104px;
  }
  .security-heading {
    align-items: flex-start;
    flex-direction: column;
  }
  .policy-row {
    flex-wrap: wrap;
  }
  .policy-row > .el-button {
    margin-left: 0;
  }
  .rule-row {
    grid-template-columns: auto 1fr;
  }
  .rule-row > * {
    grid-column: 2;
  }
  .rule-row > .el-switch {
    grid-column: 1;
  }
  .port-range {
    flex-wrap: wrap;
  }
  .compact-table {
    min-width: 620px;
  }
  .dashboard-card {
    overflow: auto;
  }
}
</style>
