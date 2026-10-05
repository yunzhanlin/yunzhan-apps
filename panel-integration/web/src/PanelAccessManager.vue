<script setup lang="ts">
import { panelTimeZone, setPanelTimeZone } from "./panelTime";
import { computed, onBeforeUnmount, onMounted, ref } from "vue";
import { ElMessage } from "element-plus";
import { BellFilled, Lock, Monitor, Setting, UserFilled } from "@element-plus/icons-vue";

interface PanelAccess {
  domain: string;
  port: number;
  certificate_id: string;
  allowed_cidrs: string[];
  https_enabled: boolean;
  http_enabled: boolean;
  http_ip: string;
  http_port: number;
  http_entry: string;
  revision: number;
  updated_at: string;
}
interface Certificate {
  id: string;
  name: string;
  domains: string[];
  not_after: string;
  trusted: boolean;
  status: string;
}
interface Preview {
  status: string;
  config: string;
}
interface NotificationSummary {
  notifications: { id: string; read_at?: number }[];
  unread: number;
}
interface NotificationSettings {
  schedule_failures: boolean;
  remote_failures: boolean;
  monitor_alerts: boolean;
  retention_days: number;
  revision: number;
  updated_at: string;
}
interface AccountState { username: string; email: string; totp_enabled: boolean; recovery_remaining: number; server_time: string }
interface SessionPolicy { idle_minutes: number; revision: number; updated_at: string }
const props = defineProps<{
  api: <T>(path: string, method?: string, body?: unknown) => Promise<T>;
  theme: "light" | "dark";
  sidebarStyle: "default" | "compact";
  displayDensity: "comfortable" | "compact";
  onSession: (value: { username: string; csrf: string }) => void;
  onBusy: (busy: boolean) => void;
}>();
const emit = defineEmits<{ tab: [value: string]; theme: [value: "light" | "dark"]; sidebarStyle: [value: "default" | "compact"]; displayDensity: [value: "comfortable" | "compact"] }>();
const state = ref<PanelAccess | null>(null),
  certificates = ref<Certificate[]>([]),
  loading = ref(false),
  saving = ref(false),
  error = ref(""),
  cidrs = ref(""),
  preview = ref(""),
  previewOpen = ref(false),
  accessAdvancedOpen = ref(false),
  httpEntryOpen = ref(false),
  notificationSummary = ref<NotificationSummary>({ notifications: [], unread: 0 }),
  notificationOpen = ref(false),
  account = ref<AccountState | null>(null),
  accountEmail = ref(""),
  accountPassword = ref(""),
  accountNewPassword = ref(""),
  accountRepeatPassword = ref(""),
  accountCode = ref(""),
  accountSaving = ref(false),
  notificationSaving = ref(false),
  notificationDraft = ref<NotificationSettings>({ schedule_failures: true, remote_failures: true, monitor_alerts: true, retention_days: 90, revision: 1, updated_at: "" }),
  notificationSettings = ref<NotificationSettings>({ schedule_failures: true, remote_failures: true, monitor_alerts: true, retention_days: 90, revision: 1, updated_at: "" });
const sessionPolicy = ref<SessionPolicy | null>(null),
  sessionIdleMinutes = ref(30),
  sessionPolicySaving = ref(false);
const sessionIdleValid = computed(() => Number.isInteger(sessionIdleMinutes.value) && sessionIdleMinutes.value >= 5 && sessionIdleMinutes.value <= 240);
const enabledNotificationKinds = computed(() =>
  [notificationSettings.value.schedule_failures, notificationSettings.value.remote_failures, notificationSettings.value.monitor_alerts].filter(Boolean).length,
);
const browserTimeZone = Intl.DateTimeFormat().resolvedOptions().timeZone;
const timeZoneOptions = [
  { value: "Asia/Shanghai", label: "(UTC+08:00) 北京、重庆、香港、新加坡" },
  { value: "UTC", label: "(UTC+00:00) 协调世界时" },
  { value: "Asia/Tokyo", label: "(UTC+09:00) 东京" },
  { value: "Europe/London", label: "伦敦" },
  { value: "America/Los_Angeles", label: "洛杉矶" },
];
if (browserTimeZone && !timeZoneOptions.some(item => item.value === browserTimeZone))
  timeZoneOptions.push({ value: browserTimeZone, label: `浏览器时区：${browserTimeZone}` });
const draft = ref<PanelAccess>({
  domain: "panel.localhost",
  port: 19443,
  certificate_id: "",
  allowed_cidrs: [],
  https_enabled: false,
  http_enabled: false,
  http_ip: "",
  http_port: 27727,
  http_entry: "",
  revision: 1,
  updated_at: "",
});
function body() {
  return {
    ...draft.value,
    allowed_cidrs: cidrs.value
      .split(/\r?\n|,/)
      .map((item) => item.trim())
      .filter(Boolean),
  };
}
function generateHTTPEntry() {
  const alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789";
  const ceiling = Math.floor(256 / alphabet.length) * alphabet.length;
  let entry = "";
  while (entry.length < 10) {
    const bytes = crypto.getRandomValues(new Uint8Array(16));
    for (const byte of bytes) {
      if (byte < ceiling) entry += alphabet[byte % alphabet.length];
      if (entry.length === 10) break;
    }
  }
  draft.value.http_entry = entry;
}
const publicHTTPURL = computed(() => state.value?.http_enabled
  ? `http://${state.value.http_ip}:${state.value.http_port}/${state.value.http_entry}/` : "");
async function copyPublicHTTPURL() {
  if (!publicHTTPURL.value) return;
  try {
    if (!navigator.clipboard?.writeText) throw new Error("clipboard unavailable");
    await navigator.clipboard.writeText(publicHTTPURL.value);
  } catch {
    // Public IP + HTTP is not a secure context, so the Clipboard API may be unavailable.
    const input = document.createElement("textarea");
    input.value = publicHTTPURL.value;
    input.style.position = "fixed";
    input.style.opacity = "0";
    document.body.appendChild(input);
    input.select();
    let copied = false;
    try { copied = document.execCommand("copy"); }
    catch { /* Browser declined legacy clipboard access. */ }
    finally { input.remove(); }
    if (!copied) {
      ElMessage.warning("浏览器未允许复制，请选择入口地址手动复制");
      return;
    }
  }
  ElMessage.success("面板入口已复制");
}
function load(value: PanelAccess) {
  state.value = value;
  draft.value = { ...value, http_port: value.http_port || 27727, allowed_cidrs: [...value.allowed_cidrs] };
  cidrs.value = value.allowed_cidrs.join("\n");
}
async function refresh() {
  if (loading.value) return;
  loading.value = true;
  error.value = "";
  try {
    const [access, list, notice, noticeSettings, accountState, policy] = await Promise.all([
      props.api<PanelAccess>("/panel-access"),
      props.api<Certificate[]>("/certificates"),
      props.api<NotificationSummary>("/notifications?limit=100"),
      props.api<NotificationSettings>("/notification-settings"),
      props.api<AccountState>("/account"),
      props.api<SessionPolicy>("/session-policy"),
    ]);
    certificates.value = list;
    notificationSummary.value = notice;
    notificationSettings.value = noticeSettings;
    account.value = accountState;
    accountEmail.value = accountState.email || "";
    sessionPolicy.value = policy;
    sessionIdleMinutes.value = policy.idle_minutes;
    load(access);
  } catch (e) {
    error.value = (e as Error).message;
  } finally {
    loading.value = false;
  }
}
async function saveAccountProfile() {
  if (accountSaving.value) return;
  const changingPassword = !!accountNewPassword.value;
  if (!accountPassword.value || (!changingPassword && accountEmail.value.trim() === (account.value?.email || "")) || (changingPassword && (accountNewPassword.value.length < 12 || accountNewPassword.value !== accountRepeatPassword.value))) {
    ElMessage.error("请填写当前密码；修改密码时新密码至少 12 字符且两次输入一致");
    return;
  }
  accountSaving.value = true;
  props.onBusy(true);
  try {
    const result = await props.api<{ username: string; csrf: string }>("/account/profile", "POST", {
      password: accountPassword.value,
      new_password: accountNewPassword.value,
      email: accountEmail.value.trim(),
      code: accountCode.value,
    });
    props.onSession(result);
    accountPassword.value = "";
    accountNewPassword.value = "";
    accountRepeatPassword.value = "";
    accountCode.value = "";
    ElMessage.success(changingPassword ? "账户资料与密码已更新，其他会话已撤销" : "账户邮箱已保存，其他会话已撤销");
    await refresh();
  } catch (e) {
    ElMessage.error((e as Error).message);
  } finally {
    accountSaving.value = false;
    props.onBusy(false);
  }
}
async function saveNotificationSettings() {
  if (notificationSaving.value) return;
  notificationSaving.value = true;
  try {
    notificationSettings.value = await props.api<NotificationSettings>("/notification-settings", "PUT", notificationDraft.value);
    notificationOpen.value = false;
    ElMessage.success("通知策略已保存");
  } catch (e) {
    ElMessage.error((e as Error).message);
  } finally {
    notificationSaving.value = false;
  }
}
async function saveSessionPolicy() {
  if (!sessionPolicy.value || sessionPolicySaving.value || !sessionIdleValid.value) return;
  sessionPolicySaving.value = true;
  try {
    const updated = await props.api<SessionPolicy>("/session-policy", "PUT", {
      idle_minutes: sessionIdleMinutes.value,
      revision: sessionPolicy.value.revision,
    });
    sessionPolicy.value = updated;
    sessionIdleMinutes.value = updated.idle_minutes;
    ElMessage.success("会话空闲超时已保存");
  } catch (e) {
    ElMessage.error((e as Error).message);
  } finally {
    sessionPolicySaving.value = false;
  }
}
async function setNotificationKind(kind: "schedule_failures" | "remote_failures" | "monitor_alerts", enabled: boolean) {
  if (notificationSaving.value) return;
  notificationSaving.value = true;
  try {
    notificationSettings.value = await props.api<NotificationSettings>("/notification-settings", "PUT", { ...notificationSettings.value, [kind]: enabled });
    ElMessage.success("通知策略已保存");
  } catch (e) {
    ElMessage.error((e as Error).message);
  } finally {
    notificationSaving.value = false;
  }
}
function openNotificationSettings() {
  notificationDraft.value = { ...notificationSettings.value };
  notificationOpen.value = true;
}
async function readAllNotifications() {
  try {
    await props.api("/notifications/read-all", "POST", {});
    notificationSummary.value.unread = 0;
    ElMessage.success("全部站内通知已标为已读");
  } catch (e) {
    ElMessage.error((e as Error).message);
  }
}
async function showPreview() {
  try {
    const result = await props.api<Preview>(
      "/panel-access/preview",
      "POST",
      body(),
    );
    preview.value = result.config;
    previewOpen.value = true;
  } catch (e) {
    ElMessage.error((e as Error).message);
  }
}
async function save() {
  if (saving.value) return;
  saving.value = true;
  try {
    const updated = await props.api<PanelAccess>(
      "/panel-access",
      "PUT",
      body(),
    );
    load(updated);
    ElMessage.success(
      updated.https_enabled || updated.http_enabled
        ? "管理入口已验证并生效"
        : "面板访问设置已保存；公网入口当前未启用",
    );
  } catch (e) {
    ElMessage.error((e as Error).message);
  } finally {
    saving.value = false;
  }
}
defineExpose({ refresh });
onMounted(refresh);
onBeforeUnmount(() => { accountPassword.value = ""; accountNewPassword.value = ""; accountRepeatPassword.value = ""; accountCode.value = ""; props.onBusy(false); });
</script>

<template>
  <div class="access-page" v-loading="loading">
    <el-alert v-if="error" :title="error" type="error" :closable="false" />
    <section class="access-reference-grid">
      <article class="panel-card access-config">
        <div class="reference-card-title">
          <div class="title-icon"><el-icon><Setting /></el-icon></div>
          <div>
            <h2>基本设置</h2>
            <p>配置面板的基础运行参数</p>
          </div>
        </div>
        <el-form
          label-position="left"
          label-width="110px"
          class="access-form compact-access-form"
          @submit.prevent="save"
        >
          <el-form-item label="面板端口"><el-input-number v-model="draft.port" :min="1024" :max="65535" controls-position="right" aria-label="面板 HTTPS 端口" /><div class="form-help">独立 HTTPS 入口仅监听本机；救援 HTTP 固定使用 19100 端口</div></el-form-item>
          <el-form-item label="面板地址"><el-input model-value="127.0.0.1（本机代理）" readonly aria-label="面板监听地址" /><div class="form-help">公网访问由 Nginx 管理入口提供</div></el-form-item>
          <el-form-item label="面板域名" required>
            <el-input
              v-model="draft.domain"
              aria-label="管理域名"
              maxlength="253"
              placeholder="panel.example.com"
            />
          </el-form-item>
          <el-form-item label="默认语言"><el-input model-value="简体中文" readonly aria-label="默认语言" /></el-form-item>
          <el-form-item label="时区设置"><el-select :model-value="panelTimeZone" aria-label="界面时区" @change="setPanelTimeZone"><el-option v-for="item in timeZoneOptions" :key="item.value" :value="item.value" :label="item.label" /></el-select><div class="form-help">只改变当前浏览器的时间显示，不改变服务器或计划任务时区</div></el-form-item>
        </el-form>
        <details class="access-advanced" :open="accessAdvancedOpen" @toggle="accessAdvancedOpen = ($event.target as HTMLDetailsElement).open">
          <summary>HTTPS 与访问控制 <span>{{ state?.https_enabled ? '已启用' : '未启用' }}</span></summary>
          <div class="setting-line"><span>启用管理入口 HTTPS</span><el-switch v-model="draft.https_enabled" aria-label="启用面板 HTTPS" /></div>
          <el-form label-position="left" label-width="96px" class="access-form compact-access-form">
            <el-form-item label="HTTPS 证书" :required="draft.https_enabled">
            <el-select
              v-model="draft.certificate_id"
              aria-label="管理入口证书"
              placeholder="选择已上传证书"
              clearable
              :disabled="!draft.https_enabled"
            >
              <el-option
                v-for="item in certificates"
                :key="item.id"
                :label="`${item.name} · ${item.domains.join(', ')}`"
                :value="item.id"
                :disabled="item.status !== 'valid'"
              />
            </el-select>
            </el-form-item>
            <el-form-item label="允许访问 IP">
            <el-input
              v-model="cidrs"
              aria-label="允许访问的 IP 网段"
              type="textarea"
              :rows="2"
              maxlength="800"
              placeholder="每行一条 CIDR；留空允许全部地址"
            />
            </el-form-item>
          </el-form>
        </details>
        <details class="access-advanced" :open="httpEntryOpen" @toggle="httpEntryOpen = ($event.target as HTMLDetailsElement).open">
          <summary class="http-entry-summary">
            <span class="http-entry-title">公网 HTTP 安全入口</span>
            <code v-if="publicHTTPURL" class="http-entry-url" :title="publicHTTPURL">{{ publicHTTPURL }}</code>
            <span v-else class="http-entry-disabled">未启用</span>
            <button v-if="publicHTTPURL" type="button" class="http-entry-copy" aria-label="复制公网面板入口" @click.stop.prevent="copyPublicHTTPURL">复制</button>
          </summary>
          <div class="setting-line"><span>启用 IP + 端口 + 安全路径</span><el-switch v-model="draft.http_enabled" aria-label="启用公网 HTTP 入口" /></div>
          <el-form label-position="left" label-width="96px" class="access-form compact-access-form">
            <el-form-item label="服务器 IP"><el-input v-model="draft.http_ip" aria-label="公网入口 IPv4" placeholder="192.0.2.10" :disabled="!draft.http_enabled" /></el-form-item>
            <el-form-item label="访问端口"><el-input-number v-model="draft.http_port" :min="1024" :max="65535" aria-label="公网 HTTP 端口" :disabled="!draft.http_enabled" /></el-form-item>
            <el-form-item label="安全路径"><el-input v-model="draft.http_entry" aria-label="公网 HTTP 安全路径" placeholder="安装时自动生成 10 位" readonly /><el-button @click="generateHTTPEntry">重新生成</el-button></el-form-item>
            <el-form-item v-if="publicHTTPURL" label="当前生效入口"><el-input :model-value="publicHTTPURL" aria-label="当前生效公网入口" readonly /><el-button @click="copyPublicHTTPURL">复制入口</el-button></el-form-item>
          </el-form>
        </details>
        <div class="access-actions">
          <el-button type="primary" :loading="saving" :disabled="!draft.domain.trim() || (draft.https_enabled && !draft.certificate_id)" aria-label="保存并验证" @click="save">保存设置</el-button>
          <el-button aria-label="预览 Nginx 配置" @click="showPreview"
            >预览配置</el-button
          >
        </div>
      </article>

      <article class="panel-card account-preview-card">
        <div class="reference-card-title">
          <div class="title-icon account"><el-icon><UserFilled /></el-icon></div>
          <div>
            <h2>管理员账户</h2>
            <p>管理面板管理员账户信息</p>
          </div>
        </div>
        <div class="account-profile">
          <div class="account-avatar"><el-icon><UserFilled /></el-icon></div>
          <div>
            <h3>{{ account?.username || 'admin' }} <em>超级管理员</em></h3>
            <p>{{ account?.email || '本机管理员账户' }}</p>
            <small>{{ account?.totp_enabled ? '已开启双重验证' : '建议开启双重验证' }}</small>
          </div>
          <el-button @click="emit('tab', 'account')">账户管理</el-button>
        </div>
        <el-form class="account-password-form" label-position="left" label-width="94px" @submit.prevent="saveAccountProfile">
          <el-form-item label="用户名"><el-input :model-value="account?.username || 'admin'" readonly aria-label="管理员用户名" /></el-form-item>
          <el-form-item label="邮箱地址"><el-input v-model="accountEmail" type="email" maxlength="254" placeholder="admin@example.com" aria-label="管理员邮箱" /></el-form-item>
          <el-form-item label="当前密码"><el-input v-model="accountPassword" type="password" autocomplete="current-password" placeholder="保存时输入当前密码" aria-label="基本设置当前密码" /></el-form-item>
          <el-form-item label="新密码"><el-input v-model="accountNewPassword" type="password" autocomplete="new-password" placeholder="不修改请留空；至少 12 字符" aria-label="基本设置新密码" /></el-form-item>
          <el-form-item label="确认密码"><el-input v-model="accountRepeatPassword" type="password" autocomplete="new-password" placeholder="再次输入新密码" aria-label="基本设置确认密码" /></el-form-item>
          <el-form-item v-if="account?.totp_enabled" label="动态码"><el-input v-model="accountCode" autocomplete="one-time-code" placeholder="动态码或恢复码" aria-label="基本设置动态码" /></el-form-item>
        </el-form>
        <el-button type="primary" :loading="accountSaving" :disabled="!accountPassword || (!accountNewPassword && accountEmail.trim() === (account?.email || '')) || (!!accountNewPassword && (accountNewPassword.length < 12 || accountNewPassword !== accountRepeatPassword))" @click="saveAccountProfile">更新账户信息</el-button>
      </article>

      <article class="panel-card access-mini-card">
        <div class="reference-card-title">
          <div class="title-icon shield"><el-icon><Lock /></el-icon></div>
          <div>
            <h2>安全设置</h2>
            <p>增强面板安全性配置</p>
          </div>
        </div>
        <div class="setting-line setting-line-detailed">
          <span>登录验证</span>
          <button type="button" class="setting-status-action" aria-label="配置登录双重验证" @click="emit('tab', 'account')">
            <i :class="['setting-status-switch', { active: account?.totp_enabled }]" aria-hidden="true"></i>
            <span><b :class="{ ok: account?.totp_enabled }">{{ account?.totp_enabled ? '已开启' : '未开启' }}</b><small>使用动态码保护管理员登录</small></span>
          </button>
        </div>
        <div class="setting-line setting-line-detailed">
          <span>绑定访问 IP</span>
          <button type="button" class="setting-status-action" aria-label="配置面板允许访问的 IP 网段" @click="accessAdvancedOpen = true">
            <i :class="['setting-status-switch', { active: !!state?.allowed_cidrs.length }]" aria-hidden="true"></i>
            <span><b :class="{ ok: !!state?.allowed_cidrs.length }">{{ state?.allowed_cidrs.length ? `${state.allowed_cidrs.length} 条网段` : '未限制' }}</b><small>在上方设置允许访问的网段</small></span>
          </button>
        </div>
        <div class="setting-line setting-line-detailed">
          <span>会话超时</span><span class="setting-timeout-control"><input v-model.number="sessionIdleMinutes" class="setting-timeout-input" type="number" min="5" max="240" step="1" :disabled="!sessionPolicy || sessionPolicySaving" aria-label="会话空闲超时分钟" /><b>分钟</b><small>无操作后退出；最长有效期 12 小时</small></span>
        </div>
        <button class="card-action" :disabled="!sessionPolicy || sessionPolicySaving || !sessionIdleValid || sessionIdleMinutes === sessionPolicy.idle_minutes" @click="saveSessionPolicy">
          保存安全设置
        </button>
      </article>
      <article class="panel-card access-mini-card">
        <div class="reference-card-title">
          <div class="title-icon notice"><el-icon><BellFilled /></el-icon></div>
          <div>
            <h2>通知设置</h2>
            <p>配置系统通知和告警方式</p>
          </div>
        </div>
        <div class="setting-line setting-line-detailed">
          <span>任务失败通知</span><span class="setting-control"><el-switch :model-value="notificationSettings.schedule_failures" :loading="notificationSaving" aria-label="任务失败通知" @change="setNotificationKind('schedule_failures', !!$event)" /><span><b :class="{ ok: notificationSettings.schedule_failures }">{{ notificationSettings.schedule_failures ? '已开启' : '已关闭' }}</b><small>计划任务执行失败时记录通知</small></span></span>
        </div>
        <div class="setting-line setting-line-detailed">
          <span>资源异常告警</span><span class="setting-control"><el-switch :model-value="notificationSettings.monitor_alerts" :loading="notificationSaving" aria-label="资源异常告警" @change="setNotificationKind('monitor_alerts', !!$event)" /><span><b :class="{ ok: notificationSettings.monitor_alerts }">{{ notificationSettings.monitor_alerts ? '已开启' : '已关闭' }}</b><small>资源进入告警状态时记录通知</small></span></span>
        </div>
        <div class="setting-line setting-line-detailed"><span>远端备份失败</span><span class="setting-control"><el-switch :model-value="notificationSettings.remote_failures" :loading="notificationSaving" aria-label="远端备份失败通知" @change="setNotificationKind('remote_failures', !!$event)" /><span><b :class="{ ok: notificationSettings.remote_failures }">{{ notificationSettings.remote_failures ? '已开启' : '已关闭' }}</b><small>{{ enabledNotificationKinds }} 类事件 · {{ notificationSummary.unread }} 条未读</small></span></span></div>
        <button class="card-action" @click="openNotificationSettings">
          配置通知策略
        </button>
      </article>
      <article class="panel-card access-mini-card">
        <div class="reference-card-title">
          <div class="title-icon theme"><el-icon><Monitor /></el-icon></div>
          <div>
            <h2>主题与显示</h2>
            <p>自定义面板外观显示</p>
          </div>
        </div>
        <div class="mini-theme-preview">
          <button type="button" :class="['theme-choice', 'light', { active: props.theme === 'light' }]" :aria-pressed="props.theme === 'light'" aria-label="切换浅色主题" @click="emit('theme', 'light')"><span class="theme-mini-screen"><i class="theme-mini-sidebar"></i><i class="theme-mini-toolbar"></i><i class="theme-mini-card first"></i><i class="theme-mini-card second"></i></span><small>◉ 浅色主题</small></button>
          <button type="button" :class="['theme-choice', 'dark', { active: props.theme === 'dark' }]" :aria-pressed="props.theme === 'dark'" aria-label="切换深色主题" @click="emit('theme', 'dark')"><span class="theme-mini-screen"><i class="theme-mini-sidebar"></i><i class="theme-mini-toolbar"></i><i class="theme-mini-card first"></i><i class="theme-mini-card second"></i></span><small>◉ 深色主题</small></button>
        </div>
        <div class="setting-line theme-option-line"><span>侧边栏样式</span><el-select :model-value="props.sidebarStyle" aria-label="侧边栏样式" @change="emit('sidebarStyle', $event)"><el-option value="default" label="默认样式"/><el-option value="compact" label="紧凑图标栏"/></el-select></div>
        <div class="setting-line theme-option-line"><span>显示密度</span><el-select :model-value="props.displayDensity" aria-label="显示密度" @change="emit('displayDensity', $event)"><el-option value="comfortable" label="舒适（推荐）"/><el-option value="compact" label="紧凑"/></el-select></div>
        <button class="card-action" @click="emit('tab', 'theme')">
          显示设置
        </button>
      </article>
    </section>

    <el-dialog v-model="previewOpen" title="面板入口配置预览" width="720px">
      <p class="preview-note">预览只展示候选配置，不会修改当前入口。</p>
      <pre class="config-preview">{{ preview }}</pre>
      <template #footer>
        <el-button type="primary" @click="previewOpen = false"
          >我已检查</el-button
        >
      </template>
    </el-dialog>
    <el-dialog v-model="notificationOpen" title="通知设置" width="520px">
      <div class="notification-policy-list">
        <div><span><strong>计划任务失败</strong><small>脚本、备份或维护任务失败时记录</small></span><el-switch v-model="notificationDraft.schedule_failures" aria-label="记录计划任务失败" /></div>
        <div><span><strong>远端备份失败</strong><small>WebDAV 有界重试耗尽后记录</small></span><el-switch v-model="notificationDraft.remote_failures" aria-label="记录远端备份失败" /></div>
        <div><span><strong>资源告警</strong><small>CPU、内存、磁盘或服务进入告警时记录</small></span><el-switch v-model="notificationDraft.monitor_alerts" aria-label="记录资源告警" /></div>
      </div>
      <el-form-item label="已读通知保留天数">
        <el-input-number v-model="notificationDraft.retention_days" :min="7" :max="365" />
      </el-form-item>
      <template #footer>
        <el-button @click="notificationOpen = false">取消</el-button>
        <el-button v-if="notificationSummary.unread" @click="readAllNotifications">全部标为已读</el-button>
        <el-button type="primary" :loading="notificationSaving" @click="saveNotificationSettings">保存设置</el-button>
      </template>
    </el-dialog>
  </div>
</template>

<style scoped>
.access-page {
  display: grid;
  gap: 14px;
}
.notification-policy-list {
  display: grid;
  margin-bottom: 18px;
  border: 1px solid #e7ecef;
  border-radius: 8px;
}
.notification-policy-list > div {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 18px;
  padding: 13px 14px;
  border-bottom: 1px solid #edf1f3;
}
.notification-policy-list > div:last-child { border-bottom: 0; }
.notification-policy-list strong,
.notification-policy-list small { display: block; }
.notification-policy-list small { margin-top: 4px; color: #8491a2; font-size: 11px; }
.access-reference-grid {
  display: grid;
  grid-template-columns: repeat(6, minmax(0, 1fr));
  gap: 14px;
}
.access-reference-grid > article {
  min-width: 0;
  overflow: hidden;
}
.access-reference-grid > article:nth-child(-n + 2) {
  min-height: 434px;
  grid-column: span 3;
}
.access-reference-grid > article:nth-child(n + 3) {
  min-height: 278px;
  grid-column: span 2;
}
.reference-card-title {
  min-height: 62px;
  display: flex;
  align-items: center;
  gap: 16px;
  padding: 0 18px;
  border-bottom: 1px solid #e9eef3;
}
.reference-card-title h2,
.reference-card-title p {
  margin: 0;
}
.reference-card-title h2 {
  color: #10213a;
  font-size: 15px;
}
.reference-card-title p {
  margin-top: 4px;
  color: #8391a4;
  font-size: 12px;
}
.title-icon {
  width: 34px;
  height: 34px;
  display: grid;
  place-items: center;
  border-radius: 0;
  background: transparent;
  color: #08ad5b;
  font-size: 30px;
  font-weight: 700;
}
.title-icon .el-icon { font-size: 30px; }
.title-icon.account {
  font-size: 30px;
}
.title-icon.shield {
  background: transparent;
}
.title-icon.notice {
  background: transparent;
  color: #ff5538;
}
.title-icon.theme {
  background: transparent;
}
.access-status-row {
  min-height: 58px;
  display: grid;
  grid-template-columns: auto 1fr auto;
  align-items: center;
  gap: 10px;
  margin: 10px 16px 0;
  padding: 8px 10px;
  border-radius: 6px;
  background: #f7faf8;
}
.access-status-row h3,
.access-status-row small {
  display: block;
}
.access-status-row h3 {
  margin: 0;
  color: #334a67;
  font-size: 12px;
}
.access-status-row small {
  margin-top: 3px;
  color: #8290a3;
  font-size: 9px;
  overflow-wrap: anywhere;
}
.access-status-row .status-icon {
  width: 32px;
  height: 32px;
  border-radius: 8px;
}
.access-status-row .status-icon span {
  width: 8px;
  height: 8px;
}
.compact-access-form {
  margin: 10px 16px 0 !important;
}
.compact-access-form :deep(.el-form-item) {
  margin-bottom: 10px;
}
.compact-access-form :deep(.el-form-item__label) {
  color: #435672;
  font-size: 11px;
}
.compact-access-form :deep(.el-input__wrapper),
.compact-access-form :deep(.el-select__wrapper) {
  min-height: 32px;
}
.compact-access-form :deep(.el-input-number) { width: 100%; }
.compact-access-form :deep(textarea) {
  min-height: 50px !important;
  font-size: 10px;
}
.compact-access-form :deep(.form-help) { width: 100%; color: #8391a4; font-size: 10px; line-height: 1.3; }
.access-advanced { margin: 0 16px; border-top: 1px solid #edf1f5; color: #52647e; font-size: 11px; }
.access-advanced summary { display: flex; justify-content: space-between; align-items: center; padding: 5px 0; cursor: pointer; list-style: none; }
.access-advanced summary::after { content: '⌄'; margin-left: 8px; }
.access-advanced[open] summary::after { content: '⌃'; }
.access-advanced summary span { margin-left: auto; color: #079b4e; }
.access-advanced .setting-line { margin: 0; }
.access-advanced .compact-access-form { margin: 10px 0 0 !important; }
.account-password-form { padding: 0 16px 4px; }
.account-password-form :deep(.el-form-item) { margin-bottom: 7px; }
.account-password-form :deep(.el-form-item__label) { color: #435672; font-size: 11px; }
.account-password-form :deep(.el-input__wrapper) { min-height: 31px; }
.access-advanced .http-entry-summary { gap: 7px; }
.http-entry-title { flex: 0 0 auto; }
.access-advanced .http-entry-url {
  min-width: 0;
  overflow: hidden;
  margin-left: auto;
  color: #078e4c;
  font-family: inherit;
  font-size: 10px;
  text-overflow: ellipsis;
  white-space: nowrap;
}
.access-advanced .http-entry-disabled { margin-left: auto; color: #8b98a9; }
.http-entry-copy { flex: 0 0 auto; padding: 2px 4px; color: #079b4e; font-size: 10px; font-weight: 600; }
.http-entry-copy:hover { text-decoration: underline; }
.access-advanced .http-entry-summary::after { flex: 0 0 auto; margin-left: 0; }
:global(html.dark) .access-advanced .http-entry-url { color: #50d58e; }
.account-profile {
  display: grid;
  grid-template-columns: auto 1fr auto;
  align-items: center;
  gap: 12px;
  padding: 18px 16px 12px;
}
.account-avatar {
  width: 56px;
  height: 56px;
  display: grid;
  place-items: center;
  border-radius: 50%;
  background: linear-gradient(160deg, #eaf1ff, #d8e3f8);
  color: #6d88bd;
  font-size: 24px;
}
.account-profile h3,
.account-profile p {
  margin: 0;
}
.account-profile h3 {
  color: #142541;
  font-size: 16px;
}
.account-profile h3 em {
  margin-left: 8px;
  padding: 3px 7px;
  border-radius: 4px;
  background: #daf7e6;
  color: #09a958;
  font-size: 9px;
  font-style: normal;
}
.account-profile p {
  margin-top: 5px;
  color: #536886;
  font-size: 11px;
}
.account-profile small {
  display: block;
  margin-top: 4px;
  color: #8b98a9;
  font-size: 9px;
}
.account-fields {
  display: grid;
  grid-template-columns: 95px 1fr;
  gap: 0;
  margin: 0 16px 12px;
  border: 1px solid #e8edf3;
  border-radius: 6px;
  overflow: hidden;
}
.account-fields dt,
.account-fields dd {
  min-height: 38px;
  display: flex;
  align-items: center;
  margin: 0;
  padding: 0 11px;
  border-bottom: 1px solid #edf1f5;
  color: #536681;
  font-size: 11px;
}
.account-fields dt {
  background: #f7f9fb;
  color: #425570;
}
.account-preview-card > .el-button {
  margin: 0 16px;
}
.access-mini-card .reference-card-title {
  min-height: 58px;
}
.setting-line {
  min-height: 40px;
  display: flex;
  align-items: center;
  justify-content: space-between;
  margin: 0 14px;
  border-bottom: 1px solid #edf1f5;
  color: #485d79;
  font-size: 12px;
}
.setting-line b {
  color: #6d7f96;
  font-weight: 500;
}
.setting-line b.ok {
  color: #09ad5a;
}
.setting-control { display: inline-flex; align-items: center; gap: 8px; }
.setting-line-detailed { min-height: 56px; justify-content: flex-start; gap: 10px; }
.setting-line-detailed > span:first-child { flex: 0 0 102px; }
.setting-line-detailed .setting-control { min-width: 0; }
.setting-line-detailed small,
.setting-status-action small,
.setting-readonly-value small { display: block; margin-top: 3px; color: #8898ac; font-size: 10px; line-height: 1.2; }
.setting-status-action { display: inline-flex; min-width: 0; align-items: center; gap: 10px; padding: 0; text-align: left; }
.setting-status-action:hover b { text-decoration: underline; }
.setting-status-switch { width: 38px; height: 21px; flex: 0 0 auto; border-radius: 12px; background: #b9c4d1; position: relative; }
.setting-status-switch::after { position: absolute; top: 2px; left: 2px; width: 17px; height: 17px; border-radius: 50%; background: white; content: ''; transition: transform .15s; }
.setting-status-switch.active { background: #08ad5b; }
.setting-status-switch.active::after { transform: translateX(17px); }
.setting-readonly-value { display: block; }
.setting-timeout-control { display: grid; grid-template-columns: minmax(0, 140px) auto; align-items: center; gap: 3px 8px; }
.setting-timeout-input { box-sizing: border-box; width: 140px; height: 33px; padding: 0 11px; border: 1px solid #dce4ec; border-radius: 5px; background: var(--panel-card, #fff); color: var(--panel-text, #152542); font: inherit; }
.setting-timeout-input:focus-visible { outline: 2px solid #20b571; outline-offset: 1px; }
.setting-timeout-input:disabled { background: #f3f6f9; color: #8390a3; }
.setting-timeout-control b { color: #65768d; }
.setting-timeout-control small { grid-column: 1 / -1; margin: 0; }
.card-action {
  height: 30px;
  margin: 12px 14px;
  padding: 0 12px;
  border: 1px solid #12af5f;
  border-radius: 5px;
  color: #0aa653;
  font-size: 12px;
}
.mini-theme-preview {
  display: flex;
  gap: 12px;
  padding: 14px 14px 4px;
}
.theme-choice { display: grid; gap: 5px; justify-items: center; padding: 0; color: #65758a; font-size: 10px; }
.theme-choice small { font-size: 10px; }
.theme-choice.active { color: #0aa85a; }
.theme-mini-screen { position: relative; width: 106px; height: 64px; display: block; overflow: hidden; border: 2px solid #dce4ed; border-radius: 5px; background: #f4f7fb; }
.theme-choice.active .theme-mini-screen { border-color: #0aae59; }
.theme-mini-screen i { position: absolute; display: block; }
.theme-mini-sidebar { inset: 0 auto 0 0; width: 24%; background: #172833; }
.theme-mini-toolbar { inset: 0 0 auto 24%; height: 12px; background: #fff; border-bottom: 1px solid #e7edf3; }
.theme-mini-card { top: 19px; height: 18px; border-radius: 2px; background: #fff; border: 1px solid #e8edf2; }
.theme-mini-card.first { left: 30%; width: 30%; }
.theme-mini-card.second { left: 65%; width: 29%; }
.theme-choice.dark .theme-mini-screen { background: #202c3a; }
.theme-choice.dark .theme-mini-toolbar { background: #263448; border-color: #354359; }
.theme-choice.dark .theme-mini-card { background: #314056; border-color: #394a61; }
.theme-option-line { min-height: 34px; border-bottom: 0; }
.theme-option-line .el-select { width: 58%; }
.theme-option-line :deep(.el-select__wrapper) { min-height: 28px; font-size: 10px; }
.access-summary {
  display: grid;
  grid-template-columns: 1.65fr repeat(3, minmax(0, 1fr));
  gap: 14px;
}
.access-summary article {
  min-height: 126px;
  padding: 20px 22px;
}
.access-state {
  display: grid;
  grid-template-columns: auto 1fr auto;
  align-items: center;
  gap: 16px;
}
.status-icon {
  display: grid;
  place-items: center;
  width: 46px;
  height: 46px;
  border-radius: 14px;
  background: #fff3df;
}
.status-icon span {
  width: 12px;
  height: 12px;
  border-radius: 50%;
  background: #d99429;
  box-shadow: 0 0 0 7px rgb(217 148 41 / 13%);
}
.status-icon.active {
  background: #e9f7f0;
}
.status-icon.active span {
  background: #28a46b;
  box-shadow: 0 0 0 7px rgb(40 164 107 / 13%);
}
.access-state small,
.summary-cell small {
  color: #78857f;
}
.access-state h2 {
  margin: 6px 0 3px;
  color: #203b34;
  font-size: 19px;
}
.access-state p {
  margin: 0;
  color: #7b8782;
  font-size: 12px;
  word-break: break-all;
}
.summary-cell {
  display: flex;
  flex-direction: column;
  justify-content: center;
}
.summary-cell strong {
  margin: 8px 0 5px;
  color: #203b34;
  font-size: 21px;
  word-break: break-all;
}
.summary-cell span {
  color: #8a9691;
  font-size: 12px;
}
.access-config {
  padding: 0;
}
.config-heading {
  display: flex;
  justify-content: space-between;
  align-items: flex-start;
  gap: 24px;
  margin-bottom: 18px;
}
.config-heading h2 {
  margin: 0;
  color: #203b34;
  font-size: 18px;
}
.config-heading p {
  margin: 7px 0 0;
  color: #77847e;
  font-size: 13px;
  line-height: 1.65;
}
.access-form {
  margin-top: 20px;
}
.form-grid {
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: 18px;
}
.access-form small {
  display: block;
  width: 100%;
  margin-top: 6px;
  color: #7d8984;
  line-height: 1.5;
}
.access-form :deep(.el-select) {
  width: 100%;
}
.access-actions {
  display: flex;
  justify-content: flex-start;
  gap: 10px;
  padding: 6px 16px 10px;
}
.preview-note {
  margin: -4px 0 12px;
  color: #75817c;
  font-size: 13px;
}
.config-preview {
  max-height: 55vh;
  overflow: auto;
  margin: 0;
  padding: 16px;
  border-radius: 10px;
  background: #13201c;
  color: #dce8e3;
  font:
    12px/1.65 ui-monospace,
    SFMono-Regular,
    Menlo,
    monospace;
  white-space: pre-wrap;
}
@media (max-width: 1080px) {
  .access-reference-grid > article:nth-child(-n + 2),
  .access-reference-grid > article:nth-child(n + 3) {
    grid-column: span 6;
  }
  .access-summary {
    grid-template-columns: 1fr 1fr;
  }
}
@media (max-width: 720px) {
  .access-summary,
  .form-grid {
    grid-template-columns: 1fr;
  }
  .access-state {
    grid-template-columns: auto 1fr;
  }
  .access-state .el-tag {
    grid-column: 2;
    justify-self: start;
  }
  .config-heading {
    flex-direction: column;
  }
  .access-actions {
    flex-direction: column-reverse;
  }
  .access-actions .el-button {
    width: 100%;
    margin: 0;
  }
  .access-config {
    padding: 18px;
  }
}
</style>
