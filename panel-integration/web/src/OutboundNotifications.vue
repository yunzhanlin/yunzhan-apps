<script setup lang="ts">
import { onBeforeUnmount, onMounted, ref } from "vue";
import { ElMessage } from "element-plus";
import { formatPanelDateTime } from "./panelTime";
interface SMTPPublic { host: string; port: number; tls_mode: string; server_name: string; ca_pem: string; auth_mode: string; username_set: boolean; password_set: boolean; from: string; to: string[] }
interface Channel { id: string; name: string; endpoint_host: string; enabled: boolean; kinds: string[]; revision: number; secret_set: boolean; updated_at: string; type: string; smtp?: SMTPPublic; credential_error?: string }
interface Delivery { id: string; event_id: string; state: string; attempts: number; http_status: number; error: string; created_at: number; completed_at: number }
const props = defineProps<{ api: <T>(path: string, method?: string, body?: unknown) => Promise<T> }>();
const kinds = [{ id: "integrity", label: "文件监控与防篡改" }, { id: "php-security", label: "PHP 风险审查与隔离恢复" }, { id: "sync", label: "文件同步冲突与失败" }, { id: "daily", label: "每日运维报告" }, { id: "schedule", label: "计划任务失败" }, { id: "remote", label: "远端备份失败" }, { id: "monitor", label: "资源告警" }];
const states: Record<string, string> = { pending: "等待发送 / 重试", running: "发送中", succeeded: "接收端已接收", failed: "失败，需处理", cancelled: "配置变更，已取消" };
const channels = ref<Channel[]>([]), deliveries = ref<Delivery[]>([]);
const loading = ref(false), saving = ref(false), historyLoading = ref(false), busyID = ref("");
const error = ref(""), workerError = ref(""), workerCheckedAt = ref("");
const editor = ref(false), history = ref(false), selected = ref<Channel | null>(null);
const draft = ref({ id: "", type: "webhook", name: "", url: "", secret: "", enabled: true, kinds: ["integrity", "sync", "daily"], revision: 0 });
const emptySMTP = () => ({ host: "", port: 587, tls_mode: "starttls", server_name: "", ca_pem: "", auth_mode: "plain", username: "", password: "", from: "", recipients: "" });
const smtpDraft = ref(emptySMTP());
let mounted = true, interval: ReturnType<typeof setInterval> | undefined;
const time = (value: number | string) => formatPanelDateTime(typeof value === "number" ? value * 1000 : value);
const kindLabel = (id: string) => kinds.find(k => k.id === id)?.label || id;
async function refresh() {
  if (loading.value) return;
  loading.value = true;
  try {
    const result = await props.api<{ channels: Channel[]; last_error: string; last_check_at: string }>("/notification-channels");
    if (!mounted) return;
    channels.value = result.channels; workerError.value = result.last_error; workerCheckedAt.value = result.last_check_at; error.value = "";
    if (selected.value) selected.value = result.channels.find(c => c.id === selected.value?.id) || null;
  } catch (e) { if (mounted) error.value = (e as Error).message; }
  finally { loading.value = false; }
}
function clearCredentials() { draft.value.url = ""; draft.value.secret = ""; smtpDraft.value.username = ""; smtpDraft.value.password = ""; }
function changeProtocol() { clearCredentials(); if (draft.value.type === "smtp") draft.value.enabled = false; }
function edit(channel?: Channel) {
  draft.value = { id: channel?.id || "", type: channel?.type || "webhook", name: channel?.name || "", url: "", secret: "", enabled: channel?.enabled ?? true, kinds: [...(channel?.kinds || ["integrity", "sync", "daily"])], revision: channel?.revision || 0 };
  smtpDraft.value = channel?.smtp ? { ...emptySMTP(), host: channel.smtp.host, port: channel.smtp.port, tls_mode: channel.smtp.tls_mode, server_name: channel.smtp.server_name, ca_pem: channel.smtp.ca_pem, auth_mode: channel.smtp.auth_mode, from: channel.smtp.from, recipients: channel.smtp.to.join("\n") } : emptySMTP();
  editor.value = true;
}
async function save() {
  if (saving.value) return;
  if (!draft.value.name.trim() || !draft.value.kinds.length) {
    ElMessage.warning("请填写名称和发送事件范围。"); return;
  }
  if (draft.value.type === "webhook" && ((!draft.value.id && (!draft.value.url || draft.value.secret.length < 16)) || (draft.value.secret && (draft.value.secret.length < 16 || draft.value.secret.length > 512)))) {
    ElMessage.warning("请填写有效 Webhook 地址；签名密钥需要 16–512 字符。"); return;
  }
  const recipients = smtpDraft.value.recipients.split(/[\n,]+/).map(v => v.trim()).filter(Boolean);
  if (draft.value.type === "smtp" && (!smtpDraft.value.host.trim() || !smtpDraft.value.from.trim() || recipients.length < 1 || recipients.length > 5 || (!draft.value.id && smtpDraft.value.auth_mode !== "none" && (!smtpDraft.value.username || !smtpDraft.value.password)))) {
    ElMessage.warning("请填写 SMTP 主机、发件地址、1–5 个收件地址及所选认证的凭据。"); return;
  }
  saving.value = true;
  try {
    const { id, type, name, enabled, kinds, revision } = draft.value;
    const input = type === "smtp" ? { type, name, enabled, kinds, revision, smtp: { host: smtpDraft.value.host.trim().toLowerCase(), port: smtpDraft.value.port, tls_mode: smtpDraft.value.tls_mode, server_name: (smtpDraft.value.server_name.trim() || smtpDraft.value.host.trim()).toLowerCase(), ca_pem: smtpDraft.value.ca_pem, auth_mode: smtpDraft.value.auth_mode, username: smtpDraft.value.auth_mode === "none" ? "" : smtpDraft.value.username, password: smtpDraft.value.auth_mode === "none" ? "" : smtpDraft.value.password, from: smtpDraft.value.from.trim(), to: recipients } } : { type, name, enabled, kinds, revision, url: draft.value.url, secret: draft.value.secret };
    await props.api("/notification-channels" + (id ? "/" + id : ""), id ? "PUT" : "POST", input);
    clearCredentials(); editor.value = false; await refresh(); ElMessage.success("推送通道已保存；从现在起记录新事件，不补发旧通知。");
  } catch (e) { ElMessage.error((e as Error).message); }
  finally { saving.value = false; }
}
async function toggle(channel: Channel) {
  if (busyID.value) return;
  busyID.value = channel.id;
  try {
    await props.api("/notification-channels/" + channel.id, "PUT", { name: channel.name, kinds: channel.kinds, enabled: !channel.enabled, revision: channel.revision });
    await refresh(); ElMessage.success(channel.enabled ? "已停用；未完成的旧配置推送已取消。" : "已启用；只发送新的事件。");
  } catch (e) { ElMessage.error((e as Error).message); await refresh(); }
  finally { busyID.value = ""; }
}
async function refreshHistory() {
  if (!selected.value || historyLoading.value) return;
  const id = selected.value.id; historyLoading.value = true;
  try {
    const result = await props.api<{ deliveries: Delivery[] }>("/notification-channels/" + id + "/deliveries");
    if (mounted && selected.value?.id === id) deliveries.value = result.deliveries;
  } catch (e) { if (mounted) ElMessage.error((e as Error).message); }
  finally { historyLoading.value = false; }
}
function showHistory(channel: Channel) { selected.value = channel; deliveries.value = []; history.value = true; void refreshHistory(); }
async function test(channel: Channel, daily = false) {
  if (busyID.value) return; busyID.value = channel.id;
  try {
    await props.api("/notification-channels/" + channel.id + "/test", "POST", { revision: channel.revision, daily });
    ElMessage.success(daily ? "已入队最近保存日报的脱敏测试摘要；它不新增自动日报事件。请核对发送记录。" : "测试消息已入队；请核对接收端实际接收记录。");
    showHistory(channel);
  } catch (e) { ElMessage.error((e as Error).message); }
  finally { busyID.value = ""; }
}
async function retry(delivery: Delivery) {
  if (!selected.value || busyID.value) return; busyID.value = delivery.id;
  try {
    await props.api("/notification-channels/" + selected.value.id + "/retry/" + delivery.id, "POST", { revision: selected.value.revision });
    await refreshHistory(); ElMessage.success("已重新入队，将在至少 15 秒后发送；接收端应按推送标识去重。");
  } catch (e) { ElMessage.error((e as Error).message); }
  finally { busyID.value = ""; }
}
onMounted(() => { void refresh(); interval = setInterval(() => { if (history.value) { void refresh(); void refreshHistory(); } }, 5000); });
onBeforeUnmount(() => { mounted = false; clearCredentials(); if (interval) clearInterval(interval); });
defineExpose({ refresh });
</script>

<template>
  <section class="panel-card outbound-card" v-loading="loading">
    <div class="outbound-heading"><div><h2>外部告警与日报推送</h2><p>签名 Webhook 或强制 TLS 的 SMTP 邮件，仅发送脱敏摘要。账号、密码、密钥与完整 Webhook 地址加密保存，不回显。</p></div><div><el-button @click="refresh">刷新</el-button><el-button type="primary" :disabled="channels.length >= 8" @click="edit()">新建通道</el-button></div></div>
    <el-alert v-if="error || workerError" :title="error || workerError" type="error" :closable="false" show-icon />
    <el-table :data="channels" empty-text="尚未配置推送通道；默认不向外发送数据">
      <el-table-column label="通道 / 接收主机" min-width="190"><template #default="{ row }"><strong>{{ row.name }}</strong><small class="host">{{ row.type === 'smtp' ? 'SMTP 邮件' : row.type === 'webhook' ? 'Webhook' : '不可读取' }} · {{ row.endpoint_host }} · v{{ row.revision }}</small><small v-if="row.credential_error" class="credential-error">{{ row.credential_error }}</small></template></el-table-column>
      <el-table-column label="事件范围" min-width="210"><template #default="{ row }"><div class="event-tags"><el-tag v-for="kind in row.kinds" :key="kind" type="info" size="small">{{ kindLabel(kind) }}</el-tag></div></template></el-table-column>
      <el-table-column label="启用" width="85"><template #default="{ row }"><el-switch :model-value="row.enabled" :loading="busyID === row.id" :disabled="!!busyID || (!!row.credential_error && !row.enabled)" :aria-label="'启用推送通道 ' + row.name" @change="toggle(row)" /></template></el-table-column>
      <el-table-column label="操作" min-width="300"><template #default="{ row }"><el-button link type="primary" :disabled="!!row.credential_error" @click="edit(row)">配置</el-button><el-button link type="primary" :disabled="!row.enabled || !!busyID || !!row.credential_error" @click="test(row)">测试推送</el-button><el-button v-if="row.kinds.includes('daily')" link type="primary" :disabled="!row.enabled || !!busyID || !!row.credential_error" @click="test(row, true)">测试日报</el-button><el-button link type="primary" @click="showHistory(row)">发送记录</el-button></template></el-table-column>
    </el-table>
    <div class="outbound-footer"><span>最多 8 个通道 · 最多 6 次自动尝试 · 配置变更会取消旧队列</span><span v-if="workerCheckedAt">后台检查：{{ time(workerCheckedAt) }}</span></div>
    <details class="protocol"><summary>接收端接入与可靠性说明</summary><p>Webhook 外部地址使用 HTTPS；HTTP 仅允许显式回环地址用于本机集成。请求为 JSON，最大 4 KiB，不转发任务输出、文件名、凭据或文件内容。</p><p>Webhook 请求头包含 X-Yunzhan-Delivery-ID、X-Yunzhan-Timestamp、X-Yunzhan-Signature。签名为 sha256= + HMAC-SHA256(密钥, 时间戳 + "." + 推送标识 + "." + 原始请求体) 的十六进制值。接收端需校验签名、限制时间戳偏差，并以推送标识去重。</p><p>Webhook 2xx 记为接收；网络错误、408、429、5xx 自动退避重试，遵守最长 1 小时的 Retry-After。SMTP 强制 TLS 1.2 以上及证书验证，STARTTLS 不可用时不发送认证和邮件，不回退明文；可使用系统 CA 或通道专用公共 CA，不修改系统根证书。支持 PLAIN / LOGIN 或显式无认证的 TLS 中继。</p><p>SMTP DATA 获得 250 才记为接收端接收，不代表进入收件箱，也不保证反垃圾、DKIM、SPF 或 DMARC 通过。临时 4xx 和网络错误退避重试，5xx 不自动重试。邮件重试保留相同 Message-ID，但邮件服务不一定据此去重；断线时可能已接收，应按至少一次投递理解。纯文本邮件最大 16 KiB，不含附件；最多 5 个收件地址，其他收件人可在 To 中看到它们。</p><p>重启可恢复未完成任务；每通道待发送上限 1000 条，总历史上限 10000 条，满额时显示错误，不跳过事件。成功与已取消记录保留 90 天，失败记录不静默删除。文件同步普通成功不推送；修改或重新启用通道只发送新事件，不补发停用期间的通知。站内通知策略仍决定资源、任务及远端备份事件是否生成。</p></details>
  </section>
  <el-dialog v-model="editor" class="outbound-dialog" align-center :title="draft.id ? '修改推送通道' : '新建推送通道'" width="min(600px, 94vw)" :close-on-click-modal="!saving" :close-on-press-escape="!saving" @closed="clearCredentials">
    <el-form label-position="top" @submit.prevent="save">
      <el-form-item label="通道名称"><el-input v-model="draft.name" maxlength="60" aria-label="推送通道名称" /></el-form-item>
      <el-form-item label="发送协议"><el-select v-model="draft.type" :disabled="!!draft.id" aria-label="推送通道发送协议" @change="changeProtocol"><el-option value="webhook" label="签名 Webhook" /><el-option value="smtp" label="SMTP 邮件（强制 TLS）" /></el-select></el-form-item>
      <template v-if="draft.type === 'webhook'">
        <el-form-item label="Webhook 地址"><el-input v-model="draft.url" :placeholder="draft.id ? '留空保留现有地址；完整地址不会回显' : 'https://receiver.example/webhook'" autocomplete="off" aria-label="Webhook 地址" /></el-form-item>
        <el-form-item label="签名密钥（16–512 字符）"><el-input v-model="draft.secret" type="password" show-password maxlength="512" autocomplete="new-password" :placeholder="draft.id ? '留空保留现有密钥' : '与接收端约定的随机密钥'" aria-label="Webhook 签名密钥" /></el-form-item>
      </template>
      <template v-else-if="draft.type === 'smtp'">
        <el-alert title="新建邮件通道默认关闭。仅保存明确指定的主机、发件人与收件人；启用后会发送所选事件的脱敏摘要。" type="info" :closable="false" />
        <el-form-item label="SMTP 主机"><el-input v-model="smtpDraft.host" maxlength="253" placeholder="smtp.example.com 或固定 IP" aria-label="SMTP 主机" /></el-form-item>
        <el-form-item label="SMTP 端口"><el-input-number v-model="smtpDraft.port" :min="1" :max="65535" aria-label="SMTP 端口" /></el-form-item>
        <el-form-item label="加密模式"><el-select v-model="smtpDraft.tls_mode" aria-label="SMTP 加密模式"><el-option value="starttls" label="强制 STARTTLS（常用 587）" /><el-option value="tls" label="连接即 TLS（常用 465）" /></el-select></el-form-item>
        <el-form-item label="证书验证名称 / SNI"><el-input v-model="smtpDraft.server_name" maxlength="253" placeholder="留空使用 SMTP 主机；固定 IP 可指定证书域名" aria-label="SMTP 证书验证名称" /></el-form-item>
        <el-form-item label="通道专用公共 CA（可选）"><el-input v-model="smtpDraft.ca_pem" type="textarea" :rows="3" maxlength="16384" placeholder="留空使用系统信任；不接受私钥，不跳过验证" aria-label="SMTP 通道公共 CA" /></el-form-item>
        <el-form-item label="认证方式"><el-select v-model="smtpDraft.auth_mode" aria-label="SMTP 认证方式"><el-option value="plain" label="PLAIN（仅已验证 TLS）" /><el-option value="login" label="LOGIN（仅已验证 TLS）" /><el-option value="none" label="明确无认证的 TLS 中继" /></el-select></el-form-item>
        <template v-if="smtpDraft.auth_mode !== 'none'">
          <el-form-item label="SMTP 账号"><el-input v-model="smtpDraft.username" maxlength="254" autocomplete="off" :placeholder="draft.id ? '不回显；留空保留现有账号' : '邮件服务提供的账号'" aria-label="SMTP 账号" /></el-form-item>
          <el-form-item label="SMTP 密码 / 应用密码"><el-input v-model="smtpDraft.password" type="password" show-password maxlength="512" autocomplete="new-password" :placeholder="draft.id ? '不回显；留空保留现有密码' : '邮件服务合法授权的凭据'" aria-label="SMTP 密码" /></el-form-item>
        </template>
        <el-form-item label="发件地址"><el-input v-model="smtpDraft.from" maxlength="254" placeholder="sender@example.com；仅 ASCII 纯地址" aria-label="SMTP 发件地址" /></el-form-item>
        <el-form-item label="收件地址（最多 5 个）"><el-input v-model="smtpDraft.recipients" type="textarea" :rows="3" placeholder="每行一个，或逗号分隔；不使用显示名" aria-label="SMTP 收件地址" /></el-form-item>
      </template>
      <el-form-item label="发送事件"><el-checkbox-group v-model="draft.kinds"><el-checkbox v-for="kind in kinds" :key="kind.id" :value="kind.id">{{ kind.label }}</el-checkbox></el-checkbox-group></el-form-item>
      <el-form-item label="启用通道"><el-switch v-model="draft.enabled" aria-label="启用当前推送通道" /></el-form-item>
      <el-alert title="保存或停用会取消旧队列，并中止仍在等待响应的旧连接；重新启用不补发历史事件。接收端已处理的数据无法撤回。" type="info" :closable="false" />
    </el-form>
    <template #footer><el-button :disabled="saving" @click="editor = false">取消</el-button><el-button type="primary" :loading="saving" @click="save">保存通道</el-button></template>
  </el-dialog>
  <el-dialog v-model="history" class="outbound-dialog" align-center :title="(selected?.name || '') + ' · 发送记录'" width="min(1080px, 96vw)">
    <div class="history-heading"><p>最近 100 条。自动重试沿用同一推送标识；SMTP Message-ID 不保证接收端去重或进入收件箱。</p><el-button :loading="historyLoading" @click="refreshHistory">刷新记录</el-button></div>
    <el-table :data="deliveries" empty-text="暂无发送记录" v-loading="historyLoading">
      <el-table-column label="时间 / 推送标识" min-width="215"><template #default="{ row }">{{ time(row.created_at) }}<small class="host delivery-id">{{ row.id }}</small></template></el-table-column>
      <el-table-column label="实际状态" min-width="150"><template #default="{ row }"><el-tag :type="row.state === 'succeeded' ? 'success' : row.state === 'failed' ? 'danger' : 'info'">{{ states[row.state] || row.state }}</el-tag></template></el-table-column>
      <el-table-column prop="attempts" label="次数" width="60" />
      <el-table-column :label="selected?.type === 'smtp' ? 'SMTP' : 'HTTP'" width="75"><template #default="{ row }">{{ row.http_status || '—' }}</template></el-table-column>
      <el-table-column prop="error" label="失败原因" min-width="190" />
      <el-table-column label="处理" width="95"><template #default="{ row }"><el-button v-if="row.state === 'failed'" link type="primary" :disabled="!selected?.enabled || !!busyID" @click="retry(row)">重新入队</el-button></template></el-table-column>
    </el-table>
  </el-dialog>
</template>

<style scoped>
:global(.outbound-dialog) { max-height: calc(100dvh - 32px); display: flex; flex-direction: column; }
:global(.outbound-dialog .el-dialog__body) { min-height: 0; overflow-y: auto; }
:global(.outbound-dialog .el-dialog__header),:global(.outbound-dialog .el-dialog__footer) { flex-shrink: 0; }
.outbound-card { padding: 18px; }
.outbound-heading,.outbound-footer,.history-heading { display: flex; justify-content: space-between; align-items: center; gap: 12px; }
.outbound-heading { margin-bottom: 16px; flex-wrap: wrap; }
.outbound-heading h2 { font-size: 16px; }
.outbound-heading p,.history-heading p,.outbound-footer,.protocol { font-size: 12px; color: var(--el-text-color-secondary); }
.outbound-heading p { margin-top: 6px; }
.host { display: block; color: var(--el-text-color-secondary); font-size: 12px; }
.delivery-id { font-family: monospace; overflow-wrap: anywhere; }
.credential-error { display: block; color: var(--el-color-danger); font-size: 12px; }
.event-tags { display: flex; gap: 5px; flex-wrap: wrap; }
.outbound-footer { margin-top: 14px; flex-wrap: wrap; }
.protocol { margin-top: 14px; padding: 12px; background: var(--el-fill-color-light); border-radius: 6px; overflow-wrap: anywhere; }
.protocol summary { cursor: pointer; font-weight: 600; }
.protocol p { margin-top: 9px; line-height: 1.7; }
.history-heading { margin-bottom: 12px; }
@media (max-width: 600px) { .outbound-card { padding: 12px; } .outbound-heading > div:last-child { width: 100%; } }
</style>
