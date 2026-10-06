<script setup lang="ts">
import { computed, ref } from "vue";
import { ElMessage, ElMessageBox } from "element-plus";
import { formatPanelDateTime } from "./panelTime";
import { isSecuritySoftware } from "./softwareRouting";
import WafWorkspace from "./WafWorkspace.vue";

type API = <T>(path: string, method?: string, body?: unknown, idempotencyKey?: string) => Promise<T>;
export interface SecurityAppCatalogItem {
  id: string;
  family: string;
  name: string;
  category: string;
  version: string;
  description: string;
  source: string;
  capabilities: string[];
  defaults: Record<string, string | number>;
}
export interface SecurityAppStatus {
  id: string;
  installed: boolean;
  enabled: boolean;
  healthy: boolean;
  version?: string;
  detail: string;
  settings?: Record<string, string | number>;
}
interface WAFEvent { time: string; site: string; ip: string; status: number; method: string; bad_method: string; bad_args: string; bad_uri: string; bad_agent: string; rate: string }

const props = defineProps<{ api: API; onJob: (id: string) => Promise<void>; onInstall: (id: string, settings: Record<string, unknown>) => Promise<string> }>();
const open = ref(false), busy = ref(false);
const selected = ref<SecurityAppCatalogItem | null>(null);
const status = ref<SecurityAppStatus | null>(null);
const form = ref<Record<string, string | number>>({});
const installed = computed(() => Boolean(status.value?.installed));
const events = ref<WAFEvent[]>([]), eventsBusy = ref(false), eventsError = ref(""), eventsMore = ref(false);
const eventRule = (event: WAFEvent) => event.rate === "REJECTED" ? "请求限速" : event.bad_method === "1" ? "请求方法" : event.bad_args === "1" ? "查询参数" : event.bad_uri === "1" ? "请求地址" : event.bad_agent === "1" ? "User-Agent" : "其他规则";

async function loadEvents() {
  if (selected.value?.id !== "nginx-waf" || !installed.value || eventsBusy.value) return;
  eventsBusy.value = true;
  eventsError.value = "";
  try {
    const page = await props.api<{ events: WAFEvent[]; has_more: boolean }>("/software/nginx-waf/events");
    events.value = page.events;
    eventsMore.value = page.has_more;
  } catch (error) {
    eventsError.value = error instanceof Error ? error.message : "防护事件读取失败";
  } finally { eventsBusy.value = false; }
}

function show(app: SecurityAppCatalogItem, current?: SecurityAppStatus) {
  if (!isSecuritySoftware(app.id)) {
    open.value = false;
    selected.value = null;
    status.value = null;
    ElMessage.error("该应用不是安全插件，请从对应的应用管理页打开");
    return;
  }
  selected.value = app;
  status.value = current || null;
  form.value = { ...app.defaults, ...(current?.settings || {}) };
  open.value = true;
  events.value = [];
  eventsMore.value = false;
  eventsError.value = "";
}
async function queue(action: "install" | "configure" | "uninstall") {
  if (!selected.value || !isSecuritySoftware(selected.value.id) || busy.value) return;
  const app = selected.value;
  try {
    if (action === "uninstall") {
      await ElMessageBox.confirm(
        app.id === "system-hardening"
          ? "将移除面板管理的 sysctl 文件，并逐项恢复安装前记录的内核参数值。"
          : app.id === "intrusion-prevention"
            ? "将移除面板管理的 SSHD Jail；Debian Fail2ban 软件包和其他 Jail 会保留。"
            : "将移除 WAF 规则并在 nginx -t 通过后重载；站点和 Nginx 本身不会删除。",
        `卸载 ${app.name}`,
        { type: "warning", confirmButtonText: "确认卸载", cancelButtonText: "取消" },
      );
    }
    busy.value = true;
    const jobID = action === "install"
      ? await props.onInstall(app.id, form.value)
      : (await props.api<{ job_id: string }>(`/software/${app.id}/${action}`, "POST", { settings: action === "uninstall" ? {} : form.value })).job_id;
    open.value = false;
    await props.onJob(jobID);
  } catch (error) {
    if (error instanceof Error && error.message !== "cancel") ElMessage.error(error.message);
  } finally { busy.value = false; }
}
async function install(app: SecurityAppCatalogItem, current?: SecurityAppStatus) {
  if (!isSecuritySoftware(app.id)) { show(app, current); return; }
  show(app, current);
  if (app.id === "nginx-waf") return;
  try {
    await ElMessageBox.confirm(
      `${app.name} 将通过受限 root 执行器安装固定配置，完成实际状态核对并写入审计。来源：${app.source}。`,
      `安装 ${app.name}`,
      { confirmButtonText: "开始安装", cancelButtonText: "先看设置" },
    );
    await queue("install");
  } catch { /* “先看设置”会保留配置弹窗。 */ }
}
defineExpose({ show, install });
</script>

<template>
  <el-dialog v-model="open" :title="selected?.id === 'nginx-waf' ? 'Nginx 防火墙管理工作台' : `${selected?.name || '安全软件'} · 设置`" :width="selected?.id === 'nginx-waf' ? 'min(1160px, 96vw)' : '560px'" class="security-app-dialog" destroy-on-close>
    <WafWorkspace v-if="selected?.id === 'nginx-waf'" :api="api" :on-install="onInstall"/>
    <template v-else>
    <template v-if="selected">
      <div class="security-app-summary">
        <span :class="['software-icon', 'software-logo', selected.family]">{{ selected.family.slice(0, 2).toUpperCase() }}</span>
        <div><strong>{{ selected.name }}</strong><small>{{ selected.source }} · v{{ selected.version }}</small></div>
        <el-tag :type="installed ? (status?.healthy ? 'success' : 'warning') : 'info'">{{ installed ? (status?.healthy ? '运行正常' : '需要核对') : '未安装' }}</el-tag>
      </div>
      <p class="security-app-detail">{{ status?.detail || selected.description }}</p>
      <el-form label-position="top">
        <template v-if="selected.id === 'nginx-waf'">
          <el-form-item label="防护级别"><el-select v-model="form.profile"><el-option value="balanced" label="平衡 · 常用攻击特征"/><el-option value="strict" label="严格 · 扩展扫描器与 SQL 特征"/></el-select></el-form-item>
          <el-form-item label="单 IP 请求速率"><el-input-number v-model="form.rate_per_second" :min="5" :max="200"/><span class="field-suffix">次 / 秒</span></el-form-item>
          <el-alert :closable="false" type="info" title="首版检查 URI、查询参数、请求方法和 User-Agent，并执行限速；不宣称具备完整请求体解析或商业规则库。"/>
        </template>
        <template v-else-if="selected.id === 'system-hardening'">
          <el-form-item label="基线"><el-select v-model="form.profile"><el-option value="baseline" label="基线 · 低兼容性风险"/><el-option value="strict" label="严格 · 同时限制非特权 BPF 并记录异常包"/></el-select></el-form-item>
          <el-alert :closable="false" type="warning" title="安装时记录每个受管 sysctl 的实际原值；卸载会逐项恢复，而不是套用猜测的系统默认值。"/>
        </template>
        <template v-else-if="selected.id === 'intrusion-prevention'">
          <div class="security-app-triple"><el-form-item label="失败次数"><el-input-number v-model="form.max_retry" :min="2" :max="20"/></el-form-item><el-form-item label="统计窗口（分钟）"><el-input-number v-model="form.find_time_minutes" :min="1" :max="1440"/></el-form-item><el-form-item label="封禁时长（分钟）"><el-input-number v-model="form.ban_time_minutes" :min="10" :max="10080"/></el-form-item></div>
          <el-alert :closable="false" type="info" title="使用 Debian Fail2ban 与 systemd SSH 日志后端；封禁列表和解封继续在安全中心读取实际 Jail。"/>
        </template>
      </el-form>
      <div class="security-app-capabilities"><span v-for="item in selected.capabilities" :key="item">{{ item }}</span></div>
      <section v-if="selected.id === 'nginx-waf' && installed" class="security-app-events">
        <div class="security-app-events-head"><strong>最近防护事件</strong><el-button size="small" :loading="eventsBusy" @click="loadEvents">刷新</el-button></div>
        <el-alert v-if="eventsError" type="error" :closable="false" :title="eventsError"/>
        <p v-else-if="!eventsBusy && events.length === 0" class="security-app-events-empty">暂无已记录的拦截事件</p>
        <div v-else class="security-app-events-scroll"><table><thead><tr><th>时间</th><th>站点</th><th>来源 IP</th><th>规则</th><th>状态</th></tr></thead><tbody><tr v-for="(event, index) in events" :key="`${event.time}-${event.ip}-${index}`"><td>{{ formatPanelDateTime(event.time) }}</td><td>{{ event.site }}</td><td>{{ event.ip }}</td><td>{{ eventRule(event) }}</td><td>{{ event.status }}</td></tr></tbody></table></div>
        <small v-if="eventsMore" class="security-app-events-note">仅显示最近 100 条；更早事件仍保留在服务器日志中。</small>
      </section>
    </template>
    </template>
    <template #footer><template v-if="selected?.id !== 'nginx-waf'"><el-button v-if="installed" type="danger" plain :loading="busy" @click="queue('uninstall')">卸载</el-button><span class="dialog-spacer"></span></template><el-button @click="open = false">关闭</el-button><el-button v-if="selected?.id !== 'nginx-waf'" type="primary" :loading="busy" @click="queue(installed ? 'configure' : 'install')">{{ installed ? '保存并应用' : '安装并验证' }}</el-button></template>
  </el-dialog>
</template>
