<script setup lang="ts">
import { apiURL } from "./panelBase";
import { computed, nextTick, onBeforeUnmount, onMounted, ref } from "vue";
import { ElMessage } from "element-plus";
import { Terminal } from "@xterm/xterm";
import { FitAddon } from "@xterm/addon-fit";
import "@xterm/xterm/css/xterm.css";
import {
  ArrowRight,
  Connection,
  Delete,
  Document,
  Folder,
  FullScreen,
  Lock,
  Plus,
  Refresh,
  Setting,
  Tools,
} from "@element-plus/icons-vue";

interface Overview {
  hostname: string;
  os: string;
  arch: string;
  cpu_cores: number;
  cpu_percent: number;
  memory_percent: number;
  memory_used: number;
  memory_total: number;
  disk_percent: number;
  disk_used: number;
  disk_total: number;
  uptime_seconds: number;
  load: string;
}

interface TerminalSnapshot {
  id: string;
  output: string;
  base: number;
  next: number;
  truncated: boolean;
  running: boolean;
  exit_code: number;
  started_at: string;
  user: string;
}
interface TerminalGrant {
  token: string;
  expires_at: number;
  user: string;
  elevated: boolean;
}
interface SavedSession {
  id: string;
  user: string;
  grant: TerminalGrant;
  running: boolean;
}

const props = defineProps<{ overview: Overview | null; csrf: string }>();
const emit = defineEmits<{ (event: "open", value: string): void }>();
const connected = ref(false);
const sessions = ref<SavedSession[]>([]);
interface CommonCommand { command: string; description: string }
const commandGroups: Record<string, CommonCommand[]> = {
  系统管理: [
    { command: "df -h", description: "查看磁盘空间" },
    { command: "free -m", description: "查看内存使用" },
    { command: "top -bn1", description: "即时进程快照" },
    { command: "ps -ef", description: "查看所有进程" },
    { command: "ss -tulnp", description: "查看端口监听" },
    { command: "systemctl status nginx", description: "查看服务状态" },
    { command: "journalctl -n 30 --no-pager", description: "查看系统日志" },
    { command: "uptime", description: "查看系统负载" },
    { command: "uname -a", description: "查看系统版本" },
  ],
  文件操作: [
    { command: "pwd", description: "当前工作目录" },
    { command: "ls -lah", description: "列出目录内容" },
    { command: "du -sh .", description: "当前目录大小" },
    { command: "find . -maxdepth 2 -type f | head -50", description: "查找当前目录文件" },
  ],
  服务管理: [
    { command: "systemctl --failed", description: "失败服务" },
    { command: "systemctl status nginx", description: "Nginx 状态" },
    { command: "systemctl list-units --type=service --state=running", description: "运行中的服务" },
  ],
  网络工具: [
    { command: "ip addr", description: "查看网络接口" },
    { command: "ss -tulnp", description: "查看端口监听" },
    { command: "ip route", description: "查看路由表" },
    { command: "getent hosts localhost", description: "检查本机解析" },
  ],
  软件安装: [
    { command: "nginx -v", description: "Nginx 版本" },
    { command: "php -v", description: "默认 PHP 版本" },
    { command: "mysql --version", description: "MySQL 客户端版本" },
    { command: "dpkg -l | head -30", description: "已安装软件包" },
  ],
};
const activeCommandGroup = ref("系统管理"), showAllCommands = ref(false);
const visibleCommands = computed(() => showAllCommands.value ? commandGroups[activeCommandGroup.value] : commandGroups[activeCommandGroup.value].slice(0, 7));
const authOpen = ref(false),
  authorizing = ref(false),
  password = ref(""),
  code = ref(""),
  confirmation = ref(""),
  authMode = ref<"restricted" | "root">("restricted"),
  terminalHost = ref<HTMLElement>(),
  sessionID = ref(""),
  terminalUser = ref("panel-task"),
  sessionError = ref(""),
  queuedCommand = ref<string | null>(null),
  connecting = ref(false);
const terminalSettingsOpen = ref(false),
  terminalFontSize = ref(13),
  terminalCursorBlink = ref(true),
  terminalSettingsDraft = ref({ fontSize: 13, cursorBlink: true });
let grant: TerminalGrant | null = null,
  restrictedGrant: TerminalGrant | null = null,
  rootGrant: TerminalGrant | null = null,
  terminal: Terminal | null = null,
  fitAddon: FitAddon | null = null,
  resizeObserver: ResizeObserver | null = null,
  pollTimer = 0,
  outputOffset = 0,
  inputQueue = Promise.resolve(),
  resizeQueue = Promise.resolve();
let activeGeneration = 0;
const decoder = new TextDecoder();

async function request<T>(
  path: string,
  method = "GET",
  body?: unknown,
  privileged = true,
  sessionGrant: TerminalGrant | null = grant,
) {
  const scopedPath =
    privileged && sessionGrant?.elevated && path.startsWith("/sessions")
      ? "/root" + path
      : path;
  const response = await fetch(apiURL("/terminal" + scopedPath), {
    method,
    credentials: "same-origin",
    headers: {
      "Content-Type": "application/json",
      "X-CSRF-Token": props.csrf,
      ...(privileged && sessionGrant ? { "X-Terminal-Token": sessionGrant.token } : {}),
    },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  const data = await response.json();
  if (!response.ok) throw new Error(data.error || "终端请求失败");
  return data as T;
}
function encode(value: string) {
  const bytes = new TextEncoder().encode(value);
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary);
}
function decode(value: string) {
  if (!value) return "";
  const binary = atob(value),
    bytes = new Uint8Array(binary.length);
  for (let index = 0; index < binary.length; index++)
    bytes[index] = binary.charCodeAt(index);
  return decoder.decode(bytes, { stream: true });
}
function dimensions() {
  return {
    cols: Math.max(40, Math.min(400, terminal?.cols || 100)),
    rows: Math.max(10, Math.min(200, terminal?.rows || 32)),
  };
}
async function authorize() {
  authorizing.value = true;
  try {
    const issued = await request<TerminalGrant>(
      authMode.value === "root" ? "/elevated-grant" : "/grant",
      "POST",
      {
        password: password.value,
        code: code.value.trim(),
        ...(authMode.value === "root"
          ? { confirmation: confirmation.value.trim() }
          : {}),
      },
      false,
    );
    if (issued.elevated) rootGrant = issued;
    else restrictedGrant = issued;
    password.value = "";
    code.value = "";
    confirmation.value = "";
    authOpen.value = false;
    connecting.value = true;
    await openSession(issued);
  } catch (error) {
    ElMessage.error((error as Error).message);
  } finally {
    connecting.value = false;
    authorizing.value = false;
  }
}
async function start(mode: "restricted" | "root" = "restricted") {
  if (connecting.value || authorizing.value) return;
  if (sessions.value.length >= 4) {
    ElMessage.warning("最多同时保留 4 个终端会话，请先关闭一个会话");
    return;
  }
  authMode.value = mode;
  const availableGrant = mode === "root" ? rootGrant : restrictedGrant;
  if (!availableGrant || availableGrant.expires_at <= Date.now() / 1000 + 5) {
    authOpen.value = true;
    return;
  }
  connecting.value = true;
  try {
    await openSession(availableGrant);
  } finally {
    connecting.value = false;
  }
}
const startRoot = () => start("root");
async function openSession(sessionGrant: TerminalGrant) {
  sessionError.value = "";
  let snapshot: TerminalSnapshot;
  try {
    snapshot = await request<TerminalSnapshot>("/sessions", "POST", {
      cols: 100,
      rows: 32,
    }, true, sessionGrant);
  } catch (error) {
    sessionError.value = (error as Error).message;
    queuedCommand.value = null;
    ElMessage.error(sessionError.value);
    return;
  }
  teardown();
  grant = sessionGrant;
  sessionID.value = snapshot.id;
  terminalUser.value = snapshot.user;
  outputOffset = snapshot.base;
  sessions.value.push({ id: snapshot.id, user: snapshot.user, grant: sessionGrant, running: snapshot.running });
  await mountSession(snapshot);
}
async function selectSession(saved: SavedSession) {
  if (connecting.value || sessionID.value === saved.id) return;
  connecting.value = true;
  teardown();
  grant = saved.grant;
  sessionID.value = saved.id;
  terminalUser.value = saved.user;
  try {
    const snapshot = await request<TerminalSnapshot>(`/sessions/${saved.id}?after=0`, "GET", undefined, true, saved.grant);
    outputOffset = snapshot.base;
    await mountSession(snapshot);
  } catch (error) {
    sessionError.value = (error as Error).message;
    teardown();
    ElMessage.error(sessionError.value);
  } finally {
    connecting.value = false;
  }
}
async function mountSession(snapshot: TerminalSnapshot) {
  const generation = ++activeGeneration;
  connected.value = true;
  await nextTick();
  if (generation !== activeGeneration) return;
  terminal = new Terminal({
    cursorBlink: terminalCursorBlink.value,
    convertEol: false,
    fontSize: terminalFontSize.value,
    lineHeight: 1.35,
    fontFamily:
      "ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace",
    scrollback: 5000,
    theme: {
      background: "#11191f",
      foreground: "#e7edf0",
      cursor: "#36d772",
      green: "#2bd06f",
      brightGreen: "#55e98a",
    },
  });
  fitAddon = new FitAddon();
  terminal.loadAddon(fitAddon);
  terminal.open(terminalHost.value!);
  fitAddon.fit();
  terminal.focus();
  terminal.onData((data) => sendInput(data));
  resizeObserver = new ResizeObserver(() => {
    if (!terminal || !fitAddon || !sessionID.value) return;
    fitAddon.fit();
    const id = sessionID.value;
    const sessionGrant = grant;
    resizeQueue = request(
      `/sessions/${id}/resize`,
      "POST",
      dimensions(),
      true,
      sessionGrant,
    )
      .then(() => undefined)
      .catch(() => undefined);
  });
  resizeObserver.observe(terminalHost.value!);
  try {
    consume(snapshot);
    await request(`/sessions/${snapshot.id}/resize`, "POST", dimensions(), true, grant);
    if (generation !== activeGeneration) return;
    poll();
    if (queuedCommand.value) {
      sendInput(queuedCommand.value + "\r");
      queuedCommand.value = null;
      terminal.focus();
    }
  } catch (error) {
    sessionError.value = (error as Error).message;
    queuedCommand.value = null;
    terminal?.writeln(`\r\n\x1b[31m${sessionError.value}\x1b[0m`);
    teardown();
  }
}
function consume(snapshot: TerminalSnapshot) {
  const saved = sessions.value.find(item => item.id === snapshot.id);
  if (saved) saved.running = snapshot.running;
  if (snapshot.truncated)
    terminal?.writeln("\r\n\x1b[33m[较早的终端输出已按容量上限截断]\x1b[0m");
  if (snapshot.output) terminal?.write(decode(snapshot.output));
  outputOffset = snapshot.next;
  if (!snapshot.running) {
    terminal?.writeln(
      `\r\n\x1b[33m[会话已结束，退出码 ${snapshot.exit_code}]\x1b[0m`,
    );
    connected.value = false;
    window.clearTimeout(pollTimer);
  }
}
function poll() {
  window.clearTimeout(pollTimer);
  if (!sessionID.value || !connected.value) return;
  const id = sessionID.value;
  const sessionGrant = grant;
  const generation = activeGeneration;
  pollTimer = window.setTimeout(async () => {
    try {
      const snapshot = await request<TerminalSnapshot>(`/sessions/${id}?after=${outputOffset}`, "GET", undefined, true, sessionGrant);
      if (generation !== activeGeneration) return;
      consume(snapshot);
      if (connected.value) poll();
    } catch (error) {
      if (generation !== activeGeneration) return;
      sessionError.value = (error as Error).message;
      terminal?.writeln(`\r\n\x1b[31m[${sessionError.value}]\x1b[0m`);
      connected.value = false;
    }
  }, 120);
}
function sendInput(data: string) {
  if (!sessionID.value || !connected.value) return;
  const id = sessionID.value;
  const sessionGrant = grant;
  inputQueue = inputQueue
    .then(() =>
      request(`/sessions/${id}/input`, "POST", {
        data: encode(data),
      }, true, sessionGrant),
    )
    .then(() => undefined)
    .catch((error) => {
      sessionError.value = (error as Error).message;
    });
}
async function disconnect() {
  queuedCommand.value = null;
  const id = sessionID.value;
  const sessionGrant = grant;
  window.clearTimeout(pollTimer);
  resizeObserver?.disconnect();
  resizeObserver = null;
  await resizeQueue;
  if (id && sessionGrant) {
    try {
      await request(`/sessions/${id}`, "DELETE", undefined, true, sessionGrant);
    } catch (error) {
      sessionError.value = (error as Error).message;
      ElMessage.error(sessionError.value);
      return;
    }
  }
  teardown();
  sessions.value = sessions.value.filter(item => item.id !== id);
  if (sessions.value.length) await selectSession(sessions.value[0]);
}
async function closeSession(saved: SavedSession) {
  if (saved.id === sessionID.value) return disconnect();
  try {
    await request(`/sessions/${saved.id}`, "DELETE", undefined, true, saved.grant);
    sessions.value = sessions.value.filter(item => item.id !== saved.id);
  } catch (error) {
    ElMessage.error((error as Error).message);
  }
}
function teardown() {
  activeGeneration++;
  window.clearTimeout(pollTimer);
  connected.value = false;
  sessionID.value = "";
  outputOffset = 0;
  resizeObserver?.disconnect();
  resizeObserver = null;
  terminal?.dispose();
  terminal = null;
  fitAddon = null;
}
function clearTerminal() {
  terminal?.clear();
  terminal?.focus();
}
function showSettings() {
  terminalSettingsDraft.value = { fontSize: terminalFontSize.value, cursorBlink: terminalCursorBlink.value };
  terminalSettingsOpen.value = true;
}
async function saveTerminalSettings() {
  terminalFontSize.value = Math.max(11, Math.min(20, Number(terminalSettingsDraft.value.fontSize) || 13));
  terminalCursorBlink.value = !!terminalSettingsDraft.value.cursorBlink;
  localStorage.setItem("panel-terminal-display", JSON.stringify({ fontSize: terminalFontSize.value, cursorBlink: terminalCursorBlink.value }));
  if (terminal && fitAddon) {
    terminal.options.fontSize = terminalFontSize.value;
    terminal.options.cursorBlink = terminalCursorBlink.value;
    fitAddon.fit();
    if (sessionID.value && grant) {
      try {
        await request(`/sessions/${sessionID.value}/resize`, "POST", dimensions(), true, grant);
      } catch (error) {
        ElMessage.error((error as Error).message);
      }
    }
    terminal.focus();
  }
  terminalSettingsOpen.value = false;
  ElMessage.success("终端显示设置已保存");
}
function fullScreen() {
  void terminalHost.value?.closest(".terminal-workspace")?.requestFullscreen();
}
function run(command: string) {
  if (!connected.value) {
    queuedCommand.value = command;
    void start("restricted");
    return;
  }
  sendInput(command + "\r");
  terminal?.focus();
}
function switchCommandGroup(group: string) {
  activeCommandGroup.value = group;
  showAllCommands.value = false;
}
function authClosed() {
  if (!connecting.value && !connected.value) queuedCommand.value = null;
}
onBeforeUnmount(() => {
  for (const saved of sessions.value)
    void fetch(apiURL(`/terminal${saved.grant.elevated ? "/root" : ""}/sessions/${saved.id}`), {
      method: "DELETE",
      credentials: "same-origin",
      keepalive: true,
      headers: {
        "Content-Type": "application/json",
        "X-CSRF-Token": props.csrf,
        "X-Terminal-Token": saved.grant.token,
      },
    });
  teardown();
});
onMounted(() => {
  try {
    const saved = JSON.parse(localStorage.getItem("panel-terminal-display") || "null");
    if (saved && Number.isInteger(saved.fontSize) && saved.fontSize >= 11 && saved.fontSize <= 20 && typeof saved.cursorBlink === "boolean") {
      terminalFontSize.value = saved.fontSize;
      terminalCursorBlink.value = saved.cursorBlink;
    }
  } catch { /* Invalid old browser preference uses defaults. */ }
});
defineExpose({ start, startRoot });
const host = computed(() => props.overview?.hostname || "panel-server");
const gb = (value = 0) => `${(value / 1024 / 1024 / 1024).toFixed(1)} GB`;
const uptime = computed(() => {
  const seconds = Math.max(0, props.overview?.uptime_seconds || 0);
  const days = Math.floor(seconds / 86400);
  const hours = Math.floor((seconds % 86400) / 3600);
  const minutes = Math.floor((seconds % 3600) / 60);
  return `${days} 天 ${hours} 小时 ${minutes} 分`;
});
</script>

<template>
  <div class="terminal-page">
    <section class="panel-card terminal-session-list">
      <div class="terminal-section-title">
        <h2>会话列表</h2>
        <el-icon><Refresh /></el-icon>
      </div>
      <button v-for="(saved, index) in sessions" :key="saved.id" class="terminal-session" :class="{ active: sessionID === saved.id }" :aria-label="`切换会话 ${index + 1} ${saved.user}`" @click="selectSession(saved)">
        <span class="terminal-online" :class="{ offline: !saved.running }"></span>
        <span><strong>{{ host }}</strong><small>{{ saved.user }} · {{ saved.running ? '已连接' : '已结束' }}</small></span>
        <b>{{ index + 1 }}</b>
      </button>
      <button v-if="!sessions.length" class="terminal-session active" @click="start()"><span class="terminal-online offline"></span><span><strong>{{ host }}</strong><small>本机服务器</small></span><b>⋮</b></button>
      <el-button
        class="new-terminal-session"
        plain
        :icon="Plus"
        @click="start()"
      >
        新建会话
      </el-button>
      <el-button
        class="new-terminal-session root-session-button"
        plain
        :icon="Lock"
        @click="startRoot"
      >
        Root 会话
      </el-button>
    </section>

    <section class="terminal-workspace">
      <div class="terminal-tabs">
        <div v-for="(saved, index) in sessions" :key="saved.id" class="terminal-tab" :class="{ active: sessionID === saved.id }">
          <button type="button" :aria-label="`切换终端标签 ${index + 1} ${saved.user}`" @click="selectSession(saved)"><span class="terminal-online" :class="{ offline: !saved.running }"></span>{{ host }}{{ sessions.length > 1 ? `-${index + 1}` : '' }}</button>
          <button type="button" class="terminal-tab-close" :aria-label="`关闭终端标签 ${index + 1}`" @click="closeSession(saved)">×</button>
        </div>
        <button aria-label="新增终端会话" :disabled="sessions.length >= 4" @click="start()">＋</button>
        <div class="terminal-tab-actions">
          <el-button
            v-if="!connected"
            size="small"
            :icon="Lock"
            @click="startRoot"
            >Root 会话</el-button
          >
          <el-button size="small" :icon="Connection" :disabled="!sessionID" @click="disconnect"
            >断开连接</el-button
          >
          <el-button size="small" :icon="Delete" @click="clearTerminal"
            >清屏</el-button
          >
          <el-button size="small" :icon="Setting" @click="showSettings"
            >设置</el-button
          >
          <el-button
            size="small"
            :icon="FullScreen"
            circle
            aria-label="全屏"
            @click="fullScreen"
          />
        </div>
      </div>
      <div class="terminal-screen" role="log" aria-label="在线终端输出">
        <div v-show="!!sessionID" ref="terminalHost" class="xterm-host"></div>
        <div v-if="!sessionID" class="terminal-connect-empty">
          <el-icon><Connection /></el-icon>
          <strong>终端会话尚未连接</strong>
          <span>普通会话使用 panel-task；Root 会话需要单独提权授权。</span>
          <small v-if="sessionError">{{ sessionError }}</small>
          <el-button type="primary" @click="start()">新建会话</el-button>
        </div>
      </div>
    </section>

    <aside class="terminal-side">
      <section class="panel-card environment-card">
        <div class="terminal-section-title">
          <h2>当前环境信息</h2>
          <el-icon><Refresh /></el-icon>
        </div>
        <dl>
          <dt>主机名</dt>
          <dd>{{ host }}</dd>
          <dt>操作系统</dt>
          <dd>{{ overview?.os || "—" }}</dd>
          <dt>系统架构</dt>
          <dd>{{ overview?.arch || "—" }}</dd>
          <dt>运行时间</dt>
          <dd>{{ uptime }}</dd>
          <dt>当前用户</dt>
          <dd>{{ connected ? terminalUser : "panel-task（受限）" }}</dd>
          <dt>系统负载</dt>
          <dd>{{ overview?.load || "—" }}</dd>
          <dt>CPU 使用率</dt>
          <dd>{{ overview?.cpu_percent?.toFixed(1) || "0.0" }}%</dd>
          <dt>内存使用率</dt>
          <dd>
            {{ overview?.memory_percent?.toFixed(1) || "0.0" }}%（{{
              gb(overview?.memory_used)
            }}
            / {{ gb(overview?.memory_total) }}）
          </dd>
          <dt>磁盘使用率</dt>
          <dd>
            {{ overview?.disk_percent?.toFixed(1) || "0.0" }}%（{{
              gb(overview?.disk_used)
            }}
            / {{ gb(overview?.disk_total) }}）
          </dd>
        </dl>
      </section>
      <section class="panel-card quick-terminal-actions">
        <h2>快捷操作</h2>
        <div>
          <button @click="emit('open', 'jobs')">
            <el-icon><Refresh /></el-icon>任务中心
          </button>
          <button @click="emit('open', 'audit')">
            <el-icon><Document /></el-icon>查看日志
          </button>
          <button @click="emit('open', 'files')">
            <el-icon><Folder /></el-icon>文件管理
          </button>
          <button @click="emit('open', 'monitor')">
            <el-icon><Tools /></el-icon>系统监控
          </button>
        </div>
      </section>
    </aside>

    <section class="panel-card common-commands">
      <div class="terminal-section-title">
        <h2>常用命令</h2>
        <div class="command-tabs" role="tablist" aria-label="命令分类">
          <button v-for="group in Object.keys(commandGroups)" :key="group" type="button"
            role="tab" :aria-selected="activeCommandGroup === group"
            :class="{ active: activeCommandGroup === group }" @click="switchCommandGroup(group)">{{ group }}</button>
        </div>
        <button type="button" @click="showAllCommands = !showAllCommands">
          {{ showAllCommands ? "收起命令" : "更多命令" }} <el-icon><ArrowRight /></el-icon>
        </button>
      </div>
      <div class="command-grid">
        <button v-for="item in visibleCommands" :key="item.command" type="button" @click="run(item.command)">
          <code>{{ item.command }}</code><span>{{ item.description }}</span>
        </button>
      </div>
    </section>

    <el-dialog
      v-model="authOpen"
      :title="authMode === 'root' ? '授权 Root 终端' : '授权受限终端'"
      width="430px"
      append-to-body
      @closed="authClosed"
    >
      <el-alert
        :title="
          authMode === 'root'
            ? 'Root 会话具有完整系统权限，只允许 1 个会话，授权 2 分钟有效，闲置 5 分钟自动回收。'
            : '终端使用 panel-task 独立账号，不能取得 root 权限；授权 10 分钟有效，会话闲置 15 分钟自动回收。'
        "
        :type="authMode === 'root' ? 'error' : 'warning'"
        :closable="false"
        show-icon
      />
      <el-form
        label-position="top"
        class="terminal-auth-form"
        @submit.prevent="authorize"
      >
        <el-form-item label="当前管理员密码">
          <el-input
            v-model="password"
            type="password"
            show-password
            autocomplete="current-password"
            @keyup.enter="authorize"
          />
        </el-form-item>
        <el-form-item label="双重验证码或恢复码（已开启双重验证时填写）">
          <el-input
            v-model="code"
            autocomplete="one-time-code"
            @keyup.enter="authorize"
          />
        </el-form-item>
        <el-form-item
          v-if="authMode === 'root'"
          label="输入 ROOT 确认完整系统权限"
        >
          <el-input
            v-model="confirmation"
            autocomplete="off"
            @keyup.enter="authorize"
          />
        </el-form-item>
      </el-form>
      <template #footer>
        <el-button @click="authOpen = false">取消</el-button>
        <el-button
          :type="authMode === 'root' ? 'danger' : 'primary'"
          :loading="authorizing"
          :disabled="
            !password || (authMode === 'root' && confirmation !== 'ROOT')
          "
          @click="authorize"
          >验证并连接</el-button
        >
      </template>
    </el-dialog>
    <el-dialog v-model="terminalSettingsOpen" title="终端显示设置" width="420px" append-to-body>
      <el-form label-width="100px">
        <el-form-item label="终端字号"><el-input-number v-model="terminalSettingsDraft.fontSize" :min="11" :max="20" aria-label="终端字号" /></el-form-item>
        <el-form-item label="闪烁光标"><el-switch v-model="terminalSettingsDraft.cursorBlink" aria-label="闪烁光标" /></el-form-item>
      </el-form>
      <p class="terminal-settings-note">{{ terminalUser === 'root' ? 'Root 会话闲置 5 分钟自动回收' : '受限会话使用 panel-task，闲置 15 分钟自动回收' }}。显示设置保存在当前浏览器。</p>
      <template #footer><el-button @click="terminalSettingsOpen = false">取消</el-button><el-button type="primary" @click="saveTerminalSettings">保存设置</el-button></template>
    </el-dialog>
  </div>
</template>

<style scoped>
.terminal-page {
  display: grid;
  grid-template-columns: 245px minmax(0, 1fr) 315px;
  grid-template-rows: minmax(560px, calc(100vh - 310px)) auto;
  gap: 12px;
}
.terminal-session-list {
  padding: 0;
}
.terminal-section-title {
  height: 48px;
  padding: 0 16px;
  display: flex;
  align-items: center;
  justify-content: space-between;
  border-bottom: 1px solid #e8edf3;
}
.terminal-section-title h2,
.quick-terminal-actions h2 {
  font-size: 15px;
  margin: 0;
  color: #10213a;
}
.terminal-session {
  width: calc(100% - 16px);
  margin: 9px 8px 4px;
  padding: 11px 12px;
  display: flex;
  align-items: center;
  gap: 10px;
  border-radius: 6px;
  text-align: left;
}
.terminal-session.active {
  background: #eaf9f0;
}
.terminal-session span:nth-child(2) {
  display: grid;
  gap: 4px;
  flex: 1;
}
.terminal-session strong {
  font-size: 13px;
  color: #079b4e;
}
.terminal-session small {
  font-size: 11px;
  color: #73859d;
}
.terminal-session b {
  color: #328660;
}
.terminal-online {
  width: 9px;
  height: 9px;
  border-radius: 50%;
  background: #0bb45c;
  flex: none;
}
.terminal-online.offline {
  background: #8a99ab;
}
.new-terminal-session {
  width: calc(100% - 16px);
  margin: 8px;
}
.terminal-workspace {
  min-width: 0;
  display: flex;
  flex-direction: column;
  border: 1px solid #dce4ec;
  border-radius: 7px;
  overflow: hidden;
  background: #121a20;
}
.terminal-tabs {
  height: 44px;
  display: flex;
  align-items: center;
  min-width: 0;
  overflow-x: auto;
  background: #fff;
  border-bottom: 1px solid #dfe6ee;
}
.terminal-tab {
  height: 44px;
  min-width: 145px;
  flex: none;
  padding: 0 13px;
  display: flex;
  align-items: center;
  gap: 9px;
  border-right: 1px solid #e5eaf0;
  font-size: 12px;
}
.terminal-tab.active { background: #f2fbf6; box-shadow: inset 0 2px #09a65a; }
.terminal-tab > button:first-child { display: flex; align-items: center; gap: 7px; min-width: 0; white-space: nowrap; }
.terminal-tab-close { margin-left: auto; color: #667891; font-size: 18px; line-height: 1; }
.terminal-tab-close:hover { color: #dc3545; }
.terminal-tab-actions { flex: none; }
.terminal-tab-close:focus-visible,
.terminal-tab > button:first-child:focus-visible { outline: 2px solid #09a65a; outline-offset: 2px; }
.terminal-tab .terminal-online { width: 8px; height: 8px; }
.terminal-tab button {
  border: 0;
  background: none;
}
.terminal-tabs > button {
  height: 44px;
  width: 44px;
  color: #63748d;
  font-size: 20px;
}
.terminal-tab-actions {
  margin-left: auto;
  padding-right: 8px;
  display: flex;
  gap: 6px;
}
.terminal-tab-actions .el-button + .el-button {
  margin: 0;
}
.terminal-screen {
  flex: 1;
  min-height: 0;
  padding: 0;
  background: radial-gradient(circle at 70% 30%, #1b252c, #11191f 72%);
  color: #e7edf0;
  font:
    13px/1.45 ui-monospace,
    SFMono-Regular,
    Menlo,
    monospace;
}
.xterm-host {
  width: 100%;
  height: 100%;
  min-height: 0;
  padding: 12px;
  box-sizing: border-box;
}
.xterm-host :deep(.xterm) {
  height: 100%;
}
.terminal-auth-form {
  margin-top: 18px;
}
.terminal-settings-note { margin: 4px 0 0; color: #718198; font-size: 12px; line-height: 1.6; }
.terminal-screen p {
  margin: 0 0 4px;
}
.terminal-screen p span {
  color: #2bd06f;
}
.terminal-screen p i {
  display: inline-block;
  width: 8px;
  height: 15px;
  background: #36d772;
  vertical-align: middle;
}
.terminal-notice {
  color: #f0b34f !important;
}
.terminal-connect-empty {
  height: 100%;
  display: grid;
  place-content: center;
  justify-items: center;
  gap: 12px;
  color: #8799a5;
  font-family: inherit;
}
.terminal-connect-empty .el-icon {
  font-size: 34px;
  color: #2aad68;
}
.terminal-connect-empty strong {
  color: #d9e4e9;
}
.terminal-side {
  display: grid;
  gap: 12px;
  align-content: start;
}
.environment-card dl {
  display: grid;
  grid-template-columns: 88px 1fr;
  gap: 13px 8px;
  padding: 15px;
  margin: 0;
  font-size: 12px;
}
.environment-card dt {
  color: #596c86;
}
.environment-card dd {
  margin: 0;
  color: #1a2d4a;
  overflow-wrap: anywhere;
}
.quick-terminal-actions {
  padding: 15px;
}
.quick-terminal-actions h2 {
  margin-bottom: 12px;
}
.quick-terminal-actions > div {
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: 8px;
}
.quick-terminal-actions button {
  height: 44px;
  border: 1px solid #e1e7ee;
  border-radius: 5px;
  display: flex;
  align-items: center;
  justify-content: center;
  gap: 7px;
  font-size: 12px;
}
.quick-terminal-actions .el-icon {
  color: #08ad5b;
  font-size: 18px;
}
.common-commands {
  grid-column: 1/-1;
}
.terminal-section-title > button {
  color: #08ad5b;
  display: flex;
  align-items: center;
  gap: 5px;
  font-size: 12px;
}
.command-tabs {
  display: flex;
  gap: 0;
  align-self: stretch;
  min-width: 0;
  margin-right: auto;
  padding: 0 12px;
}
.command-tabs button {
  padding: 0 13px;
  font-size: 11px;
  color: #6e7f97;
  white-space: nowrap;
}
.command-tabs button.active {
  color: #08a855;
  border-bottom: 2px solid #08ad5b;
}
.command-grid {
  display: grid;
  grid-template-columns: repeat(7, minmax(0, 1fr));
  gap: 8px;
  padding: 10px 16px;
}
.command-grid button {
  height: 53px;
  border: 1px solid #e0e7ee;
  border-radius: 5px;
  text-align: left;
  padding: 8px 12px;
  display: grid;
  gap: 3px;
}
.command-grid code {
  color: #253a58;
  white-space: nowrap;
  overflow: hidden;
  text-overflow: ellipsis;
}
.command-grid span {
  font-size: 10px;
  color: #8190a4;
}
@media (max-width: 1100px) {
  .terminal-page {
    grid-template-columns: 210px minmax(0, 1fr);
  }
  .terminal-side {
    grid-column: 1/-1;
    grid-template-columns: 1fr 1fr;
  }
  .common-commands {
    grid-column: 1/-1;
  }
  .command-grid {
    grid-template-columns: repeat(4, minmax(0, 1fr));
  }
}
@media (max-width: 700px) {
  .terminal-page {
    grid-template-columns: 1fr;
  }
  .terminal-session-list,
  .terminal-side {
    display: none;
  }
  .terminal-workspace {
    min-height: 600px;
  }
  .terminal-tab-actions .el-button:not(:first-child) {
    display: none;
  }
  .common-commands {
    grid-column: 1;
  }
  .command-grid {
    grid-template-columns: 1fr 1fr;
  }
  .command-tabs {
    overflow: auto;
  }
  .terminal-screen {
    min-height: 540px;
  }
  .terminal-page {
    grid-template-rows: auto;
  }
}
</style>
