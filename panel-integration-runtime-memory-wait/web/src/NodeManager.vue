<script setup lang="ts">
import { computed, ref } from "vue";
import { ElMessage, ElMessageBox } from "element-plus";
import { Plus, Refresh } from "@element-plus/icons-vue";
type API = <T>(path: string, method?: string, body?: unknown) => Promise<T>;
interface Runtime {
  id: string;
  family: string;
  version: string;
  status: string;
}
interface Site {
  id: string;
  name: string;
  domain: string;
  status: string;
}
interface App {
  id: string;
  name: string;
  release_id: string;
  site_id: string;
  site_name: string;
  entry: string;
  port: number;
  starter: boolean;
  created_at: string;
  status: string;
  pid: number;
}
const props = defineProps<{ api: API; installed: Runtime[]; sites: Site[] }>();
const drawer = ref(false),
  loading = ref(false),
  createOpen = ref(false),
  logsOpen = ref(false),
  logs = ref("");
const apps = ref<App[]>([]);
const form = ref({
  name: "",
  release_id: "",
  site_id: "",
  entry: "server.js",
  port: 17000,
  starter: true,
});
const releases = computed(() =>
  props.installed.filter(
    (r) => r.family === "node" && r.status === "installed",
  ),
);
const availableSites = computed(() =>
  props.sites.filter(
    (s) => !["provisioning", "needs_attention"].includes(s.status),
  ),
);
const running = computed(
  () => apps.value.filter((a) => a.status === "running").length,
);
async function refresh() {
  loading.value = true;
  try {
    apps.value = (await props.api<{ apps: App[] }>("/node/apps")).apps;
  } catch (e) {
    ElMessage.error(e instanceof Error ? e.message : "读取 Node.js 项目失败");
  } finally {
    loading.value = false;
  }
}
async function open() {
  drawer.value = true;
  await refresh();
}
function create() {
  if (!releases.value.length || !availableSites.value.length) {
    ElMessage.warning("请先安装 Node.js 并创建可用网站");
    return;
  }
  const used = new Set(apps.value.map((a) => a.port));
  let port = 17000;
  while (used.has(port) && port <= 17999) port++;
  form.value = {
    name: "",
    release_id: releases.value.at(-1)?.id || releases.value[0].id,
    site_id: availableSites.value[0].id,
    entry: "server.js",
    port,
    starter: true,
  };
  createOpen.value = true;
}
async function submit() {
  if (!form.value.name.trim()) {
    ElMessage.warning("请输入项目名称");
    return;
  }
  loading.value = true;
  try {
    await props.api("/node/apps", "POST", {
      ...form.value,
      name: form.value.name.trim(),
    });
    createOpen.value = false;
    ElMessage.success("Node.js 项目已启动并监听回环端口");
    await refresh();
  } catch (e) {
    ElMessage.error(e instanceof Error ? e.message : "创建失败");
  } finally {
    loading.value = false;
  }
}
async function action(app: App, value: "start" | "stop" | "restart") {
  try {
    await props.api(`/node/apps/${app.id}/${value}`, "POST", {});
    ElMessage.success("项目状态已更新");
    await refresh();
  } catch (e) {
    ElMessage.error(e instanceof Error ? e.message : "操作失败");
  }
}
async function showLogs(app: App) {
  try {
    logs.value = (
      await props.api<{ content: string }>(`/node/apps/${app.id}/logs`)
    ).content;
    logsOpen.value = true;
  } catch (e) {
    ElMessage.error(e instanceof Error ? e.message : "读取日志失败");
  }
}
async function remove(app: App) {
  try {
    const result = await ElMessageBox.prompt(
      `停止项目并删除运行配置；网站目录和入口文件会保留。请输入项目名称 ${app.name}`,
      "删除 Node.js 项目",
      {
        confirmButtonText: "删除项目",
        cancelButtonText: "取消",
        inputPlaceholder: app.name,
        type: "warning",
      },
    );
    await props.api(`/node/apps/${app.id}`, "DELETE", {
      confirm_name: result.value,
    });
    ElMessage.success("项目运行配置已删除，代码文件已保留");
    await refresh();
  } catch (e) {
    if (e instanceof Error) ElMessage.error(e.message);
  }
}
defineExpose({ open, refresh });
</script>
<template>
  <el-drawer
    v-model="drawer"
    title="Node.js 项目管理"
    size="920px"
    class="node-drawer"
    @open="refresh"
  >
    <div class="node-summary">
      <div>
        <small>项目总数</small><strong>{{ apps.length }}</strong>
      </div>
      <div>
        <small>运行中</small><strong class="green">{{ running }}</strong>
      </div>
      <div>
        <small>可用版本</small><strong>{{ releases.length }}</strong>
      </div>
      <div class="node-actions">
        <el-button :icon="Refresh" @click="refresh">刷新</el-button
        ><el-button
          type="primary"
          :icon="Plus"
          :disabled="!releases.length || !availableSites.length"
          @click="create"
          >添加项目</el-button
        >
      </div>
    </div>
    <el-table
      v-loading="loading"
      :data="apps"
      empty-text="尚未添加 Node.js 项目"
      class="node-table"
    >
      <el-table-column label="项目" min-width="145"
        ><template #default="{ row }"
          ><strong>{{ row.name }}</strong
          ><small>{{ row.site_name }}</small></template
        ></el-table-column
      >
      <el-table-column label="版本" width="110"
        ><template #default="{ row }"
          >Node {{ row.release_id.replace("node-", "") }}</template
        ></el-table-column
      >
      <el-table-column
        label="入口"
        min-width="120"
        prop="entry"
      /><el-table-column label="本机地址" min-width="145"
        ><template #default="{ row }"
          >127.0.0.1:{{ row.port }}</template
        ></el-table-column
      ><el-table-column label="PID" width="80" prop="pid" />
      <el-table-column label="状态" width="95"
        ><template #default="{ row }"
          ><el-tag
            :type="
              row.status === 'running'
                ? 'success'
                : row.status === 'stopped'
                  ? 'info'
                  : 'danger'
            "
            >{{
              row.status === "running"
                ? "运行中"
                : row.status === "stopped"
                  ? "已停止"
                  : "需核对"
            }}</el-tag
          ></template
        ></el-table-column
      >
      <el-table-column label="操作" min-width="245" fixed="right"
        ><template #default="{ row }"
          ><el-button
            link
            type="primary"
            @click="action(row, row.status === 'running' ? 'stop' : 'start')"
            >{{ row.status === "running" ? "停止" : "启动" }}</el-button
          ><el-button
            link
            type="primary"
            :disabled="row.status !== 'running'"
            @click="action(row, 'restart')"
            >重启</el-button
          ><el-button link type="primary" @click="showLogs(row)">日志</el-button
          ><el-button link type="danger" @click="remove(row)"
            >删除</el-button
          ></template
        ></el-table-column
      >
    </el-table>
    <div class="node-security">
      <strong>运行边界</strong
      ><span
        >项目使用所属网站的独立系统账户，只监听
        127.0.0.1；需要对外访问时可在网站设置中添加反向代理。</span
      >
    </div>
  </el-drawer>
  <el-dialog v-model="createOpen" title="添加 Node.js 项目" width="560px"
    ><el-form label-position="top"
      ><el-form-item label="项目名称"
        ><el-input
          v-model="form.name"
          maxlength="40"
          placeholder="例如：订单 API" /></el-form-item
      ><el-form-item label="所属网站目录"
        ><el-select v-model="form.site_id" style="width: 100%"
          ><el-option
            v-for="site in availableSites"
            :key="site.id"
            :label="`${site.name} · ${site.domain}`"
            :value="site.id" /></el-select
        ><small class="help"
          >工作目录固定为该网站的 public 目录。</small
        ></el-form-item
      >
      <div class="node-form-grid">
        <el-form-item label="Node.js 版本"
          ><el-select v-model="form.release_id" style="width: 100%"
            ><el-option
              v-for="item in releases"
              :key="item.id"
              :label="`Node.js ${item.version}`"
              :value="item.id" /></el-select></el-form-item
        ><el-form-item label="回环端口"
          ><el-input-number
            v-model="form.port"
            :min="17000"
            :max="17999"
            controls-position="right"
        /></el-form-item>
      </div>
      <el-form-item label="入口文件"
        ><el-input v-model="form.entry" placeholder="server.js" /></el-form-item
      ><el-form-item label="创建启动示例"
        ><el-switch v-model="form.starter" /><span class="switch-help"
          >入口不存在时创建最小 HTTP 服务；已有文件绝不覆盖。</span
        ></el-form-item
      ><el-alert
        :closable="false"
        type="info"
        title="运行时注入 HOST=127.0.0.1、PORT 与 NODE_ENV=production。" /></el-form
    ><template #footer
      ><el-button @click="createOpen = false">取消</el-button
      ><el-button type="primary" :loading="loading" @click="submit"
        >创建并启动</el-button
      ></template
    ></el-dialog
  >
  <el-dialog v-model="logsOpen" title="Node.js 项目日志" width="760px">
    <pre class="node-logs">{{ logs || "暂无日志" }}</pre>
    <template #footer
      ><el-button @click="logsOpen = false">关闭</el-button></template
    ></el-dialog
  >
</template>
<style scoped>
.node-summary {
  display: grid;
  grid-template-columns: repeat(3, minmax(100px, 1fr)) auto;
  gap: 12px;
  margin-bottom: 18px;
}
.node-summary > div {
  border: 1px solid #e8edf3;
  border-radius: 8px;
  padding: 14px 16px;
  background: #fff;
}
.node-summary small {
  display: block;
  color: #718096;
  margin-bottom: 8px;
}
.node-summary strong {
  font-size: 24px;
  color: #172033;
}
.node-summary .green {
  color: #08a858;
}
.node-summary .node-actions {
  display: flex;
  align-items: center;
  gap: 8px;
  border: 0;
  padding: 0;
}
.node-table {
  border: 1px solid #e8edf3;
  border-radius: 8px;
}
.node-table strong,
.node-table small {
  display: block;
}
.node-table small,
.help {
  color: #94a3b8;
  margin-top: 4px;
}
.node-security {
  display: flex;
  gap: 12px;
  margin-top: 16px;
  padding: 14px 16px;
  border-radius: 8px;
  background: #f0fbf5;
  color: #4b6474;
  font-size: 13px;
}
.node-security strong {
  color: #08a858;
  white-space: nowrap;
}
.node-form-grid {
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: 16px;
}
.node-form-grid :deep(.el-input-number) {
  width: 100%;
}
.switch-help {
  margin-left: 10px;
  color: #718096;
  font-size: 12px;
}
.node-logs {
  max-height: 480px;
  overflow: auto;
  margin: 0;
  padding: 16px;
  background: #111820;
  color: #d9e7df;
  border-radius: 7px;
  font:
    12px/1.6 ui-monospace,
    monospace;
  white-space: pre-wrap;
}
@media (max-width: 760px) {
  .node-summary {
    grid-template-columns: 1fr 1fr;
  }
  .node-summary .node-actions {
    grid-column: 1/-1;
  }
  .node-form-grid {
    grid-template-columns: 1fr;
  }
  .node-security {
    flex-direction: column;
  }
}
</style>
