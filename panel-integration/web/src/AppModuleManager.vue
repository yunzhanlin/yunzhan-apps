<script setup lang="ts">
import { ref } from "vue";
import { ElMessage } from "element-plus";
import AppModuleReport from "./AppModuleReport.vue";
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
interface Guidance {
  description: string;
  workflow: string[];
  limitations: string[];
}
const props = defineProps<{ api: API; onJob: (id: string) => Promise<void> }>();
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
  try {
    const page = await props.api<{
      definition: Definition;
      guidance: Guidance;
      status: { installed: boolean; healthy: boolean };
      report: unknown;
    }>(`/app-modules/${id}`);
    definition.value = page.definition;
    guidance.value = page.guidance;
    installed.value = page.status.installed;
    healthy.value = page.status.healthy;
    if (page.report !== null && page.report !== undefined)
      setReport(page.report);
    sites.value = await props.api<typeof sites.value>("/sites");
    form.value = {
      role: "viewer",
      read_only: true,
      auto_restore: false,
      nodes: [{ address: "127.0.0.1:21001", weight: 1, backup: false }],
      site_ids: [],
      excludes: [],
      status_code: 0,
      min_seconds: 1,
      only_bots: false,
    };
  } catch (e) {
    error.value = e instanceof Error ? e.message : String(e);
  } finally {
    busy.value = false;
  }
  if (
    installed.value &&
    definition.value?.actions.includes("run") &&
    !(definition.value.fields || []).some((f) => f.kind === "site") &&
    id !== "platform-ops"
  )
    await execute("run");
}
function selected(row: Record<string, any>) {
  for (const f of definition.value?.fields || [])
    if (row[f.key] !== undefined) form.value[f.key] = row[f.key];
  if (row.drill && definition.value?.id === "disk-analysis")
    void execute("run");
  else ElMessage.info("已填入所选记录，可执行对应操作");
}
function inputBody() {
  const body: Record<string, unknown> = {};
  for (const f of definition.value?.fields || []) {
    const v = form.value[f.key];
    if (v !== undefined && v !== null && v !== "")
      body[f.key] =
        f.kind === "datetime"
          ? new Date(v).toISOString()
          : f.kind === "json" && typeof v === "string"
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
      inputBody(),
    );
    setReport(result);
    if (!["run", "logs", "probe", "check", "preview"].includes(action))
      ElMessage.success("操作已执行并记录审计");
    for (const f of definition.value.fields || [])
      if (f.kind === "password") form.value[f.key] = "";
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
      ].includes(action) &&
      definition.value.actions.includes("run")
    )
      setReport(
        await props.api(`/app-modules/${definition.value.id}/run`, "POST", {}),
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
        <el-form label-position="top" class="module-fields">
          <el-form-item
            v-for="field in definition.fields || []"
            :key="field.key"
            :label="field.label"
          >
            <el-select
              v-if="field.kind === 'site'"
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
            <el-date-picker
              v-else-if="field.kind === 'datetime'"
              v-model="form[field.key]"
              type="datetime"
              clearable
              placeholder="不限制时间"
            />
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
                    : field.key === 'status_code'
                      ? 599
                      : field.key === 'min_seconds'
                        ? 3600
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
            v-for="action in definition.actions"
            :key="action"
            :disabled="
              !installed || busy || (action === 'terminate' && !form.pid)
            "
            :type="
              ['delete', 'terminate', 'remove', 'unmount'].includes(action)
                ? 'danger'
                : 'primary'
            "
            @click="execute(action)"
            >{{ labels[action] || action }}</el-button
          >
        </div>
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
      </template>
    </div>
    <template #footer
      ><el-button
        v-if="report && !report.token"
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
