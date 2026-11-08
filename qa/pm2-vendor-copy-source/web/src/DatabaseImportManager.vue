<script setup lang="ts">
import { apiURL } from "./panelBase";
import { onMounted, onUnmounted, ref, computed } from "vue";
import { ElMessage, ElMessageBox } from "element-plus";
interface Import {
  target_database_id?: string;
  target_revision?: number;
  id: string;
  server_id: string;
  name: string;
  bytes: number;
  sha256: string;
  state: string;
  job_id: string;
  created_at: string;
}
const props = defineProps<{
  api: <T>(path: string, method?: string, body?: unknown) => Promise<T>;
  csrf: string;
  servers: { id: string; name: string; release_id: string; status: string }[];
  onJob: (id: string) => Promise<void>;
}>();
const emit = defineEmits<{ changed: [] }>();
const rows = ref<Import[]>([]),
  open = ref(false),
  busy = ref(false),
  error = ref(""),
  formError = ref(""),
  progress = ref(0),
  file = ref<File>(),
  selected = ref<Import>(),
  serverID = ref(""),
  name = ref(""),
  confirm = ref(""),
  release = ref<Import>(),
  releaseOpen = ref(false),
  releaseBusy = ref(false),
  releaseError = ref(""),
  releaseName = ref(""),
  page = ref(1);
const overwriteTarget = ref<{
  id: string;
  revision: number;
  server_id: string;
  name: string;
}>();
const overwritePlan = ref<{
  database_id: string;
  revision: number;
  charset: string;
  collation: string;
  connections: number;
}>();
const planBusy = ref(false),
  planError = ref("");
const isOverwrite = computed(
  () => !!overwriteTarget.value || !!selected.value?.target_database_id,
);
const visible = computed(() =>
  rows.value.slice((page.value - 1) * 5, page.value * 5),
);
function fileSize(bytes: number) {
  const units = ["B", "KiB", "MiB", "GiB"];
  let i = 0;
  while (bytes >= 1024 && i < 3) {
    bytes /= 1024;
    i++;
  }
  return bytes.toFixed(i ? 1 : 0) + " " + units[i];
}
const serverName = (id: string) =>
  props.servers.find((s) => s.id === id)?.name || id;
const labels: Record<string, string> = {
  awaiting_upload: "待上传",
  staged: "待导入",
  queued: "任务已提交",
  succeeded: "已完成",
  released: "源文件已清理",
  failed: "失败，可核对重试",
};
let xhr: XMLHttpRequest | undefined, timer: ReturnType<typeof setInterval>;
let planGeneration = 0;
async function refresh() {
  try {
    rows.value = await props.api<Import[]>("/databases/imports");
    error.value = "";
  } catch (e) {
    error.value = (e as Error).message;
  }
}
function begin(row?: Import) {
  planGeneration++;
  planBusy.value = false;
  overwriteTarget.value = row?.target_database_id
    ? {
        id: row.target_database_id,
        revision: row.target_revision!,
        server_id: row.server_id,
        name: row.name,
      }
    : undefined;
  overwritePlan.value = undefined;
  planError.value = "";
  selected.value = row;
  serverID.value =
    row?.server_id ||
    props.servers.find((s) => s.status === "running")?.id ||
    "";
  name.value = row?.name || "";
  file.value = undefined;
  confirm.value = "";
  progress.value = 0;
  formError.value = "";
  open.value = true;
  if (overwriteTarget.value) loadOverwritePlan();
}
async function loadOverwritePlan() {
  if (!overwriteTarget.value) return;
  const target = { ...overwriteTarget.value },
    generation = ++planGeneration;
  planBusy.value = true;
  try {
    const plan = await props.api<NonNullable<typeof overwritePlan.value>>(
      "/databases/items/" + target.id + "/overwrite-plan",
    );
    if (generation !== planGeneration) return;
    if (plan.database_id !== target.id || plan.revision !== target.revision)
      throw new Error("目标修订已变化，请从数据库列表重新发起覆盖导入");
    overwritePlan.value = plan;
    planError.value = "";
  } catch (e) {
    if (generation === planGeneration) planError.value = (e as Error).message;
  } finally {
    if (generation === planGeneration) planBusy.value = false;
  }
}
function beginOverwrite(db: {
  id: string;
  revision: number;
  server_id: string;
  name: string;
}) {
  begin();
  overwriteTarget.value = { ...db };
  serverID.value = db.server_id;
  name.value = db.name;
  loadOverwritePlan();
}
defineExpose({ begin, beginOverwrite });
function choose(e: Event) {
  file.value = (e.target as HTMLInputElement).files?.[0];
}
function upload(v: Import, f: File): Promise<Import> {
  return new Promise((resolve, reject) => {
    const request = new XMLHttpRequest();
    xhr = request;
    request.open("POST", apiURL("/databases/imports/" + v.id + "/upload"));
    request.setRequestHeader("Content-Type", "application/octet-stream");
    request.setRequestHeader("X-CSRF-Token", props.csrf);
    request.timeout = 1800000;
    request.upload.onprogress = (e) => {
      if (e.lengthComputable)
        progress.value = Math.round((e.loaded / e.total) * 100);
    };
    request.onload = () => {
      xhr = undefined;
      let out: any;
      try {
        out = JSON.parse(request.responseText);
      } catch {
        reject(new Error("无法读取上传结果，请刷新导入记录"));
        return;
      }
      if (request.status === 200) resolve(out);
      else reject(new Error(out.error || "上传失败"));
    };
    request.onerror = () => reject(new Error("上传连接中断，可使用此记录重传"));
    request.ontimeout = () => reject(new Error("上传超时，可使用此记录重传"));
    request.onabort = () => reject(new Error("上传已取消，可使用此记录重传"));
    request.send(f);
  });
}
async function submit() {
  if (busy.value) return;
  busy.value = true;
  formError.value = "";
  try {
    if (
      isOverwrite.value &&
      (planBusy.value || !overwritePlan.value || planError.value)
    )
      throw new Error(planError.value || "请等待覆盖预检完成");
    if (!selected.value) {
      if (
        !file.value ||
        !file.value.size ||
        file.value.size > 512 * 1024 * 1024
      )
        throw new Error("请选择 1 字节至 512 MiB 的普通 SQL 文件");
      selected.value = overwriteTarget.value
        ? await props.api<Import>(
            "/databases/items/" +
              overwriteTarget.value.id +
              "/overwrite-upload",
            "POST",
            {
              revision: overwriteTarget.value.revision,
              bytes: file.value.size,
            },
          )
        : await props.api<Import>("/databases/imports", "POST", {
            server_id: serverID.value,
            name: name.value,
            bytes: file.value.size,
          });
    }
    if (selected.value.state === "awaiting_upload") {
      if (!file.value || file.value.size !== selected.value.bytes)
        throw new Error("请选择原文件，文件长度需要与此上传记录一致");
      selected.value = await upload(selected.value, file.value);
      await refresh();
      return;
    }
    if (confirm.value !== selected.value.name)
      throw new Error("请输入目标数据库名确认");
    const j = await props.api<{ job_id: string }>(
      "/databases/imports/" + selected.value.id + "/start",
      "POST",
      { confirm_name: confirm.value },
    );
    open.value = false;
    await refresh();
    emit("changed");
    await props.onJob(j.job_id);
  } catch (e) {
    formError.value = (e as Error).message;
    await refresh();
  } finally {
    busy.value = false;
    xhr = undefined;
  }
}
async function remove(row: Import) {
  try {
    await ElMessageBox.confirm(
      `移除“${row.name}”的未执行上传记录及 SQL 暂存文件。`,
      "移除 SQL 上传",
      { confirmButtonText: "移除上传", cancelButtonText: "取消" },
    );
    await props.api("/databases/imports/" + row.id, "DELETE");
    await refresh();
  } catch (e) {
    if (e !== "cancel" && e !== "close") ElMessage.error((e as Error).message);
  }
}
function reviewRelease(row: Import) {
  release.value = row;
  releaseName.value = "";
  releaseError.value = "";
  releaseOpen.value = true;
}
async function submitRelease() {
  if (!release.value || releaseBusy.value) return;
  releaseBusy.value = true;
  releaseError.value = "";
  try {
    await props.api(
      "/databases/imports/" + release.value.id + "/release",
      "POST",
      {
        confirm_name: releaseName.value,
      },
    );
    releaseOpen.value = false;
    await refresh();
    ElMessage.success("SQL 上传文件已清理，导入记录已保留");
  } catch (e) {
    releaseError.value = (e as Error).message;
  } finally {
    releaseBusy.value = false;
  }
}
onMounted(() => {
  refresh();
  timer = setInterval(refresh, 4000);
});
onUnmounted(() => {
  clearInterval(timer);
  xhr?.abort();
});
</script>
<template>
  <section class="panel-card list-card sql-import-section">
    <div class="table-toolbar">
      <div>
        <h2>SQL 导入</h2>
        <small class="muted"
          >导入到新数据库，或从数据库列表发起覆盖导入。</small
        >
      </div>
      <el-button type="primary" @click="begin()">导入 SQL</el-button>
    </div>
    <el-alert v-if="error" :title="error" type="error" :closable="false" />
    <div v-if="!rows.length" class="import-empty">
      支持 MySQL 8.0 / 8.4，上传后确认目标，再交由任务执行。
    </div>
    <article
      v-for="row in visible"
      :key="row.id"
      class="import-row"
      :data-import-id="row.id"
    >
      <div class="import-meta">
        <strong>{{ row.name }}</strong
        ><small
          >{{ serverName(row.server_id) }} · {{ fileSize(row.bytes) }}</small
        ><small
          >{{ row.target_database_id ? "覆盖已有库 · " : "新库导入 · "
          }}{{
            row.target_database_id && row.state === "failed"
              ? "未交付，请查看恢复结果"
              : labels[row.state] || row.state
          }}</small
        >
      </div>
      <div class="import-actions">
        <el-button
          v-if="['awaiting_upload', 'staged'].includes(row.state)"
          @click="begin(row)"
          >{{ row.state === "staged" ? "确认导入" : "继续上传" }}</el-button
        ><el-button v-if="row.job_id" @click="onJob(row.job_id)"
          >查看任务</el-button
        ><el-button v-else text @click="remove(row)">移除</el-button>
        <el-button v-if="row.state === 'succeeded'" @click="reviewRelease(row)"
          >清理上传文件</el-button
        >
      </div>
    </article>
    <el-pagination
      v-if="rows.length > 5"
      v-model:current-page="page"
      :page-size="5"
      :total="rows.length"
      layout="prev, pager, next"
    />
  </section>
  <el-dialog
    v-model="open"
    :title="isOverwrite ? '覆盖已有数据库' : '导入到新数据库'"
    width="600px"
    class="sql-import-dialog"
    :close-on-click-modal="!busy"
    :close-on-press-escape="!busy"
    :show-close="!busy"
    destroy-on-close
  >
    <el-alert
      v-if="formError"
      type="error"
      :title="formError"
      :closable="false"
    />
    <el-alert
      v-if="planError"
      :title="planError"
      type="error"
      :closable="false"
    />
    <div v-if="isOverwrite" class="import-review">
      <strong>替换 {{ name }} 的全部内容</strong>
      <p>
        任务先验证原密码，再隔离应用连接并备份当前数据、执行
        SQL。失败时自动恢复原数据，保留操作前副本、库名和原密码。备份期间会短暂锁定同实例写入；覆盖期间应用无法访问此库。
      </p>
      <small
        >目标修订 {{ overwriteTarget?.revision }} · 保留库 ID
        和原应用账号</small
      >
      <small v-if="planBusy">正在检查目标和访问依赖…</small>
      <small v-else-if="overwritePlan"
        >已通过依赖预检 · {{ overwritePlan.connections }} 个应用连接 ·
        {{ overwritePlan.charset }} / {{ overwritePlan.collation }}</small
      >
      <el-button
        v-if="planError"
        :disabled="busy || planBusy"
        @click="loadOverwritePlan"
        >重新检查</el-button
      >
    </div>
    <el-form label-position="top" @submit.prevent="submit">
      <el-form-item label="目标 MySQL 实例"
        ><el-select
          v-model="serverID"
          aria-label="导入目标实例"
          :disabled="busy || !!selected || isOverwrite"
          style="width: 100%"
          ><el-option
            v-for="s in servers"
            :key="s.id"
            :value="s.id"
            :label="s.name + ' · ' + s.release_id"
            :disabled="s.status !== 'running'" /></el-select
      ></el-form-item>
      <el-form-item :label="isOverwrite ? '目标数据库名' : '新数据库名'"
        ><el-input
          v-model="name"
          aria-label="导入新数据库名"
          placeholder="例如 website_data"
          :disabled="busy || !!selected || isOverwrite"
          maxlength="32"
        /><small v-if="!isOverwrite" class="muted"
          >小写字母开头，可用数字及下划线，最多 32
          位。目标名称必须尚未使用。</small
        ></el-form-item
      >
      <el-form-item v-if="selected?.state !== 'staged'" label="SQL 文件"
        ><input
          type="file"
          accept=".sql,application/sql,text/plain"
          aria-label="SQL 文件"
          :disabled="busy"
          @change="choose"
        /><small class="muted"
          >普通 SQL，最大 512 MiB；压缩包请先解压。原始 SQL
          按目标库权限执行。</small
        ></el-form-item
      >
      <el-progress
        v-if="busy && selected?.state === 'awaiting_upload'"
        :percentage="progress"
      />
      <template v-if="selected?.state === 'staged'"
        ><div class="import-review">
          <strong>文件已上传并校验</strong
          ><small>{{ fileSize(selected.bytes) }}</small
          ><code>SHA-256 {{ selected.sha256 }}</code>
          <p v-if="!isOverwrite">
            将新建
            {{
              selected.name
            }}。执行失败时保留任务，成功前不提供应用连接信息。跨库语句和无权使用的
            DEFINER 会导致导入失败。
          </p>
        </div>
        <el-form-item
          :label="isOverwrite ? '确认覆盖数据库名' : '确认新数据库名'"
          ><el-input
            v-model="confirm"
            aria-label="确认导入数据库名"
            :disabled="busy" /></el-form-item
      ></template>
    </el-form>
    <template #footer
      ><el-button v-if="busy && xhr" @click="xhr?.abort()">取消上传</el-button
      ><el-button v-else :disabled="busy" @click="open = false">关闭</el-button
      ><el-button
        type="primary"
        :loading="busy"
        :disabled="
          !serverID ||
          !name ||
          (isOverwrite && (planBusy || !overwritePlan || !!planError)) ||
          (selected?.state === 'staged' ? confirm !== name : !file)
        "
        @click="submit"
        >{{
          selected?.state === "staged"
            ? isOverwrite
              ? "备份并替换数据库"
              : "创建新库并导入"
            : "上传并校验"
        }}</el-button
      ></template
    >
  </el-dialog>
  <el-dialog
    v-model="releaseOpen"
    title="清理 SQL 上传文件"
    width="560px"
    class="sql-import-dialog"
    :close-on-click-modal="!releaseBusy"
    :close-on-press-escape="!releaseBusy"
    :show-close="!releaseBusy"
    destroy-on-close
  >
    <el-alert
      v-if="releaseError"
      :title="releaseError"
      type="error"
      :closable="false"
    />
    <div v-if="release" class="import-review">
      <strong>{{ release.name }}</strong>
      <small
        >{{ serverName(release.server_id) }} · 释放
        {{ fileSize(release.bytes) }}</small
      >
      <code>SHA-256 {{ release.sha256 }}</code>
      <code>原任务 {{ release.job_id }}</code>
      <p>
        移除这次导入的上传源文件，保留数据库当前数据、已有备份和任务记录。清理后无法再下载这份上传文件；再次导入需要重新上传。
      </p>
    </div>
    <el-form label-position="top" @submit.prevent="submitRelease">
      <el-form-item label="确认导入数据库名">
        <el-input
          v-model="releaseName"
          aria-label="确认清理数据库名"
          :disabled="releaseBusy"
        />
      </el-form-item>
    </el-form>
    <template #footer>
      <el-button :disabled="releaseBusy" @click="releaseOpen = false"
        >取消</el-button
      >
      <el-button
        type="danger"
        :loading="releaseBusy"
        :disabled="releaseName !== release?.name"
        @click="submitRelease"
        >清理上传文件</el-button
      >
    </template>
  </el-dialog>
</template>
<style scoped>
.import-empty {
  padding: 24px;
  color: var(--text-secondary, #718078);
  font-size: 13px;
}
.import-row {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 16px;
  padding: 18px 22px;
  border-top: 1px solid #edf0ef;
}
.import-meta {
  display: grid;
  gap: 7px;
  min-width: 0;
}
.import-meta strong {
  overflow-wrap: anywhere;
}
.import-meta small {
  color: #7b8982;
  font-size: 12px;
}
.import-actions {
  display: flex;
  flex-wrap: wrap;
  gap: 6px;
  flex-shrink: 0;
}
.import-actions .el-button {
  margin: 0;
}
.import-review {
  background: #f3f8f6;
  border: 1px solid #dbe8e1;
  border-radius: 8px;
  padding: 16px;
  margin-bottom: 18px;
  display: grid;
  gap: 10px;
}
.import-review code {
  font-size: 11px;
  overflow-wrap: anywhere;
}
.import-review p {
  font-size: 13px;
  line-height: 1.8;
  margin: 0;
}
.sql-import-section .el-pagination {
  margin: 16px;
}
.el-form-item small {
  line-height: 1.7;
  margin-top: 6px;
}
.el-form-item input[type="file"] {
  max-width: 100%;
}
@media (max-width: 680px) {
  .import-row {
    align-items: flex-start;
    flex-direction: column;
    padding: 16px;
  }
  .import-actions {
    align-self: flex-end;
  }
  .sql-import-section .table-toolbar {
    align-items: flex-start;
  }
}
</style>
<style>
.sql-import-dialog {
  max-height: 90vh;
  max-width: calc(100vw - 24px);
  margin-top: 5vh;
  display: flex;
  flex-direction: column;
}
.sql-import-dialog .el-dialog__body {
  overflow: auto;
}
.sql-import-dialog .el-dialog__footer {
  flex-shrink: 0;
}
.sql-import-dialog .el-alert {
  margin-bottom: 16px;
}
</style>
