<script setup lang="ts">
import { computed, onBeforeUnmount, ref, watch } from "vue";
import { canReadPath, type AccessPlan } from "./menuPermissions";
import {
  validIDSRuleProfile,
  type IDSRuleProfile,
} from "./networkIDSOperations";
type API = <T>(
  path: string,
  method?: string,
  body?: unknown,
  idempotencyKey?: string,
) => Promise<T>;
interface Selection {
  feed_id: string;
  app_version: string;
  app_manifest_sha256: string;
  rule_manifest_sha256: string;
}
interface Available {
  selection: Selection;
  assets: { name: string; sha256: string; bytes: number }[];
  download_bytes: number;
  supported: boolean;
  detail?: string;
}
interface Page {
  source: {
    stale: boolean;
    checked_at?: string;
    fetched_at?: string;
    error?: string;
  };
  available: Available[];
  stored: {
    state_known: boolean;
    rows: { selection: Selection; state: string; error?: string }[];
    retained_stages: number;
    error?: string;
  };
  jobs: { id: string; state: string; error: string; created_at: string }[];
  data_only: boolean;
  capture_started: boolean;
  native_syntax_verified: boolean;
}
const props = defineProps<{
  api: API;
  installed: boolean;
  access?: AccessPlan | null;
  onJob: (id: string) => Promise<void>;
  onSelect?: (choice: IDSRuleProfile) => Promise<void>;
  revision?: number;
  nativePending?: boolean;
  activeProfile?: unknown;
}>();
const page = ref<Page>(),
  busy = ref(false),
  error = ref(""),
  acceptedJobID = ref("");
const authorized = computed(
  () =>
    !!props.access &&
    props.access.menu_ids.includes("security") &&
    canReadPath(props.access, "/software/network-threat-detection/rule-feeds"),
);
let generation = 0,
  pending: { selection: string; key: string } | undefined;
function invalidate() {
  generation++;
  page.value = undefined;
  pending = undefined;
  acceptedJobID.value = "";
  error.value = "";
  busy.value = false;
}
onBeforeUnmount(invalidate);
const selectionID = (selection: Selection) => JSON.stringify(selection);
function selectionShape(value: unknown): value is Selection {
  if (!value || typeof value !== "object" || Array.isArray(value)) return false;
  const fields = [
    "feed_id",
    "app_version",
    "app_manifest_sha256",
    "rule_manifest_sha256",
  ];
  const record = value as Record<string, unknown>;
  return (
    Object.keys(record).length === fields.length &&
    fields.every(
      (name) =>
        Object.hasOwn(record, name) &&
        typeof record[name] === "string" &&
        record[name].length <= 64,
    )
  );
}
function validSelection(value: unknown) {
  return (
    selectionShape(value) &&
    /^et-open-web-[0-9]{8}$/.test(value.feed_id) &&
    /^[0-9]+(?:\.[0-9]+){0,3}(?:-[A-Za-z0-9]+(?:[.-][A-Za-z0-9]+)*)?$/.test(
      value.app_version,
    ) &&
    value.app_version.length <= 64 &&
    /^[a-f0-9]{64}$/.test(value.app_manifest_sha256) &&
    /^[a-f0-9]{64}$/.test(value.rule_manifest_sha256)
  );
}
function validPage(result: Page) {
  const limits: Record<string, number> = {
    "manifest.json": 32 << 10,
    "et-open.rules": 8 << 20,
    LICENSE: 128 << 10,
    "BSD-License.txt": 128 << 10,
    "classification.config": 128 << 10,
    "reference.config": 128 << 10,
  };
  return (
    result?.data_only === true &&
    result.capture_started === false &&
    result.native_syntax_verified === false &&
    typeof result.source?.stale === "boolean" &&
    Array.isArray(result.available) &&
    result.available.length <= 1 &&
    result.available.every(
      (row) =>
        validSelection(row.selection) &&
        typeof row.supported === "boolean" &&
        Array.isArray(row.assets) &&
        row.assets.length === 6 &&
        new Set(row.assets.map((asset) => asset.name)).size === 6 &&
        row.assets.every(
          (asset) =>
            Object.hasOwn(limits, asset.name) &&
            Number.isInteger(asset.bytes) &&
            asset.bytes > 0 &&
            asset.bytes <= limits[asset.name] &&
            /^[a-f0-9]{64}$/.test(asset.sha256),
        ) &&
        row.download_bytes ===
          row.assets.reduce((bytes, asset) => bytes + asset.bytes, 0),
    ) &&
    typeof result.stored?.state_known === "boolean" &&
    Number.isInteger(result.stored.retained_stages) &&
    result.stored.retained_stages >= 0 &&
    result.stored.retained_stages <= 8 &&
    Array.isArray(result.stored.rows) &&
    result.stored.rows.length <= 8 &&
    result.stored.rows.every((row) =>
      ["verified-data-only", "verified-retained-data"].includes(row.state)
        ? validSelection(row.selection) &&
          (row.state !== "verified-retained-data" ||
            (typeof row.error === "string" && !!row.error))
        : row.state === "unverified" &&
          selectionShape(row.selection) &&
          typeof row.error === "string" &&
          !!row.error,
    ) &&
    Array.isArray(result.jobs) &&
    result.jobs.length <= 16 &&
    result.jobs.every(
      (job) =>
        /^[a-f0-9]{32}$/.test(job.id) &&
        [
          "queued",
          "running",
          "succeeded",
          "failed",
          "needs_attention",
        ].includes(job.state) &&
        typeof job.error === "string" &&
        typeof job.created_at === "string",
    )
  );
}
async function refresh(force = false) {
  if (!props.installed || !authorized.value || busy.value) return;
  const token = ++generation;
  busy.value = true;
  error.value = "";
  try {
    const result = await props.api<Page>(
      "/software/network-threat-detection/rule-feeds" +
        (force ? "?refresh=1" : ""),
    );
    if (token !== generation) return;
    if (!validPage(result))
      throw new Error("规则数据状态契约不能核对；未宣称原生校验或启用采集");
    page.value = result;
  } catch (e) {
    if (token === generation) {
      page.value = undefined;
      error.value = e instanceof Error ? e.message : String(e);
    }
  } finally {
    if (token === generation) busy.value = false;
  }
}
function canInstall(row: Available) {
  return (
    authorized.value &&
    props.installed &&
    !busy.value &&
    page.value?.source.stale === false &&
    page.value?.stored.state_known === true &&
    row.supported === true
  );
}
function canChoose() {
  return (
    authorized.value &&
    !!activeProfile.value &&
    props.installed &&
    props.access?.role === "admin" &&
    !busy.value &&
    !props.nativePending &&
    !!props.onSelect &&
    Number.isSafeInteger(props.revision) &&
    (props.revision || 0) >= 1
  );
}
function canSelect(row: Page["stored"]["rows"][number]) {
  return (
    canChoose() &&
    page.value?.stored.state_known === true &&
    row.state === "verified-data-only" &&
    validSelection(row.selection)
  );
}
async function selectProfile(choice: IDSRuleProfile) {
  if (!canChoose() || !validIDSRuleProfile(choice)) return;
  if (
    choice.source === "verified-feed" &&
    !page.value?.stored.rows.some(
      (row) =>
        canSelect(row) &&
        selectionID(row.selection) === selectionID(choice.selection!),
    )
  )
    return;
  // Hand the parent detached primitive bindings, not a reactive table row.
  // The retry payload must not change when the inventory is refreshed.
  const detached: IDSRuleProfile = choice.source === "original"
    ? {source:"original"}
    : {source:"verified-feed",selection:{feed_id:choice.selection!.feed_id,app_version:choice.selection!.app_version,app_manifest_sha256:choice.selection!.app_manifest_sha256,rule_manifest_sha256:choice.selection!.rule_manifest_sha256}};
  await props.onSelect!(detached);
}
const activeProfile = computed(() => {
  const value = props.activeProfile as
    | {
        source?: unknown;
        state?: unknown;
        selection?: unknown;
        warning?: unknown;
        current_for_new_selection?: unknown;
        age_days?: unknown;
      }
    | undefined;
  if (!value || typeof value !== "object" || Array.isArray(value))
    return undefined;
  if (value.source === "original" && value.state === "fixed-indicators")
    return { source: "original", label: "原创指标规则", warning: "" };
  if (
    value.source === "verified-feed" &&
    value.state === "verified-for-committed-use" &&
    validIDSRuleProfile({
      source: "verified-feed",
      selection: value.selection,
    }) &&
    typeof value.warning !== "object" &&
    (value.warning === undefined || typeof value.warning === "string") &&
    typeof value.current_for_new_selection === "boolean" &&
    Number.isInteger(value.age_days) &&
    Number(value.age_days) >= 0
  )
    return {
      source: "verified-feed",
      label: (value.selection as Selection).feed_id,
      warning: value.warning as string | undefined,
    };
  return undefined;
});
async function install(row: Available) {
  if (!canInstall(row)) return;
  const token = ++generation,
    identity = selectionID(row.selection);
  if (!pending || pending.selection !== identity)
    pending = { selection: identity, key: crypto.randomUUID() };
  const key = pending.key;
  busy.value = true;
  error.value = "";
  try {
    const result = await props.api<{
      job_id: string;
      data_only: boolean;
      capture_started: boolean;
      native_syntax_verified: boolean;
    }>(
      "/software/network-threat-detection/rule-feeds/install",
      "POST",
      row.selection,
      key,
    );
    if (token !== generation) return;
    if (
      !/^[a-f0-9]{32}$/.test(result.job_id) ||
      result.data_only !== true ||
      result.capture_started !== false ||
      result.native_syntax_verified !== false
    )
      throw new Error("安装响应身份不完整；保留原提交键，未另建任务");
    pending = undefined;
    acceptedJobID.value = result.job_id;
    if (props.access?.menu_ids.includes("audit"))
      await props.onJob(result.job_id);
  } catch (e) {
    if (token === generation)
      error.value = e instanceof Error ? e.message : String(e);
  } finally {
    if (token === generation) busy.value = false;
  }
}
watch(
  () => [props.installed, authorized.value, props.access] as const,
  () => {
    invalidate();
    if (props.installed && authorized.value) void refresh();
  },
  { immediate: true },
);
const stateLabels: Record<string, string> = {
  queued: "等待存放",
  running: "存放进行中",
  succeeded: "仅数据存放完成",
  failed: "失败 · 原记录保留",
  needs_attention: "未核实完成 · 保留现场",
};
</script>
<template>
  <section class="ids-feeds" aria-label="IDS 规则数据管理" v-loading="busy">
    <div class="ids-feed-heading">
      <h3>规则数据与更新</h3>
      <el-button
        :disabled="busy || !installed || !authorized"
        @click="refresh(true)"
        >检查规则目录</el-button
      >
    </div>
    <el-alert
      title="下载存放不启用检测。规则选择是独立后台事务：重新验签、原生校验；运行中的采集会重启并核对新鲜计数，停止的采集仍保持停止。任何失败保留原任务与恢复记录，不自动封禁。"
      type="info"
      :closable="false"
    />
    <p v-if="!installed">先安装网络威胁检测模块；查看本页不会自动安装应用。</p>
    <p v-else-if="!authorized">
      当前用户没有软件管理权限，未读取或提交规则任务。
    </p>
    <p>
      已提交的实际规则：{{
        activeProfile?.label || "尚未核对；先刷新实际采集报表"
      }}
      · 配置修订：{{ revision || "未核对" }}
    </p>
    <el-alert
      v-if="activeProfile?.warning"
      :title="activeProfile.warning"
      type="warning"
      :closable="false"
    />
    <el-button
      :disabled="!canChoose() || activeProfile?.source !== 'verified-feed'"
      @click="selectProfile({ source: 'original' })"
      >后台切回原创指标规则</el-button
    >
    <el-alert v-if="error" :title="error" type="error" :closable="false" />
    <el-alert
      v-if="acceptedJobID"
      :title="`服务器已接受任务 ${acceptedJobID}；未宣称存放完成或启用检测，可检查目录查看后续状态。`"
      type="info"
      :closable="false"
    />
    <template v-if="page">
      <el-alert
        v-if="page.source.stale"
        title="目录来自过期缓存，不能确认最新规则；安装操作已禁用。"
        type="warning"
        :closable="false"
      />
      <el-alert
        v-if="!page.stored.state_known"
        :title="
          page.stored.error ||
          '本机规则清单未核对完整；未知不是已安装或零威胁。'
        "
        type="warning"
        :closable="false"
      />
      <p>
        已签名应用声明 · 目录检查：{{
          page.source.checked_at || page.source.fetched_at || "未确认"
        }}。仅点击下载时拉取闭合规则包；保留许可证与原始签名。
      </p>
      <p v-if="!page.available.length">
        当前已签名应用没有发布此规则数据包；不显示虚构的新版本。
      </p>
      <article
        v-for="row in page.available"
        :key="selectionID(row.selection)"
        class="ids-feed-card"
      >
        <div class="ids-feed-heading">
          <strong>{{ row.selection.feed_id }}</strong
          ><el-button
            type="primary"
            :disabled="!canInstall(row)"
            @click="install(row)"
            >{{
              pending?.selection === selectionID(row.selection)
                ? "以原提交键重试"
                : "新建下载存放任务"
            }}</el-button
          >
        </div>
        <p>
          应用版本 {{ row.selection.app_version }} ·
          {{ row.assets.length }} 个文件 · {{ row.download_bytes }} 字节
        </p>
        <p class="ids-feed-digest">
          应用清单 SHA-256：{{ row.selection.app_manifest_sha256
          }}<br />规则清单 SHA-256：{{ row.selection.rule_manifest_sha256 }}
        </p>
        <el-alert
          v-if="row.detail"
          :title="row.detail"
          type="warning"
          :closable="false"
        />
        <el-collapse
          ><el-collapse-item title="已签名文件与大小"
            ><el-table :data="row.assets" size="small"
              ><el-table-column
                prop="name"
                label="文件"
                min-width="180" /><el-table-column
                prop="bytes"
                label="字节"
                width="105" /><el-table-column
                prop="sha256"
                label="SHA-256"
                min-width="270" /></el-table></el-collapse-item
        ></el-collapse>
      </article>
      <h4>本机独立核对结果</h4>
      <p>
        最多保留 8 个数据版本或失败阶段；保留阶段
        {{ page.stored.retained_stages }} 个，不自动删除旧副本。
      </p>
      <el-table
        :data="page.stored.rows"
        border
        empty-text="未返回已存放规则；不代表没有威胁"
      >
        <el-table-column label="规则身份" min-width="205"
          ><template #default="{ row }">{{
            row.selection.feed_id || "身份尚未核实"
          }}</template></el-table-column
        >
        <el-table-column label="状态" min-width="220"
          ><template #default="{ row }">{{
            row.state === "verified-data-only"
              ? "签名数据已核对 · 未校验或启用"
              : row.state === "verified-retained-data"
                ? "签名留存数据 · 当前授权过期，不可新选"
                : "未核对完成"
          }}</template></el-table-column
        >
        <el-table-column prop="error" label="核对问题" min-width="220" />
        <el-table-column label="规则选择" min-width="210"
          ><template #default="{ row }"
            ><el-button
              :disabled="!canSelect(row)"
              @click="
                selectProfile({
                  source: 'verified-feed',
                  selection: row.selection,
                })
              "
              >后台校验并选择此规则</el-button
            ></template
          ></el-table-column
        >
      </el-table>
      <h4>最近 16 个存放任务</h4>
      <el-table :data="page.jobs" border empty-text="尚无规则存放任务">
        <el-table-column prop="created_at" label="提交时间" min-width="190" />
        <el-table-column prop="id" label="任务标识" min-width="245" />
        <el-table-column label="状态" min-width="190"
          ><template #default="{ row }">{{
            stateLabels[row.state] || "状态未知"
          }}</template></el-table-column
        >
        <el-table-column
          prop="error"
          label="失败 / 未核实原因"
          min-width="220"
        />
      </el-table>
    </template>
  </section>
</template>
<style scoped>
.ids-feeds {
  display: grid;
  gap: 14px;
  min-width: 0;
}
.ids-feed-heading {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 12px;
  flex-wrap: wrap;
}
.ids-feed-heading h3,
.ids-feeds h4 {
  margin: 0;
}
.ids-feed-card {
  border: 1px solid #dce5ed;
  border-radius: 8px;
  padding: 16px;
  display: grid;
  gap: 10px;
}
.ids-feed-card p,
.ids-feeds p {
  margin: 0;
  line-height: 1.65;
  color: #62718b;
}
.ids-feed-digest {
  overflow-wrap: anywhere;
  font-size: 12px;
}
@media (max-width: 600px) {
  .ids-feed-heading {
    align-items: flex-start;
    flex-direction: column;
  }
}
</style>
