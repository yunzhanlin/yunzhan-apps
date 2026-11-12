<script setup lang="ts">
import { computed, onBeforeUnmount, reactive, ref, watch } from "vue";
import { formatPanelDateTime } from "./panelTime";

const props = defineProps<{
  api: <T>(path: string, method?: string, body?: unknown, idempotencyKey?: string, signal?: AbortSignal) => Promise<T>;
  active: boolean;
  enabled: boolean;
  sites: { id: string; name: string; domain: string }[];
}>();

type Transfer = {
  time: string;
  site_id: string;
  username: string;
  client_ip: string;
  direction: "upload" | "download";
  path: string;
  bytes: string;
  kib_per_second: number;
};

type History = {
  from: string;
  to: string;
  events: Transfer[];
  source_limit: number;
  has_more: boolean;
};

const filters = reactive({ minutes: "60", site_id: "", username: "", direction: "" });
const end = ref<Date | null>(null);
const afterToday = (date: Date) => date.getTime() > Date.now();
const query = computed(() => {
  const params = new URLSearchParams({ ...filters });
  if (end.value instanceof Date && Number.isFinite(end.value.getTime())) params.set("end", end.value.toISOString());
  return params.toString();
});
const siteLabels = computed(() => new Map(props.sites.map(site => [site.id, site.name])));
const history = ref<History>();
const busy = ref(false);
const error = ref("");
let generation = 0;
let pending: AbortController | undefined;

function reset() {
  generation++;
  pending?.abort();
  pending = undefined;
  busy.value = false;
  history.value = undefined;
  error.value = "";
}

async function refresh() {
  if (!props.active || !props.enabled || busy.value) return;
  const request = ++generation;
  const requested = query.value;
  pending = new AbortController();
  busy.value = true;
  history.value = undefined;
  error.value = "";
  try {
    const data = await props.api<History>("/app-modules/pure-ftpd/transfers?" + requested, "GET", undefined, undefined, pending.signal);
    if (request === generation) history.value = data;
  } catch (cause) {
    if (request === generation) error.value = cause instanceof Error ? cause.message : String(cause);
  } finally {
    if (request === generation) {
      pending = undefined;
      busy.value = false;
    }
  }
}

watch(() => [props.active, props.enabled], () => {
  reset();
  if (props.active && props.enabled) void refresh();
}, { immediate: true });
watch(query, reset);
onBeforeUnmount(reset);
</script>

<template>
  <section aria-label="FTP 传输日志">
    <el-alert v-if="!enabled" title="签名安装或更新 Pure-FTPd 后可查询传输日志。" type="info" :closable="false" />
    <template v-else>
      <el-form class="transfer-filters" label-position="top" @submit.prevent="refresh">
        <el-form-item label="时间范围">
          <el-select v-model="filters.minutes" aria-label="时间范围">
            <el-option label="最近 15 分钟" value="15" />
            <el-option label="最近 1 小时" value="60" />
            <el-option label="最近 24 小时" value="1440" />
            <el-option label="最近 7 天" value="10080" />
          </el-select>
        </el-form-item>
        <el-form-item label="结束时间">
          <el-date-picker v-model="end" type="datetime" placeholder="当前时间" aria-label="结束时间"
            :disabled-date="afterToday" />
        </el-form-item>
        <el-form-item label="站点">
          <el-select v-model="filters.site_id" filterable aria-label="站点">
            <el-option label="所有站点" value="" />
            <el-option v-for="site in sites" :key="site.id" :label="site.name + ' · ' + site.domain" :value="site.id" />
          </el-select>
        </el-form-item>
        <el-form-item label="FTP 账户">
          <el-input v-model.trim="filters.username" maxlength="32" clearable aria-label="FTP 账户" placeholder="全部账户" />
        </el-form-item>
        <el-form-item label="传输方向">
          <el-select v-model="filters.direction" aria-label="传输方向">
            <el-option label="全部方向" value="" />
            <el-option label="上传" value="upload" />
            <el-option label="下载" value="download" />
          </el-select>
        </el-form-item>
        <el-button native-type="submit" type="primary" :loading="busy">查询传输日志</el-button>
      </el-form>
      <el-alert v-if="error" :title="error" type="error" :closable="false" role="alert" />
      <template v-if="history">
        <p role="status">{{ formatPanelDateTime(history.from) }} 至 {{ formatPanelDateTime(history.to) }}，当前日志返回 {{ history.events.length }} 条。</p>
        <el-alert v-if="history.has_more" type="warning" :closable="false"
          :title="'已达到结果或源日志扫描上限（最多 ' + history.source_limit + ' 条源记录）。可调整结束时间，或缩短查询时段。'" />
        <el-table :data="history.events" empty-text="当前保留的日志中没有符合条件的传输" aria-label="FTP 传输记录">
          <el-table-column label="时间" min-width="175">
            <template #default="{ row }">{{ formatPanelDateTime(row.time) }}</template>
          </el-table-column>
          <el-table-column label="站点" min-width="130" show-overflow-tooltip>
            <template #default="{ row }">{{ siteLabels.get(row.site_id) ?? row.site_id }}</template>
          </el-table-column>
          <el-table-column prop="username" label="账户" min-width="105" />
          <el-table-column prop="client_ip" label="客户端 IP" min-width="125" />
          <el-table-column label="方向" width="65">
            <template #default="{ row }">{{ row.direction === 'upload' ? '上传' : '下载' }}</template>
          </el-table-column>
          <el-table-column prop="path" label="站点内文件" min-width="180" show-overflow-tooltip />
          <el-table-column label="字节" min-width="105" align="right">
            <template #default="{ row }">{{ BigInt(row.bytes).toLocaleString('zh-CN') }}</template>
          </el-table-column>
          <el-table-column prop="kib_per_second" label="KiB/s" min-width="80" align="right" />
        </el-table>
      </template>
    </template>
  </section>
</template>

<style scoped>
.transfer-filters {
  display: grid;
  align-items: end;
  gap: 12px;
  grid-template-columns: repeat(auto-fit, minmax(min(100%, 150px), 1fr));
  margin-bottom: 12px;
}
.transfer-filters :deep(.el-form-item) { margin-bottom: 0; }
.transfer-filters :deep(.el-select), .transfer-filters :deep(.el-date-editor) { width: 100%; }
</style>
