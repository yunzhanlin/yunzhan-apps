<script setup lang="ts">
import { computed, onBeforeUnmount, ref, watch } from "vue";

const props = defineProps<{
  api: <T>(path: string) => Promise<T>;
  site: string;
  from: string;
  to: string;
}>();

const metrics = [
  { key: "pv", label: "浏览量 PV" },
  { key: "uv", label: "浏览器访客 UV" },
  { key: "sessions", label: "访问会话" },
  { key: "clicks", label: "采集到的点击" },
] as const;

type Metric = typeof metrics[number]["key"];
type Period = Record<Metric, number> & { from: string; to: string };
type Comparison = {
  site_id: string;
  current: Period;
  previous: Period;
  retention_days: number;
  within_retention: boolean;
};

const result = ref<Comparison>();
const loading = ref(false);
const error = ref("");
let generation = 0;

const rows = computed(() => {
  const data = result.value;
  if (!data) return [];
  return metrics.map(metric => {
    const current = data.current[metric.key];
    const previous = data.previous[metric.key];
    const change = data.within_retention && previous > 0 ? (current - previous) / previous : undefined;
    return { label: metric.label, current, previous, change };
  });
});
const count = new Intl.NumberFormat("zh-CN");
const percent = new Intl.NumberFormat("zh-CN", {
  style: "percent",
  maximumFractionDigits: 1,
  signDisplay: "exceptZero",
});

function validPeriod(period: Period | undefined, from: number, to: number): boolean {
  return !!period && Date.parse(period.from) === from && Date.parse(period.to) === to &&
    metrics.every(({ key }) => Number.isSafeInteger(period[key]) && period[key] >= 0);
}

async function load() {
  const current = ++generation;
  const { site, from, to } = props;
  const start = Date.parse(from);
  const end = Date.parse(to);
  result.value = undefined;
  loading.value = true;
  error.value = "";
  try {
    const query = new URLSearchParams({ from, to });
    const response = await props.api<Comparison>(`/analytics/sites/${site}/compare?${query}`);
    if (current !== generation) return;
    if (response.site_id !== site || !validPeriod(response.current, start, end) ||
        !validPeriod(response.previous, start - (end - start), start) ||
        typeof response.within_retention !== "boolean" ||
        !Number.isInteger(response.retention_days) || response.retention_days < 1 || response.retention_days > 90) {
      throw new Error("返回的站点、统计周期或指标无法核对。");
    }
    result.value = response;
  } catch (cause) {
    if (current === generation) error.value = cause instanceof Error ? cause.message : String(cause);
  } finally {
    if (current === generation) loading.value = false;
  }
}

watch(() => [props.site, props.from, props.to], () => {
  ++generation;
  result.value = undefined;
  error.value = "";
  loading.value = false;
}, { flush: "sync" });

onBeforeUnmount(() => { ++generation; });
</script>

<template>
  <section class="period-comparison" aria-labelledby="analytics-comparison-title">
    <header>
      <h4 id="analytics-comparison-title">统计周期对比</h4>
      <el-button :loading="loading" @click="load">{{ result ? "刷新对比" : "对比上一周期" }}</el-button>
    </header>
    <p v-if="error" role="alert" class="error">{{ error }}</p>
    <template v-if="result">
      <dl>
        <div><dt>当前周期（UTC）</dt><dd>{{ result.current.from }} → {{ result.current.to }}</dd></div>
        <div><dt>上一周期（UTC）</dt><dd>{{ result.previous.from }} → {{ result.previous.to }}</dd></div>
      </dl>
      <p>按两个相邻、等长周期内实际保留的采集事件计算。上一周期为零时，变化率显示为 —。</p>
      <el-alert v-if="!result.within_retention" type="warning" :closable="false"
        :title="`周期超出当前 ${result.retention_days} 天保留期限，计数可能缺失，变化率已隐藏。`" />
      <div class="table-container">
        <table>
          <thead><tr><th scope="col">指标</th><th scope="col">当前</th><th scope="col">上一周期</th><th scope="col">变化率</th></tr></thead>
          <tbody>
            <tr v-for="row in rows" :key="row.label">
              <th scope="row">{{ row.label }}</th>
              <td>{{ count.format(row.current) }}</td>
              <td>{{ count.format(row.previous) }}</td>
              <td>{{ row.change === undefined ? "—" : percent.format(row.change) }}</td>
            </tr>
          </tbody>
        </table>
      </div>
    </template>
  </section>
</template>

<style scoped>
.period-comparison { display: grid; gap: 12px; margin: 16px 0; min-width: 0; }
header { display: flex; align-items: center; justify-content: space-between; gap: 12px; flex-wrap: wrap; }
h4, p, dl { margin: 0; }
p, dt { color: var(--el-text-color-secondary); }
.error { color: var(--el-color-danger); }
dl { display: flex; flex-wrap: wrap; gap: 12px 28px; }
dd { margin: 4px 0 0; overflow-wrap: anywhere; }
.table-container { overflow-x: auto; }
table { width: 100%; border-collapse: collapse; font-variant-numeric: tabular-nums; }
th, td { padding: 8px; border-bottom: 1px solid var(--el-border-color-lighter); text-align: right; white-space: nowrap; }
th:first-child { text-align: left; }
</style>
