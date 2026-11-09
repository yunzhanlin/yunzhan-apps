<script setup lang="ts">
import { onMounted, onUnmounted, ref } from "vue";
import { formatPanelDateTime } from "./panelTime";

interface CleanupRecord {
  engine: "mysql" | "mariadb" | "site";
  artifact_id: string;
  schedule_id: string;
  schedule_name: string;
  bytes: number;
  sha256: string;
  state: "pending" | "completed";
  attempts: number;
  last_error: string;
  created_at: string;
  completed_at: string;
  status: "needs_attention" | "ready" | "held" | "completed";
}
interface CleanupPage {
  items: CleanupRecord[];
  counts: Record<CleanupRecord["status"], number>;
  total: number;
  has_more: boolean;
  read_only: boolean;
}
const props = defineProps<{ api: <T>(path: string, method?: string, body?: unknown) => Promise<T> }>();
const items = ref<CleanupRecord[]>([]), counts = ref<CleanupPage["counts"] | null>(null);
const loading = ref(false), error = ref(""), page = ref(1), total = ref(0), hasMore = ref(false);
const detail = ref<CleanupRecord | null>(null), detailOpen = ref(false);
const labels = { needs_attention: "需核对 · 已停止自动重试", ready: "等待清理", held: "当前暂缓", completed: "已完成" };
const engines = { mysql: "MySQL", mariadb: "MariaDB", site: "网站备份" };
let sequence = 0, disposed = false;
async function load() {
  if (loading.value || disposed) return;
  const current = ++sequence, requestedPage = page.value;
  loading.value = true;
  try {
    const data = await props.api<CleanupPage>(`/schedules/retention?limit=10&offset=${(requestedPage - 1) * 10}`);
    if (disposed || current !== sequence) return;
    if (data.read_only !== true) throw new Error("清理记录响应无法核对");
    items.value = data.items; counts.value = data.counts; total.value = data.total;
    hasMore.value = data.has_more; error.value = "";
  } catch (e) {
    if (!disposed && current === sequence) error.value = (e as Error).message;
  } finally {
    if (!disposed && current === sequence) loading.value = false;
  }
}
function move(amount: number) {
  if (loading.value) return;
  page.value = Math.max(1, page.value + amount);
  void load();
}
function inspect(item: CleanupRecord) { detail.value = { ...item }; detailOpen.value = true; }
let timer: ReturnType<typeof setInterval>;
onMounted(() => { void load(); timer = setInterval(() => void load(), 10000); });
onUnmounted(() => { disposed = true; sequence++; clearInterval(timer); });
</script>

<template>
  <section class="panel-card retention-card" aria-label="备份保留与清理记录">
    <div class="retention-heading">
      <div><h3>备份保留与清理记录</h3><p>失败或未确认的清理停止自动重试，保留原原因；其他合格备份继续按当前保留策略清理。</p></div>
      <el-button :loading="loading" @click="load">刷新清理记录</el-button>
    </div>
    <el-alert v-if="error" :title="error" type="error" :closable="false" show-icon />
    <template v-if="counts">
      <div class="retention-counts" role="status">
        <span>需核对 <strong>{{ counts.needs_attention }}</strong></span>
        <span>等待清理 <strong>{{ counts.ready }}</strong></span>
        <span>当前暂缓 <strong>{{ counts.held }}</strong></span>
        <span>已完成 <strong>{{ counts.completed }}</strong></span>
      </div>
      <el-alert v-if="counts.needs_attention > 0" title="有清理记录需要核对。请先检查原备份和存储权限；刷新记录不会重放删除操作。" type="warning" :closable="false" show-icon />
      <el-table :data="items" empty-text="本页没有备份清理记录" max-height="360">
        <el-table-column label="原计划" min-width="170"><template #default="{ row }">{{ row.schedule_name }}<small class="retention-engine">{{ engines[row.engine as CleanupRecord['engine']] }}</small></template></el-table-column>
        <el-table-column label="状态" min-width="220"><template #default="{ row }"><el-tag :type="row.status === 'needs_attention' ? 'warning' : row.status === 'completed' ? 'success' : 'info'">{{ labels[row.status as CleanupRecord['status']] }}</el-tag></template></el-table-column>
        <el-table-column prop="attempts" label="已登记次数" width="110" />
        <el-table-column label="原始原因" min-width="260" show-overflow-tooltip><template #default="{ row }">{{ row.last_error || (row.status === 'held' ? '当前策略、任务状态、远端复制或备份身份未满足清理条件' : '—') }}</template></el-table-column>
        <el-table-column label="操作" width="110"><template #default="{ row }"><el-button link type="primary" @click="inspect(row)">查看记录</el-button></template></el-table-column>
      </el-table>
      <div class="retention-pagination"><span>共 {{ total }} 条 · 第 {{ page }} 页</span><el-button :disabled="loading || page === 1" @click="move(-1)">上一页</el-button><el-button :disabled="loading || !hasMore" @click="move(1)">下一页</el-button></div>
    </template>
    <el-dialog v-model="detailOpen" title="备份清理原始记录" width="min(700px, 96vw)" append-to-body>
      <template v-if="detail">
        <el-alert title="这里只读取后台记录，不执行删除，也不把记录当作当前文件存在或删除结果的证明。" type="info" :closable="false" show-icon />
        <dl class="retention-detail">
          <dt>类型与计划</dt><dd>{{ engines[detail.engine] }} · {{ detail.schedule_name }}</dd>
          <dt>状态</dt><dd>{{ labels[detail.status] }}</dd>
          <dt>备份标识</dt><dd><code>{{ detail.artifact_id }}</code></dd>
          <dt>原始 SHA-256</dt><dd><code>{{ detail.sha256 }}</code></dd>
          <dt>登记大小</dt><dd>{{ detail.bytes }} 字节</dd>
          <dt>已登记次数</dt><dd>{{ detail.attempts }}</dd>
          <dt>原始原因</dt><dd>{{ detail.last_error || '—' }}</dd>
          <dt>记录时间</dt><dd>{{ formatPanelDateTime(detail.created_at) }}</dd>
          <dt v-if="detail.completed_at">完成时间</dt><dd v-if="detail.completed_at">{{ formatPanelDateTime(detail.completed_at) }}</dd>
        </dl>
      </template>
      <template #footer><el-button @click="detailOpen = false">关闭</el-button></template>
    </el-dialog>
  </section>
</template>

<style scoped>
.retention-card { padding: 22px; }
.retention-heading { display: flex; align-items: center; justify-content: space-between; gap: 16px; }
.retention-heading h3 { margin: 0 0 8px; }
.retention-heading p { color: var(--text-secondary); margin: 0; line-height: 1.6; }
.retention-counts { display: flex; flex-wrap: wrap; gap: 12px 24px; margin: 18px 0; }
.retention-counts strong { margin-left: 6px; }
.retention-engine { display: block; color: var(--text-secondary); margin-top: 6px; }
.retention-pagination { display: flex; flex-wrap: wrap; gap: 10px; align-items: center; justify-content: flex-end; margin-top: 12px; }
.retention-pagination span { margin-right: auto; }
.retention-detail { display: grid; grid-template-columns: 110px minmax(0, 1fr); gap: 12px; line-height: 1.6; }
.retention-detail dt { color: var(--text-secondary); }
.retention-detail dd { margin: 0; overflow-wrap: anywhere; }
@media (max-width: 600px) { .retention-card { padding: 14px; } .retention-heading { align-items: flex-start; flex-direction: column; } .retention-detail { grid-template-columns: 1fr; gap: 6px; } .retention-detail dd { margin-bottom: 8px; } }
</style>
