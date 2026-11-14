<script setup lang="ts">
import {computed, ref, watch} from 'vue';
import {archiveStates, statisticsArchiveInventory} from './statisticsHistory';

const props = defineProps<{report: Record<string, unknown>}>();
const inventory = computed(() => statisticsArchiveInventory(props.report));
const state = ref('');
const page = ref(1);
const pageSize = 12;
const filtered = computed(() => inventory.value?.sources.filter(row => !state.value || state.value === row.state) ?? []);
const visible = computed(() => filtered.value.slice((page.value - 1) * pageSize, page.value * pageSize));
watch([inventory, state], () => { page.value = 1; });
watch(() => inventory.value?.site_id, () => { state.value = ''; });

function download() {
 const snapshot = inventory.value;
 if (!snapshot) return;
 const blob = new Blob([JSON.stringify(snapshot, null, 2) + '\n'], {type: 'application/json;charset=utf-8'});
 const url = URL.createObjectURL(blob);
 const link = document.createElement('a');
 link.href = url;
 link.download = 'statistics-archive-inventory-' + snapshot.site_id + '.json';
 link.click();
 window.setTimeout(() => URL.revokeObjectURL(url), 1000);
}
</script>

<template>
  <details v-if="report.history_archive_inventory !== undefined" class="archive-inventory">
    <summary>压缩归档清单</summary>
    <template v-if="inventory">
      <p>核对时间 {{ inventory.checked_at }}（UTC）</p>
      <div class="archive-controls">
        <label>归档状态
          <select v-model="state">
            <option value="">全部状态</option>
            <option v-for="(label, value) in archiveStates" :key="value" :value="value">{{ label }}</option>
          </select>
        </label>
        <el-button size="small" @click="download">下载本报告的归档清单</el-button>
      </div>
      <p v-if="inventory.omitted" role="status">另有 {{ inventory.omitted }} 条历史来源超出清单上限。下载包含当前列出的全部条目。</p>
      <p v-if="!inventory.sources.length">本轮没有发现压缩归档。</p>
      <p v-else-if="!visible.length">没有符合筛选条件的归档。</p>
      <ul v-else class="archive-list">
        <li v-for="(row, index) in visible" :key="row.name + ':' + index">
          <div class="archive-row">
            <code>{{ row.name }}</code>
            <strong>{{ archiveStates[row.state] }}</strong>
          </div>
          <p v-if="row.compressed_bytes !== undefined">压缩大小 {{ row.compressed_bytes.toLocaleString() }} B</p>
          <template v-if="row.verified">
            <p>已读 {{ row.verified.read_bytes.toLocaleString() }} / {{ row.verified.expanded_bytes.toLocaleString() }} B · 跳过 {{ row.verified.skipped_lines.toLocaleString() }} 行</p>
            <div>SHA-256 <code>{{ row.verified.sha256 }}</code></div>
          </template>
        </li>
      </ul>
      <el-pagination v-if="filtered.length > pageSize" v-model:current-page="page" layout="prev, pager, next"
        :page-size="pageSize" :pager-count="5" :total="filtered.length" small />
    </template>
    <p v-else role="status">归档清单无法核对，请刷新报告。</p>
  </details>
</template>

<style scoped>
.archive-inventory{padding:12px 14px;margin:12px 0;border:1px solid var(--panel-border,#dce5ed);border-radius:8px}
summary{cursor:pointer;font-weight:600}
.archive-controls,.archive-row{display:flex;gap:8px 12px;align-items:center;justify-content:space-between;flex-wrap:wrap}
select{padding:4px 6px;margin-left:6px;border:1px solid var(--panel-border,#dce5ed);border-radius:4px;background:var(--el-bg-color);color:inherit}
.archive-list{list-style:none;padding:0;margin:12px 0}
.archive-list li{border-top:1px solid var(--panel-border,#dce5ed);padding:8px 0;overflow-wrap:anywhere}
.archive-list p{margin:4px 0}
code{overflow-wrap:anywhere}
</style>
