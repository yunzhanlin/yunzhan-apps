<script setup lang="ts">
import {computed, ref, watch} from 'vue';
import type {RemoteSyncPreview} from './remoteSyncPreview';
const props = defineProps<{preview: RemoteSyncPreview; stale: boolean}>();
const labels = {create: '待新建', update: '待更新', unchanged: '未变化', conflict: '保留冲突'} as const;
const filter = ref<'' | 'create' | 'update' | 'conflict'>('');
watch(() => props.preview, () => { filter.value = ''; });
const rows = computed(() => props.preview.rows.filter(row => !filter.value || row.action === filter.value));
const bytes = (n: number) => new Intl.NumberFormat('zh-CN').format(n) + ' B';
</script>

<template>
  <section class="sync-preview" aria-label="远端文件变更预览">
    <h4>远端文件变更预览</h4>
    <p v-if="stale" role="status" class="stale">下方是上次预览，当前选择尚未核对。请重新预览。</p>
    <p>连接 <strong>{{ preview.remote_target_id }}</strong> · 修订 {{ preview.revision }} · 源网站 <code>{{ preview.site_id }}</code></p>
    <details v-if="preview.excludes.length"><summary>本次排除 {{ preview.excludes.length }} 项</summary><ul><li v-for="(path, i) in preview.excludes" :key="i">{{ path }}</li></ul></details>
    <dl class="sync-totals">
      <div v-for="(label, action) in labels" :key="action"><dt>{{ label }}</dt><dd>{{ preview.counts[action] }}</dd></div>
    </dl>
    <p>扫描 {{ preview.source_files }} 个文件（{{ bytes(preview.source_bytes) }}），预计传输 {{ bytes(preview.transfer_bytes) }}。不会删除远端文件；执行时将重新核对内容和权限。</p>
    <p v-if="preview.rows_limited" role="status">上方总数覆盖全部已扫描文件。下方只显示有变更或冲突的部分路径。</p>
    <label v-if="preview.rows.length">筛选变更
      <select v-model="filter"><option value="">全部变更和冲突</option><option value="create">待新建</option><option value="update">待更新</option><option value="conflict">保留冲突</option></select>
    </label>
    <ul v-if="rows.length" class="sync-rows" aria-label="文件变更明细">
      <li v-for="row in rows" :key="row.path">
        <strong>{{ labels[row.action] }}</strong> <code>{{ row.path }}</code>
        <span>源 {{ bytes(row.source_bytes) }}<template v-if="row.target_bytes !== undefined"> · 远端 {{ bytes(row.target_bytes) }}</template></span>
        <span v-if="row.reason">{{ row.reason === 'untracked_target' ? '远端已有未纳入同步的文件' : '远端文件与上次同步记录不一致' }}</span>
      </li>
    </ul>
    <p v-else-if="filter">本次展示的路径中没有这一类。</p>
    <p v-else>本次扫描没有需要同步的变更或保留冲突。</p>
  </section>
</template>

<style scoped>
.sync-preview { margin: 12px 0; overflow-wrap: anywhere; }
.sync-preview h4 { margin: 0 0 8px; }
.sync-preview p { margin: 8px 0; }
.sync-totals { display: grid; grid-template-columns: repeat(auto-fit, minmax(100px, 1fr)); gap: 8px; }
.sync-totals div { background: #f1f5f8; padding: 8px 12px; border-radius: 6px; }
.sync-totals dd { margin: 0; font-size: 1.25em; font-weight: 600; }
.stale { background: #fff1d5; color: #654108; padding: 8px; }
.sync-rows { list-style: none; padding: 0; margin: 12px 0; }
.sync-rows li { display: flex; flex-wrap: wrap; gap: 4px 12px; border-top: 1px solid #dbe4ec; padding: 8px 0; }
.sync-rows span { color: #40536a; }
</style>
