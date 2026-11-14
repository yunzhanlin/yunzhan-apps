<script setup lang="ts">
import {computed, ref, watch} from 'vue';
import {siteDiagnosisBatch, type DiagnosisState} from './siteDiagnosisBatch';
const props = defineProps<{report: Record<string, unknown>}>();
const labels = {failed:'有检查失败',unknown:'结果待核对',warning:'需要关注',passed:'检查通过'} as const;
const rows = computed(() => siteDiagnosisBatch(props.report));
const filter = ref<'' | DiagnosisState>('');
const expanded = ref('');
watch(() => props.report, () => { filter.value = ''; expanded.value = ''; });
const shown = computed(() => rows.value?.filter(row => !filter.value || row.state === filter.value) ?? []);
const count = (state: DiagnosisState) => rows.value?.filter(row => row.state === state).length ?? 0;
</script>

<template>
  <section class="batch" aria-label="网站诊断总览">
    <h4>网站诊断总览</h4>
    <p v-if="!rows" role="alert">服务器返回的批量记录数量或网站身份不一致，无法核对本次报告。</p>
    <template v-else>
      <dl class="totals"><div v-for="(label,state) in labels" :key="state"><dt>{{label}}</dt><dd>{{count(state)}}</dd></div></dl>
      <label>按检查结果筛选
        <select v-model="filter"><option value="">全部网站</option><option v-for="(label,state) in labels" :key="state" :value="state">{{label}}</option></select>
      </label>
      <p v-if="!shown.length" role="status">当前筛选下没有网站。</p>
      <article v-for="row in shown" :key="row.id" :aria-label="row.domain">
        <header><strong>{{row.domain}}</strong><span>{{labels[row.state]}}</span></header>
        <p v-if="row.report">{{row.report.path}} · {{row.http === undefined ? '未取得 HTTP 状态' : 'HTTP '+row.http}}<template v-if="row.responseMs !== undefined"> · {{row.responseMs}} 毫秒</template></p>
        <p v-if="row.issues.length">{{row.issues.join('、')}}</p>
        <p v-if="!row.report">本次未获得可以核对的完整诊断。重新选择该站点后再运行诊断。</p>
        <button v-else type="button" class="el-button" :aria-expanded="expanded === row.id" @click="expanded = expanded === row.id ? '' : row.id">
          {{expanded === row.id ? '收起检查详情' : '查看检查详情'}}
        </button>
        <slot v-if="row.report && expanded === row.id" :report="row.report" />
      </article>
    </template>
  </section>
</template>

<style scoped>
.batch { overflow-wrap: anywhere; }
.totals { display: grid; grid-template-columns: repeat(auto-fit,minmax(100px,1fr)); gap: 8px; }
.totals div { border-radius: 6px; background: #f1f5f8; padding: 8px 12px; }
.totals dd { margin: 0; font-size: 1.2em; font-weight: 600; }
.batch article { padding: 12px 0; border-bottom: 1px solid #e1e9ee; }
.batch header { display: flex; flex-wrap: wrap; justify-content: space-between; gap: 6px 14px; }
.batch p { margin: 7px 0; }
</style>
