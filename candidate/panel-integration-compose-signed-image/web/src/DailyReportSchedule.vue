<script setup lang="ts">
import { computed, onBeforeUnmount, reactive, ref, watch } from "vue";

const props = defineProps<{
  api: <T>(path: string, method?: string, body?: unknown) => Promise<T>;
  active: boolean;
  enabled: boolean;
}>();

type Schedule = {
  time_zone: string;
  local_time: string;
  revision: number;
};

const route = "/app-modules/daily-report/schedule";
const schedule = ref<Schedule>();
const draft = reactive({ time_zone: "", local_time: "" });
const pending = ref(false);
const error = ref("");
const saved = ref(false);
let epoch = 0;
const valid = computed(() => draft.time_zone.length > 0 && /^(?:[01]\d|2[0-3]):[0-5]\d$/.test(draft.local_time));
const dirty = computed(() => Boolean(schedule.value &&
  (draft.time_zone !== schedule.value.time_zone || draft.local_time !== schedule.value.local_time)));

function display(value: Schedule) {
  schedule.value = value;
  draft.time_zone = value.time_zone;
  draft.local_time = value.local_time;
}

async function reload() {
  if (!props.active || !props.enabled || pending.value) return;
  const current = ++epoch;
  pending.value = true;
  error.value = "";
  saved.value = false;
  schedule.value = undefined;
  try {
    const value = await props.api<Schedule>(route);
    if (current === epoch) display(value);
  } catch (cause) {
    if (current === epoch) error.value = cause instanceof Error ? cause.message : String(cause);
  } finally {
    if (current === epoch) pending.value = false;
  }
}

async function save() {
  if (!props.active || !props.enabled || pending.value || !schedule.value || !dirty.value || !valid.value) return;
  const current = ++epoch;
  pending.value = true;
  error.value = "";
  saved.value = false;
  try {
    const value = await props.api<Schedule>(route, "POST", { ...draft, expected_revision: schedule.value.revision });
    if (current === epoch) {
      display(value);
      saved.value = true;
    }
  } catch (cause) {
    if (current === epoch) {
      error.value = cause instanceof Error ? cause.message : String(cause);
      schedule.value = undefined;
    }
  } finally {
    if (current === epoch) pending.value = false;
  }
}

watch(() => [props.active, props.enabled], () => {
  epoch++;
  pending.value = false;
  error.value = "";
  saved.value = false;
  schedule.value = undefined;
  if (props.active && props.enabled) void reload();
}, { immediate: true });
onBeforeUnmount(() => { epoch++; });
</script>

<template>
  <section aria-label="日报生成时间">
    <el-alert v-if="!enabled" title="签名安装或更新每日运维报告后可设置生成时间。" type="info" :closable="false" />
    <template v-else>
      <p>按所选时区的当地时间生成日报。后台每分钟检查一次，每个当地日期最多自动生成一份。</p>
      <el-form v-if="schedule" class="schedule-form" label-position="top" @submit.prevent="save">
        <el-form-item label="IANA 时区">
          <el-input v-model.trim="draft.time_zone" aria-label="IANA 时区" maxlength="80" placeholder="Asia/Shanghai" :disabled="pending" />
        </el-form-item>
        <el-form-item label="当地生成时间">
          <el-input v-model="draft.local_time" type="time" aria-label="当地生成时间" :disabled="pending" />
        </el-form-item>
        <el-button native-type="submit" type="primary" :disabled="!dirty || !valid" :loading="pending">保存生成时间</el-button>
      </el-form>
      <el-alert v-if="error" :title="error" type="error" :closable="false" role="alert" />
      <p v-if="saved && schedule" role="status">已保存 {{ schedule.time_zone }} {{ schedule.local_time }}。</p>
      <el-button :disabled="pending" @click="reload">读取当前设置</el-button>
    </template>
  </section>
</template>

<style scoped>
.schedule-form { display: flex; align-items: end; flex-wrap: wrap; gap: 12px; margin-bottom: 12px; }
.schedule-form :deep(.el-form-item) { margin-bottom: 0; }
</style>
