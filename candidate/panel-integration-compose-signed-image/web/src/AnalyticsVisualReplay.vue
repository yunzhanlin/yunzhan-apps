<script setup lang="ts">
import {computed, onBeforeUnmount, ref, watch} from 'vue';

type Viewport = {width: number; height: number; scroll: number; pointer?: number[]; tiles: number[][]};
type Frame = {path: string; received_ms: number; viewport: Viewport};
type Replay = {site_id: string; session_id: string; from: string; to: string; frames: Frame[]};
const props = defineProps<{
 load: (path: string) => Promise<Replay>;
 site: string; session: string; visitor: string; from: string; to: string;
}>();
const frames = ref<Frame[]>();
const canvas = ref<HTMLCanvasElement>();
const cursor = ref(0), playing = ref(false), busy = ref(false), error = ref('');
const frame = computed(() => frames.value?.[cursor.value]);
const count = computed(() => frames.value?.length ?? 0);
let request = 0, timer: ReturnType<typeof setTimeout> | undefined;

function paint() {
 const viewport = frame.value?.viewport, surface = canvas.value;
 if (!viewport || !surface) return;
 const scale = Math.min(1, 760 / Math.max(viewport.width, viewport.height));
 surface.width = Math.max(1, Math.round(viewport.width * scale));
 surface.height = Math.max(1, Math.round(viewport.height * scale));
 const pen = surface.getContext('2d');
 if (!pen) return;
 const sx = surface.width / 1000, sy = surface.height / 1000;
 pen.fillStyle = '#ffffff';
 pen.fillRect(0, 0, surface.width, surface.height);
 for (const [left, top, width, height, color, kind] of viewport.tiles) {
  const x = left * sx, y = top * sy, w = width * sx, h = height * sy;
  pen.fillStyle = '#' + color.toString(16).padStart(6, '0');
  if (kind === 1 || kind === 2) pen.fillRect(x, y + h * 0.3, w, Math.max(1, h * 0.35));
  else pen.fillRect(x, y, w, h);
  if (kind === 3 || kind === 4) {
   pen.strokeStyle = '#64748b';
   pen.strokeRect(x, y, w, h);
  }
 }
 if (viewport.pointer) {
  const [x, y, clicked] = viewport.pointer;
  pen.beginPath();
  pen.arc(x * sx, y * sy, clicked ? 8 : 4, 0, Math.PI * 2);
  pen.lineWidth = 2;
  pen.strokeStyle = '#be123c';
  pen.stroke();
 }
}

function pause() {
 playing.value = false;
 if (timer !== undefined) clearTimeout(timer);
 timer = undefined;
}
function seek(value: number) {
 pause();
 if (Number.isInteger(value) && value >= 0 && value < count.value) cursor.value = value;
}
function tick() {
 const next = frames.value?.[cursor.value + 1], current = frame.value;
 if (!playing.value || !next || !current) return pause();
 timer = setTimeout(() => {
  cursor.value++;
  tick();
 }, Math.max(250, Math.min(5000, next.received_ms - current.received_ms)));
}
function toggle() {
 if (playing.value) return pause();
 if (count.value < 2) return;
 if (cursor.value + 1 >= count.value) cursor.value = 0;
 playing.value = true;
 tick();
}

async function fetchReplay() {
 const generation = ++request;
 const {site,session,visitor,from,to} = props;
 pause();
 frames.value = undefined;
 cursor.value = 0;
 error.value = '';
 busy.value = true;
 try {
  const query = new URLSearchParams({visitor,from,to});
  const value = await props.load('/analytics/sites/' + encodeURIComponent(site) + '/sessions/' +
   encodeURIComponent(session) + '/replay?' + query);
  if (generation !== request) return;
  if (value.site_id !== site || value.session_id !== session || value.from !== from || value.to !== to ||
      !Array.isArray(value.frames) || value.frames.length > 180) throw new Error('返回的会话画面范围无法核对');
  frames.value = value.frames;
 } catch (e) {
  if (generation === request) error.value = (e as Error).message;
 } finally {
  if (generation === request) busy.value = false;
 }
}

watch([frame, canvas], paint, {flush: 'post'});
watch(() => [props.site, props.session, props.visitor, props.from, props.to], () => {
 request++;
 pause();
 frames.value = undefined;
 cursor.value = 0;
 busy.value = false;
 error.value = '';
}, {flush: 'sync'});
onBeforeUnmount(() => { request++; pause(); });
</script>

<template>
  <section class="visual-replay" aria-label="会话画面回看">
    <el-button :loading="busy" @click="fetchReplay">读取会话画面</el-button>
    <el-alert v-if="error" :title="error" type="error" :closable="false" />
    <template v-if="frames">
      <p v-if="!count">当前会话和时间范围没有保存的画面。</p>
      <template v-else-if="frame">
        <p class="replay-frame-description" aria-live="polite">
          {{cursor + 1}} / {{count}} · {{new Date(frame.received_ms).toLocaleTimeString()}} · <code>{{frame.path}}</code>
          · 滚动 {{(frame.viewport.scroll / 10).toFixed(0)}}%
        </p>
        <canvas ref="canvas" role="img" aria-label="遮挡后的页面布局和指针位置" />
        <div class="replay-playback">
          <el-button :disabled="cursor === 0" @click="seek(cursor - 1)">上一帧</el-button>
          <el-button :disabled="count < 2" @click="toggle">{{playing ? '暂停画面' : '播放画面'}}</el-button>
          <el-button :disabled="cursor + 1 >= count" @click="seek(cursor + 1)">下一帧</el-button>
          <input type="range" min="0" :max="count - 1" :value="cursor" :disabled="count < 2" aria-label="会话画面进度"
            @input="seek(Number(($event.target as HTMLInputElement).value))">
        </div>
        <p>画面按接收时间播放，超过 5 秒的间隔会压缩。</p>
      </template>
    </template>
  </section>
</template>

<style scoped>
.visual-replay{padding:12px 0}
.replay-frame-description{overflow-wrap:anywhere}
canvas{display:block;max-width:100%;height:auto;max-height:480px;margin:8px 0;border:1px solid var(--el-border-color);background:white}
.replay-playback{display:flex;align-items:center;flex-wrap:wrap;gap:8px}
.replay-playback input{flex:1;min-width:7rem;max-width:20rem}
</style>
