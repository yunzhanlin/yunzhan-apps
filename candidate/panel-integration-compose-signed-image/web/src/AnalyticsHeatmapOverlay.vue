<script setup lang="ts">
import { onBeforeUnmount, ref } from "vue";

defineProps<{
  page: string;
  points: { x: number; y: number; count: number }[];
}>();
const screenshot = ref("");
const error = ref("");
let generation = 0;
let objectURL = "";

function clear() {
  generation++;
  if (objectURL) URL.revokeObjectURL(objectURL);
  objectURL = "";
  screenshot.value = "";
  error.value = "";
}
async function choose(event: Event) {
  const input = event.currentTarget as HTMLInputElement;
  const file = input.files?.[0];
  input.value = "";
  if (!file) return;
  clear();
  const current = generation;
  try {
    if (file.size < 33 || file.size > (16 << 20)) throw Error("请选择不超过 16 MiB 的完整页面 PNG。");
    const header = new DataView(await file.slice(0,24).arrayBuffer());
    if (current !== generation) return;
    if (header.getUint32(0) !== 0x89504e47 || header.getUint32(4) !== 0x0d0a1a0a ||
        header.getUint32(8) !== 13 || header.getUint32(12) !== 0x49484452) {
      throw Error("所选文件不是可识别的 PNG。");
    }
    const width = header.getUint32(16), height = header.getUint32(20);
    if (!width || !height || width > 32768 || height > 32768 || width*height > 32_000_000) {
      throw Error("截图最长边须在 32768 像素内，总像素不得超过 3200 万。");
    }
    objectURL = URL.createObjectURL(file.slice(0,file.size,"image/png"));
    screenshot.value = objectURL;
  } catch (cause) {
    if (current === generation) error.value = (cause as Error).message;
  }
}
function decodeFailed() {
  clear();
  error.value = "截图无法解码，请重新选择完整 PNG。";
}
onBeforeUnmount(clear);
</script>

<template>
  <section class="analytics-overlay" aria-label="页面截图热图">
    <h4>页面截图叠加</h4>
    <p>选择相同页面、屏宽和布局的全页 PNG。布局变化会影响点位，图片仅在此页面显示。</p>
    <div class="overlay-actions">
      <label>全页截图 <input type="file" accept="image/png,.png" @change="choose"></label>
      <el-button v-if="screenshot" @click="clear">移除截图</el-button>
    </div>
    <el-alert v-if="error" :title="error" type="error" :closable="false" />
    <div v-if="screenshot" class="overlay-preview">
      <div class="overlay-page" role="img" :aria-label="`${page} 的截图和点击热图`">
        <img :src="screenshot" alt="" @error="decodeFailed">
        <span v-for="point in points" :key="`${point.x}:${point.y}`" class="overlay-dot"
          :style="{left:`${point.x+2.5}%`,top:`${point.y+2.5}%`,width:`${Math.min(30,8+Math.log2(1+point.count)*4)}px`}"
          :title="`${point.count} 次点击`" aria-hidden="true" />
      </div>
    </div>
  </section>
</template>

<style scoped>
.analytics-overlay{margin:18px 0;color:var(--el-text-color-regular)}
.overlay-actions{display:flex;align-items:center;flex-wrap:wrap;gap:12px;margin:12px 0}
.overlay-actions label{display:grid;gap:6px;min-width:0}.overlay-actions input{max-width:100%}
.overlay-preview{max-height:70vh;overflow:auto;border:1px solid var(--el-border-color);border-radius:8px}
.overlay-page{position:relative}.overlay-page img{display:block;width:100%;height:auto}
.overlay-dot{position:absolute;transform:translate(-50%,-50%);aspect-ratio:1;border-radius:50%;background:#f9731699;box-shadow:0 0 0 1px #fff}
</style>
