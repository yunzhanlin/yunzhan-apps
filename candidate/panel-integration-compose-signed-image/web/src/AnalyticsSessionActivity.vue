<script setup lang="ts">
import { computed, onBeforeUnmount, ref, watch } from "vue";

type Event = {kind:"pageview"|"click"|"engagement";path:string;received_at:number;duration_seconds?:number;x?:number;y?:number};
type Activity = {session_id:string;from:string;to:string;partial:boolean;events:Event[]};
const props = defineProps<{
  load:(path:string)=>Promise<Activity>;
  site:string; session:string; visitor:string; from:string; to:string;
}>();

const result=ref<Activity>(), busy=ref(false), error=ref(""), cursor=ref(0), playing=ref(false);
let epoch=0;
let timer:ReturnType<typeof setTimeout>|undefined;
const labels={pageview:"浏览页面",click:"点击",engagement:"前台停留"};
const event=computed(()=>result.value?.events[cursor.value]);
const count=computed(()=>result.value?.events.length ?? 0);
const localTime=(stamp:number)=>new Date(stamp*1000).toLocaleTimeString("zh-CN",{hour12:false});

function pause() {
  playing.value=false;
  if(timer!==undefined) clearTimeout(timer);
  timer=undefined;
}
function step(next:number) {
  pause();
  if(Number.isInteger(next) && next>=0 && next<count.value) cursor.value=next;
}
function advance() {
  if(!playing.value || !result.value || cursor.value+1>=count.value){pause();return;}
  const events=result.value.events;
  const gap=(events[cursor.value+1].received_at-events[cursor.value].received_at)*1000;
  timer=setTimeout(()=>{
    cursor.value++;
    advance();
  },Math.min(2500,Math.max(450,gap)));
}
function play() {
  if(playing.value){pause();return;}
  if(count.value<2)return;
  if(cursor.value+1>=count.value) cursor.value=0;
  playing.value=true;
  advance();
}
async function load() {
  pause();
  const request=++epoch, {site,session,visitor,from,to}=props;
  error.value=""; result.value=undefined;cursor.value=0;busy.value=true;
  const params=new URLSearchParams({from,to,visitor});
  try{
    const out=await props.load(`/analytics/sites/${encodeURIComponent(site)}/sessions/${encodeURIComponent(session)}/activity?${params}`);
    if(request!==epoch)return;
    if(out.session_id!==session || out.from!==from || out.to!==to) throw new Error("服务器返回了不同的会话或时间范围");
    result.value=out;
  }catch(e){
    if(request===epoch) error.value=e instanceof Error?e.message:"会话活动暂不可用";
  }finally{if(request===epoch)busy.value=false;}
}
watch(()=>[props.site,props.session,props.visitor,props.from,props.to],()=>{
  epoch++;pause();result.value=undefined;error.value="";busy.value=false;cursor.value=0;
});
onBeforeUnmount(()=>{epoch++;pause();});
</script>

<template>
  <section class="analytics-session-activity" aria-label="会话活动回看">
    <el-button :loading="busy" @click="load">{{result ? '重新读取活动' : '读取会话活动'}}</el-button>
    <el-alert v-if="error" type="error" :title="error" :closable="false" />
    <template v-if="result">
      <p>按服务器接收顺序回看页面、点击位置和前台停留。播放间隔经过压缩，事件可能延迟到达。</p>
      <el-alert v-if="result.partial" title="活动超过读取上限，仅显示最近一段。缩短统计时间范围可核对更早的活动。" type="warning" :closable="false" />
      <p v-if="!count">这段时间没有可显示的活动。</p>
      <template v-if="event">
        <div class="activity-current" aria-live="polite">
          <span>{{cursor+1}} / {{count}} · {{localTime(event.received_at)}} · {{labels[event.kind]}}</span>
          <code>{{event.path}}</code>
          <span v-if="event.kind==='engagement'">{{event.duration_seconds?.toFixed(1)}} 秒</span>
          <div v-if="event.kind==='click'" class="activity-click-grid" role="img"
            :aria-label="`归一化点击坐标：${event.x?.toFixed(1)}%，${event.y?.toFixed(1)}%`">
            <span :style="{left:event.x+'%',top:event.y+'%'}" />
          </div>
        </div>
        <div class="activity-controls">
          <el-button :disabled="cursor===0" @click="step(cursor-1)">上一步</el-button>
          <el-button :disabled="count<2" @click="play">{{playing?'暂停':'播放'}}</el-button>
          <el-button :disabled="cursor+1>=count" @click="step(cursor+1)">下一步</el-button>
          <input type="range" min="0" :max="count-1" :value="cursor" aria-label="活动位置" :disabled="count<2"
            @input="step(Number(($event.target as HTMLInputElement).value))">
        </div>
        <ol class="activity-list">
          <li v-for="(row,index) in result.events" :key="index">
            <button type="button" :aria-current="cursor===index?'step':undefined" @click="step(index)">
              <time :datetime="new Date(row.received_at*1000).toISOString()">{{localTime(row.received_at)}}</time>
              <span>{{labels[row.kind]}}</span>
              <code>{{row.path}}</code>
            </button>
          </li>
        </ol>
      </template>
    </template>
  </section>
</template>

<style scoped>
.analytics-session-activity{margin:12px 0;min-width:0}
.analytics-session-activity p{color:var(--el-text-color-secondary)}
.activity-current{display:flex;flex-wrap:wrap;align-items:center;gap:10px;margin:12px 0;overflow-wrap:anywhere}
.activity-click-grid{position:relative;margin:4px;width:100%;max-width:220px;height:120px;background:var(--el-fill-color-light);border:1px solid var(--el-border-color)}
.activity-click-grid span{position:absolute;width:11px;height:11px;background:var(--el-color-primary);border:1px solid var(--el-bg-color);border-radius:50%;transform:translate(-50%,-50%)}
.activity-controls{display:flex;gap:8px;flex-wrap:wrap;align-items:center;margin-bottom:10px}
.activity-controls :deep(.el-button){margin-left:0}
.activity-list{max-height:200px;overflow:auto;padding-left:22px}
.activity-list button{display:flex;flex-wrap:wrap;gap:8px;width:100%;padding:6px 8px;border:0;background:none;color:inherit;text-align:left;cursor:pointer;overflow-wrap:anywhere}
.activity-list button[aria-current]{background:var(--el-color-primary-light-9);color:var(--el-color-primary-dark-2)}
</style>
