<script setup lang="ts">
import {computed,onBeforeUnmount,ref,shallowRef,watch} from 'vue';
import type {AccessPlan} from './menuPermissions';
import {newPM2ConfigurationID} from './pm2Configuration';
import {archiveBody,archiveDisplayTime,archiveFullAdmin,archiveLabels,configurationResultLabels,archiveOriginalRecords,archivePage,archivePending,archiveRow,pm2ArchiveVersion,type ArchiveAction,type ArchivePage,type ArchivePending,type ArchiveRow} from './pm2ConfigurationArchive';
type API=<T>(path:string,method?:string,body?:unknown,idempotencyKey?:string,signal?:AbortSignal)=>Promise<T>;
const props=defineProps<{api:API;actor:string;access?:AccessPlan|null;active:boolean;installed:boolean;installedVersion:string;installationId:string}>();
const page=shallowRef<ArchivePage>(),selected=shallowRef<ArchiveRow>(),records=shallowRef<ReturnType<typeof archiveOriginalRecords>>(),pending=shallowRef<ArchivePending>();
const busy=ref(false),error=ref(''),notice=ref(''),markerInvalid=ref(false);
let epoch=0,controller:AbortController|undefined;
const enabled=computed(()=>props.active&&props.installed&&props.installedVersion===pm2ArchiveVersion&&/^[a-f0-9]{32}$/.test(props.actor)&&/^[a-f0-9]{32}$/.test(props.installationId)&&archiveFullAdmin(props.access));
const key=()=>`yunzhan-pm2-configuration-archive-v1/${props.actor}/${props.installationId}`;
function remember(p:ArchivePending){sessionStorage.setItem(key(),JSON.stringify(p));pending.value=p}
function forget(){sessionStorage.removeItem(key());pending.value=undefined}
function stop(){epoch++;controller?.abort();controller=undefined;busy.value=false;page.value=undefined;selected.value=undefined;records.value=undefined}
function readPending(){pending.value=undefined;markerInvalid.value=false;if(!enabled.value)return;try{const raw=sessionStorage.getItem(key());if(raw){const p:unknown=JSON.parse(raw);if(!archivePending(p,props.actor,props.installationId))throw Error('浏览器保存的原请求身份无法核对；请按服务器原归档记录核对，当前不发送新封存。');pending.value=p;notice.value='保留上次待核对请求；本页不会自动重发。'}}catch(e){markerInvalid.value=true;error.value=String(e)}}
async function run(task:(request:AbortController,current:()=>boolean)=>Promise<void>){if(!enabled.value||busy.value)return;const generation=epoch,actor=props.actor,installation=props.installationId,request=new AbortController();controller=request;busy.value=true;error.value='';const current=()=>enabled.value&&generation===epoch&&props.actor===actor&&props.installationId===installation&&!request.signal.aborted;try{await task(request,current)}catch(e){if(current())error.value=e instanceof Error?e.message:String(e)}finally{if(epoch===generation){busy.value=false;controller=undefined}}}
async function refresh(offset=0){await run(async(request,current)=>{const out=archivePage(await props.api('/app-modules/pm2-manager/configuration-archives?pm2_installation_id='+props.installationId+'&limit=16&offset='+offset,'GET',undefined,undefined,request.signal));if(!current())return;page.value=out;selected.value=undefined;records.value=undefined;notice.value='只读清单已刷新；未封存、恢复或启停项目。'})}
function choose(row:ArchiveRow){if(busy.value)return;selected.value=row;records.value=undefined;notice.value='已选择原封存请求；尚未执行恢复。'}
async function readRecords(offset=0){const row=selected.value;if(row?.state!=='archived')return;await run(async(request,current)=>{const out=archiveOriginalRecords(await props.api(`/app-modules/pm2-manager/configuration-archives/${row.pm2_operation_id}/records?pm2_installation_id=${props.installationId}&limit=16&offset=${offset}`,'GET',undefined,undefined,request.signal),row);if(current()&&selected.value===row)records.value=out})}
async function observe(){const original=pending.value;if(!original)return;await run(async(request,current)=>{const out=archivePage(await props.api('/app-modules/pm2-manager/configuration-archives?pm2_installation_id='+props.installationId+'&pm2_operation_id='+original.id+'&limit=1','GET',undefined,undefined,request.signal));if(!current())return;page.value=out;const row=out.configuration_archives[0];selected.value=row;records.value=undefined;if(!row){notice.value='尚未发现原请求，不能据此认定未执行；保留原编号，仅可手动使用原编号重试。';return}if(row.pm2_operation_id!==original.id||row.state!=='not_started'&&(original.action==='archive-configurations'?row.inventory_sha256!==original.sha256:row.expected_sha!==original.sha256))throw Error('原请求摘要不匹配，仍待核对');if(row.state!=='needs_attention'){forget();notice.value=row.state==='not_started'?'原编号已保留且不能执行新的封存；未宣称封存成功。':'已核对原请求持久结果：'+archiveLabels[row.state]}else notice.value='原封存尚未完成。请核对后选择继续封存或恢复原目录；不会重放配置更新。'})}
async function submit(action:ArchiveAction,retry=false){
 if(!enabled.value||busy.value||markerInvalid.value||pending.value&&!retry)return;
 let original:ArchivePending;
 if(retry){if(!pending.value)return;original=pending.value}
 else if(action==='archive-configurations'){if(!page.value?.active_inventory_known||!page.value.archive_eligible||!page.value.inventory_sha256)return;original={actor:props.actor,installation:props.installationId,action,id:newPM2ConfigurationID(),sha256:page.value.inventory_sha256}}
 else{const row=selected.value;if(row?.state!=='needs_attention'||action==='recover-configuration-archive'&&row.restore_requested)return;original={actor:props.actor,installation:props.installationId,action,id:row.pm2_operation_id,sha256:row.expected_sha}}
 await run(async(request,current)=>{remember(original);const out=await props.api<any>('/app-modules/pm2-manager/'+original.action,'POST',archiveBody(original),undefined,request.signal);if(!current())return;const row=archiveRow(out?.archive);if(!row||row.pm2_operation_id!==original.id||row.state!=='not_started'&&(original.action==='archive-configurations'?row.inventory_sha256!==original.sha256:row.expected_sha!==original.sha256))throw Error('原封存回执身份尚未核对；保留原编号，不自动重发');page.value=undefined;selected.value=row;records.value=undefined;if(row.state!=='needs_attention'){forget();notice.value=archiveLabels[row.state]+'。全部原记录保留，未启停项目；请刷新查看最新活动记录。'}else notice.value='原请求仍待核对；请只读核对原编号后显式恢复。'})
}
function releasePendingForRecovery(){const p=pending.value,row=selected.value;if(!p||!row||p.id!==row.pm2_operation_id||row.state!=='needs_attention'||(p.action==='archive-configurations'?row.inventory_sha256!==p.sha256:row.expected_sha!==p.sha256))return;try{forget();notice.value='已核对原中断记录。请选择继续完成封存或恢复原目录，不会自动执行。'}catch(e){error.value=String(e)}}
watch(()=>[props.active,props.installed,props.installedVersion,props.installationId,props.actor,JSON.stringify(props.access)],()=>{stop();error.value='';notice.value='';readPending()},{immediate:true});
onBeforeUnmount(stop);
</script>
<template>
 <section class="pm2-config-archive" aria-label="PM2 配置记录封存">
  <h3>配置记录封存</h3>
  <p>活动目录最多保存 512 条配置请求。封存已完成记录后可继续保存新配置，旧记录全部保留，旧编号不能再次执行。最多保留 512 次封存请求。</p>
  <el-alert v-if="installedVersion!==pm2ArchiveVersion" title="请先在版本与更新中更新到 compat12，再使用配置封存。" type="info" :closable="false" />
  <el-alert v-else-if="!archiveFullAdmin(access)" title="完整配置记录仅完整管理员可维护。" type="warning" :closable="false" />
  <el-alert v-if="error" :title="error" type="error" :closable="false" />
  <el-alert v-if="notice" :title="notice" type="info" :closable="false" />
  <div class="archive-controls">
   <el-button :disabled="!enabled||busy" @click="refresh()">只读刷新记录</el-button>
   <el-button type="primary" :disabled="!enabled||busy||!!pending||markerInvalid||!page?.archive_eligible" @click="submit('archive-configurations')">封存已完成记录</el-button>
  </div>
  <template v-if="pending">
   <p>待核对原编号：<code>{{pending.id}}</code>。断开连接不会自动重发。</p>
   <el-button :disabled="!enabled||busy" @click="observe">核对原请求</el-button>
   <el-button :disabled="!enabled||busy||markerInvalid" @click="submit(pending.action,true)">使用原编号手动重试</el-button>
   <el-button v-if="selected?.pm2_operation_id===pending.id&&selected.state==='needs_attention'" :disabled="busy" @click="releasePendingForRecovery">选择原记录的恢复方式</el-button>
  </template>
  <template v-if="page">
   <p v-if="page.active_inventory_known">当前活动记录 {{page.active_record_count}} / 512，待核对配置 {{page.active_pending_count}} 条。</p>
   <el-alert v-else title="活动目录尚未完整核对；不能将它当作空目录或执行新封存。历史清单单独显示。" type="warning" :closable="false" />
   <el-table :data="page.configuration_archives" border highlight-current-row row-key="pm2_operation_id" empty-text="尚无配置封存记录" @row-click="choose">
    <el-table-column label="建立时间" min-width="180"><template #default="scope">{{archiveDisplayTime(scope.row.created_at)}}</template></el-table-column>
    <el-table-column label="状态" min-width="220"><template #default="scope">{{archiveLabels[scope.row.state as ArchiveRow['state']]}}</template></el-table-column>
    <el-table-column prop="record_count" label="原记录数" width="100" />
    <el-table-column label="原请求" min-width="220"><template #default="scope"><code>{{scope.row.pm2_operation_id}}</code></template></el-table-column>
    <el-table-column label="操作" width="100" fixed="right"><template #default="scope"><el-button :disabled="busy" :aria-label="'选择原封存请求 '+scope.row.pm2_operation_id" @click.stop="choose(scope.row)">选择</el-button></template></el-table-column>
   </el-table>
   <div class="archive-controls"><el-button :disabled="busy||page.offset===0" @click="refresh(Math.max(0,page.offset-16))">上一页封存</el-button><span>共 {{page.total}} 次请求</span><el-button :disabled="busy||page.page_complete" @click="refresh(page.next_offset)">下一页封存</el-button></div>
  </template>
  <template v-if="selected">
   <h4>所选原记录：{{archiveLabels[selected.state]}}</h4><p><code>{{selected.pm2_operation_id}}</code></p>
   <el-button v-if="selected.state==='archived'" :disabled="busy||!enabled" @click="readRecords()">查看原配置记录</el-button>
   <template v-if="selected.state==='needs_attention'">
    <p>继续封存会保留旧目录并建立新的活动目录。恢复原目录仅用于核对，原配置不自动重放，项目服务不启停。</p>
    <el-button :disabled="busy||!enabled||!!pending||markerInvalid||selected.restore_requested" @click="submit('recover-configuration-archive')">继续完成封存</el-button>
    <el-button :disabled="busy||!enabled||!!pending||markerInvalid" @click="submit('restore-configuration-archive')">恢复原目录待核对</el-button>
    <p v-if="selected.restore_requested">已持久选择恢复原目录，后续只能继续该恢复方向。</p>
   </template>
  </template>
  <template v-if="records">
   <el-table :data="records.rows" border empty-text="当前页没有配置记录"><el-table-column prop="resource_id" label="项目" min-width="150"/><el-table-column label="原结果" min-width="160"><template #default="scope">{{configurationResultLabels[scope.row.state as keyof typeof configurationResultLabels]}}</template></el-table-column><el-table-column label="建立时间" min-width="180"><template #default="scope">{{archiveDisplayTime(scope.row.created_at)}}</template></el-table-column><el-table-column prop="pm2_operation_id" label="原配置编号" min-width="250"/></el-table>
   <div class="archive-controls"><el-button :disabled="busy||records.offset===0" @click="readRecords(Math.max(0,records.offset-16))">上一页配置</el-button><span>共 {{records.total}} 条原记录</span><el-button :disabled="busy||records.next>=records.total" @click="readRecords(records.next)">下一页配置</el-button></div>
  </template>
 </section>
</template>
<style scoped>
.pm2-config-archive{display:grid;gap:14px;min-width:0}.pm2-config-archive p{margin:0;line-height:1.7;overflow-wrap:anywhere}.pm2-config-archive h3,.pm2-config-archive h4{margin:0}.archive-controls{display:flex;align-items:center;flex-wrap:wrap;gap:10px}code{overflow-wrap:anywhere;font-size:12px}
</style>
