<script setup lang="ts">
import {computed,onMounted,onUnmounted,ref} from "vue";
import {ElMessageBox} from "element-plus";
import {formatPanelDateTime} from "./panelTime";
import {decodeIntrusionWorkspace,decodeIntrusionRequests,intrusionID,intrusionCurrentVersion,intrusionVersionRequiresUpdate,type IntrusionWorkspace,type IntrusionRequests,type IntrusionRequest} from "./intrusionWorkspace";
type API=<T>(path:string,method?:string,body?:unknown,key?:string)=>Promise<T>;
const props=defineProps<{api:API;onInstall:(id:string,settings:Record<string,unknown>)=>Promise<string>;onJob:(id:string)=>Promise<void>}>();
const view=ref<IntrusionWorkspace>(),requests=ref<IntrusionRequests>(),error=ref(""),loading=ref(false),busy=ref(false),tab=ref("overview");
const form=ref({max_retry:5,find_time_minutes:10,ban_time_minutes:60});
interface OriginalTicket {action:string;key?:string;job?:string;actor:string;store:boolean}
const ticket=ref<OriginalTicket>();
let disposed=false,generation=0;
const current=computed(()=>view.value?.current);
const blocked=computed(()=>!view.value||!requests.value||loading.value||busy.value||!!ticket.value||!!view.value.pending);
const legacy=computed(()=>intrusionVersionRequiresUpdate(current.value));
const actionName=(a:string)=>({install:"安装",configure:"配置",uninstall:"移除受管策略",update:"更新",recover:"显式恢复"}[a]||a);
const ports=(p:number[]|undefined)=>p?.length?p.join("、"):"尚未核对";
const label=(name:string)=>({max_retry:"失败次数",find_time_minutes:"统计窗口（分钟）",ban_time_minutes:"封禁时长（分钟）"}[name]||name);
const limits=computed(()=>Object.entries(form.value).map(([key,value])=>({key,label:label(key),configured:current.value?.settings[key],actual:current.value?.runtime_settings[{max_retry:"maxretry",find_time_minutes:"findtime",ban_time_minutes:"bantime"}[key]||""] ,factor:key==="max_retry"?1:60,value})));
async function refresh(){
  if(disposed||loading.value||busy.value)return;
  const epoch=++generation;loading.value=true;error.value="";view.value=undefined;
  try{
    const [snapshot,directory]=await Promise.allSettled([props.api<unknown>("/software/intrusion-prevention/workspace"),props.api<unknown>("/software/intrusion-prevention/requests")]);
    if(disposed||epoch!==generation)return;
    if(snapshot.status==='rejected')throw snapshot.reason;
    const next=decodeIntrusionWorkspace(snapshot.value);
    view.value=next;requests.value=undefined;
    try{
      if(directory.status==='rejected')throw directory.reason;
      const own=decodeIntrusionRequests(directory.value);
      if(ticket.value&&ticket.value.actor!==own.actor_id)ticket.value=undefined;
      requests.value=own;
    }catch(e){error.value="当前账户原请求目录尚未核对，变更保持关闭："+((e as Error).message||"目录不可用");}
    if(next.current?.installed)form.value={max_retry:next.current.settings.max_retry!,find_time_minutes:next.current.settings.find_time_minutes!,ban_time_minutes:next.current.settings.ban_time_minutes!};
  }catch(e){if(!disposed&&epoch===generation){error.value=(e as Error).message;requests.value=undefined;}}
  finally{if(!disposed&&epoch===generation)loading.value=false;}
}
async function more(){
  const own=requests.value;if(!own?.next_cursor||busy.value||loading.value)return;
  const epoch=generation;loading.value=true;
  try{const next=decodeIntrusionRequests(await props.api<unknown>(`/software/intrusion-prevention/requests?cursor=${own.next_cursor}`),own.next_cursor);if(disposed||epoch!==generation)return;if(next.actor_id!==own.actor_id)throw Error("账户已变化，未采用上一账户任务");requests.value={...next,entries:[...own.entries,...next.entries]};}
  catch(e){if(!disposed)error.value=(e as Error).message;}finally{if(!disposed)loading.value=false;}
}
async function showJob(row:IntrusionRequest){if(!busy.value&&intrusionID(row.id))await props.onJob(row.id);}
async function submit(action:"install"|"configure"|"uninstall"|"recover"){
  const captured=view.value,own=requests.value;if(!captured||!own||disposed||loading.value||busy.value||ticket.value)return;
  const pending=captured.pending;
  if(action==="recover"?(!pending||!pending.recovery_permitted):!!pending)return;
  if(action==="configure"&&legacy.value)return;
  const settings=action==="recover"?{transaction_id:pending!.id,plan_sha256:pending!.sha256}:action==="uninstall"?{}:{...form.value};
  try{
    await ElMessageBox.confirm(action==="recover"?`仅按原事务 ${pending!.id} 和完整摘要 ${pending!.sha256} 核对。已提交事务仅收尾，未提交事务恢复原完整状态；遇到外部修改或启动身份变化会拒绝覆盖。` :action==="uninstall"?"仅移除云栈拥有的3个文件并恢复独立核对的底层限额/端口；保留 Fail2ban、SSHD 和其他 Jail，不重启或重载。恢复默认封禁时长也会影响当前使用默认时长的封禁到期时间。":"采用实际 SSH 数字端口，不修改 SSH 监听、不重启或重载 Jail。修改默认封禁时长会影响当前和后续使用默认时长的封禁到期时间，开始时间不重置。",actionName(action)+" SSH 防入侵",{type:"warning",confirmButtonText:action==="recover"?"按原事务核对恢复":"确认",cancelButtonText:"取消"});
    if(disposed||captured!==view.value||own!==requests.value)return;
    busy.value=true;error.value="";
    const check=decodeIntrusionRequests(await props.api<unknown>("/software/intrusion-prevention/requests"));
    if(disposed||check.actor_id!==own.actor_id)throw Error("账户已变化，未提交上一账户配置");
    const key=Array.from(crypto.getRandomValues(new Uint8Array(16)),n=>n.toString(16).padStart(2,"0")).join("");
    const original:OriginalTicket={action,actor:own.actor_id,store:action==="install",...(action!=="install"?{key}:{})};
    ticket.value=original;
    const job=action==="install"?await props.onInstall("intrusion-prevention",settings):(await props.api<{job_id:string}>(`/software/intrusion-prevention/${action}`,"POST",{actor_id:own.actor_id,settings},key)).job_id;
    if(!intrusionID(job))throw Error("回复缺少原任务标识；结果未知，未重发");
    if(!disposed){ticket.value={...original,job};await props.onJob(job);}
  }catch(e){if(!disposed&&!['cancel','close'].includes(String(e)))error.value=(e as Error).message||"请求结果尚未确认，未自动重发";}
  finally{if(!disposed)busy.value=false;}
}
onMounted(refresh);onUnmounted(()=>{disposed=true;++generation;});
</script>

<template>
  <section class="intrusion-workspace" aria-label="SSH 防入侵工作台">
    <header><div><h3>SSH 防入侵</h3><p>实际监听 · Fail2ban 限额与作用域 · 封禁保留 · 原事务恢复</p></div><el-button :loading="loading" :disabled="busy" @click="refresh">只读刷新</el-button></header>
    <el-alert v-if="error" type="error" :title="error" :closable="false"/>
    <el-alert v-if="ticket" type="warning" :closable="false" :title="ticket.job?`原${actionName(ticket.action)}任务 ${ticket.job} 已入队；不代表执行或实装验收通过。` : ticket.store?'签名仓库安装结果尚未确认；原请求由应用商店管理，未创建第二个请求。':`原请求 ${ticket.key} 结果尚未确认；未自动重发。关闭窗口不会取消后台任务，可在账户原请求目录继续核对。`"/>
    <el-empty v-if="!view&&!loading" description="状态尚未完整核对，变更入口保持关闭"/>
    <template v-if="view">
      <div class="intrusion-summary">
        <div><small>安装状态</small><strong>{{ view.pending?'原事务未闭合':current?.installed?'已安装 v'+current.version:'未安装' }}</strong><span>{{ formatPanelDateTime(view.checked_at) }}</span></div>
        <div><small>实际 SSH 监听</small><strong>{{ ports(current?.ssh_listening_ports) }}</strong><span>{{ current?.ssh_ports_match?'与 SSHD 配置一致':'未完成一致性核对' }}</span></div>
        <div><small>实际内核作用域</small><strong>{{ current?.kernel_scope_verified?'本次采样通过':current?.kernel_scope_deferred?'等待首次封禁':'尚未通过' }}</strong><span>不等于攻击拦截旅程验收</span></div>
        <div><small>当前封禁</small><strong>{{ current?.active_bans_known?current.active_bans:'未知' }}</strong><span>完整地址与解封仍在安全中心</span></div>
      </div>
      <el-alert :type="current?.healthy?'success':'warning'" :title="view.detail" :closable="false"/>
      <el-alert type="info" :title="view.ban_duration_semantics" :closable="false"/>
      <section v-if="view.pending" class="intrusion-pending"><h4>原事务需要核对</h4><dl><dt>原任务</dt><dd>{{ view.pending.id }}</dd><dt>完整摘要</dt><dd>{{ view.pending.sha256 }}</dd><dt>操作 / 状态</dt><dd>{{ actionName(view.pending.action) }} / {{ view.pending.state }}</dd><dt>动作端口</dt><dd>{{ ports(view.pending.before_ports) }} → {{ ports(view.pending.target_ports) }}</dd><dt>实际 SSH 端口</dt><dd>{{ ports(view.pending.ssh_observed_ports) }}（不会改写监听）</dd></dl><p>{{ view.pending.detail }}</p><div class="intrusion-table-scroll compact" role="region" aria-label="原事务限额变更" tabindex="0"><table><thead><tr><th scope="col">限额</th><th scope="col">原状态</th><th scope="col">目标状态</th></tr></thead><tbody><tr v-for="key in Object.keys(view.pending.before_settings)" :key="key"><th scope="row">{{ label(key) }}</th><td>{{ view.pending.before_settings[key] }}</td><td>{{ view.pending.target_settings[key] }}</td></tr></tbody></table></div><el-button type="warning" :disabled="busy||loading||!!ticket||!requests||!view.pending.recovery_permitted" @click="submit('recover')">按原事务显式恢复</el-button><small>只读预检不是写入许可；提交时仍逐项重新核对。不会重建历史封禁或自动补偿。</small></section>
      <el-tabs v-model="tab">
        <el-tab-pane label="状态与作用域" name="overview">
          <el-alert v-for="warning in current?.warnings||[]" :key="warning" :title="warning" type="warning" :closable="false"/>
          <div class="intrusion-table-scroll actions" role="region" aria-label="运行中封禁动作与内核作用域" tabindex="0"><table><thead><tr><th scope="col">封禁动作</th><th scope="col">数字端口</th><th scope="col">协议</th><th scope="col">实际内核</th><th scope="col">证据范围</th></tr></thead><tbody><tr v-for="row in current?.actions||[]" :key="row.name"><th scope="row">{{ row.name }}</th><td>{{ ports(row.ports) }}</td><td>{{ row.protocol }}</td><td>{{ row.kernel_scope_verified?'采样通过':row.kernel_scope_deferred?'等待创建':'未核对' }}</td><td>{{ row.detail }}</td></tr><tr v-if="!current?.actions.length"><td colspan="5" class="empty">没有完整动作观察，不猜测默认范围</td></tr></tbody></table></div>
          <div class="intrusion-table-scroll compact" role="region" aria-label="配置与运行限额对照" tabindex="0"><table><thead><tr><th scope="col">限额</th><th scope="col">清单值</th><th scope="col">运行值</th></tr></thead><tbody><tr v-for="row in limits" :key="row.key"><th scope="row">{{ row.label }}</th><td>{{ row.configured??'未记录' }}</td><td>{{ row.actual===undefined?'未知':row.actual/row.factor }}</td></tr></tbody></table></div>
          <p>配置、运行属性、当前内核集合及服务状态分别核对；只读采样通过不代表已完成失败登录、冷启动或长期运行验收。</p>
        </el-tab-pane>
        <el-tab-pane label="防护设置" name="settings">
          <el-alert v-if="legacy" type="warning" :title="'当前为旧版。请先在应用商店完成签名 ' + intrusionCurrentVersion + ' 更新；保存配置不会代替更新或改写版本标签。'" :closable="false"/>
          <el-form label-position="top" :disabled="blocked||legacy"><div class="intrusion-form"><el-form-item label="失败次数"><el-input-number v-model="form.max_retry" :min="2" :max="20" :precision="0"/></el-form-item><el-form-item label="统计窗口（分钟）"><el-input-number v-model="form.find_time_minutes" :min="1" :max="1440" :precision="0"/></el-form-item><el-form-item label="封禁时长（分钟）"><el-input-number v-model="form.ban_time_minutes" :min="10" :max="10080" :precision="0"/></el-form-item></div></el-form>
          <p>仅接管已运行且受支持的 SSHD Jail；不自动改造自定义动作、切换日志后端或安装依赖。检测到外部改动、未知状态会停止并保留原证据。</p>
          <div class="intrusion-buttons"><el-button type="primary" :disabled="blocked||legacy" @click="submit(current?.installed?'configure':'install')">{{ current?.installed?'保存并核对实际策略':'从签名应用仓库安装' }}</el-button><el-button v-if="current?.installed" type="danger" plain :disabled="blocked" @click="submit('uninstall')">恢复底层策略并移除受管文件</el-button></div>
        </el-tab-pane>
        <el-tab-pane label="事务回执" name="history"><p>原回执不自动清理，也不证明当前状态持续健康。保留的原子临时记录：{{ view.retained_temporaries }}。</p><div class="intrusion-table-scroll receipts" role="region" aria-label="不可变原事务回执" tabindex="0"><table><thead><tr><th scope="col">完成时间</th><th scope="col">操作</th><th scope="col">终态</th><th scope="col">原事务 ID</th><th scope="col">完整摘要</th></tr></thead><tbody><tr v-for="row in view.history" :key="row.id"><td>{{ formatPanelDateTime(row.finished_at) }}</td><td>{{ actionName(row.action) }}</td><td>{{ row.state }}</td><td class="identity">{{ row.id }}</td><td class="identity">{{ row.sha256 }}</td></tr><tr v-if="!view.history.length"><td colspan="5" class="empty">尚无完整终态回执</td></tr></tbody></table></div></el-tab-pane>
        <el-tab-pane label="当前账户原请求" name="requests"><p>关闭窗口后通过账户 ID 查回原任务，只读查看不会重发。签名安装和更新请求在应用商店核对；这里仅列配置、移除和显式恢复。</p><div class="intrusion-table-scroll originals" role="region" aria-label="当前账户原请求目录" tabindex="0"><table><thead><tr><th scope="col">提交时间</th><th scope="col">操作</th><th scope="col">任务状态</th><th scope="col">原任务</th><th scope="col">查看</th></tr></thead><tbody><tr v-for="row in requests?.entries||[]" :key="row.id"><td>{{ formatPanelDateTime(row.created_at) }}</td><td>{{ actionName(row.action) }}</td><td>{{ row.state }}</td><td class="identity">{{ row.id }}</td><td><el-button link :disabled="busy" @click="showJob(row)">原任务详情</el-button></td></tr><tr v-if="!requests?.entries.length"><td colspan="5" class="empty">当前页没有已绑定原请求；不据此推断未知请求未提交</td></tr></tbody></table></div><el-button v-if="requests?.next_cursor" :loading="loading" :disabled="busy" @click="more">继续只读加载</el-button></el-tab-pane>
      </el-tabs>
    </template>
  </section>
</template>

<style scoped>
.intrusion-workspace{display:grid;grid-template-columns:minmax(0,1fr);gap:16px;color:#304960;min-width:0}.intrusion-workspace>*{min-width:0}.intrusion-workspace :deep(.el-tabs),.intrusion-workspace :deep(.el-tab-pane){min-width:0;max-width:100%}.intrusion-workspace header{display:flex;justify-content:space-between;gap:16px;align-items:center}.intrusion-workspace h3,.intrusion-workspace h4{margin:0 0 8px}.intrusion-workspace p{line-height:1.65;color:#61768a;margin:8px 0}.intrusion-summary{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:12px}.intrusion-summary>div{display:grid;gap:8px;padding:16px;border:1px solid #e2e9ee;border-radius:10px;background:#f5f8fa}.intrusion-summary strong{font-size:19px;color:#18362f;overflow-wrap:anywhere}.intrusion-summary small,.intrusion-summary span{font-size:12px;color:#61768a}.intrusion-pending{padding:18px;border:1px solid #f2db9e;border-radius:10px;background:#fffbef}.intrusion-pending dl{display:grid;grid-template-columns:120px 1fr;gap:10px}.intrusion-pending dd{margin:0;overflow-wrap:anywhere;font-family:monospace}.intrusion-pending small{display:block;margin-top:10px}.intrusion-pending>.el-button{margin-top:16px}.intrusion-form{display:flex;flex-wrap:wrap;gap:28px}.intrusion-buttons{display:flex;gap:12px;flex-wrap:wrap;margin-top:20px}.el-alert+.el-alert{margin-top:10px}@media(max-width:760px){.intrusion-summary{grid-template-columns:repeat(2,minmax(0,1fr))}.intrusion-pending dl{grid-template-columns:1fr}.intrusion-workspace header{align-items:flex-start}}
.intrusion-table-scroll{min-width:0;max-width:100%;overflow:auto;max-height:380px;overscroll-behavior-inline:contain;border-radius:6px}.intrusion-table-scroll:focus-visible{outline:2px solid #0b9963;outline-offset:2px}.intrusion-table-scroll table{width:100%;border-collapse:collapse;background:#fff;color:#526574;font-size:14px;text-align:left}.intrusion-table-scroll th,.intrusion-table-scroll td{padding:12px;border-bottom:1px solid #e4ebef;vertical-align:top;line-height:1.5}.intrusion-table-scroll thead th{position:sticky;top:0;background:#f8fafb;color:#62778b;font-weight:600;z-index:1}.intrusion-table-scroll tbody th{font-weight:400}.intrusion-table-scroll .empty{text-align:center;color:#81929f;padding:28px 14px}.intrusion-table-scroll.compact table{min-width:290px}.intrusion-table-scroll.actions table{min-width:680px}.intrusion-table-scroll.receipts table{min-width:1120px}.intrusion-table-scroll.originals table{min-width:800px}.intrusion-table-scroll .identity{font-family:monospace;white-space:nowrap}
</style>
