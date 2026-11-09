<script setup lang="ts">
import { computed, onMounted, onUnmounted, ref } from "vue";
import { ElMessageBox } from "element-plus";
import { formatPanelDateTime } from "./panelTime";

type API = <T>(path: string, method?: string, body?: unknown, key?: string) => Promise<T>;
interface Parameter { key:string; actual:string; target:string; original:string; managed:boolean; original_known:boolean; reversible:boolean; drift:boolean; detail:string }
interface Transaction { id:string; sha256:string; action:string; started_at:string; finished_at?:string; from_profile:string; to_profile:string; state:string; recovery_permitted:boolean; detail:string }
interface Inspection { format:number; checked_at:string; installed:boolean; healthy:boolean; version:string; profile:string; config_matches:boolean; originals_complete:boolean; parameters:Parameter[]; pending:Transaction|null; history:Transaction[]; retained_temporaries:number; detail:string }
const props=defineProps<{api:API;onInstall:(id:string,settings:Record<string,unknown>)=>Promise<string>;onJob:(id:string)=>Promise<void>}>();
const view=ref<Inspection>(), error=ref(""), busy=ref(false), loading=ref(false), profile=ref("baseline"), filter=ref("all"), tab=ref("parameters");
const ticket=ref<{action:string;key:string;job?:string}>();
let disposed=false, generation=0;
const id=/^[a-f0-9]{32}$/, hash=/^[a-f0-9]{64}$/;
const knownKeys=new Set(["fs.protected_fifos","fs.protected_hardlinks","fs.protected_regular","fs.protected_symlinks","kernel.dmesg_restrict","kernel.kptr_restrict","kernel.unprivileged_bpf_disabled","kernel.yama.ptrace_scope","net.ipv4.conf.all.accept_redirects","net.ipv4.conf.all.log_martians","net.ipv4.conf.all.send_redirects","net.ipv4.conf.default.accept_redirects","net.ipv4.conf.default.send_redirects","net.ipv6.conf.all.accept_redirects","net.ipv6.conf.default.accept_redirects"]);
function transaction(v:Transaction){return v && id.test(v.id) && hash.test(v.sha256) && typeof v.recovery_permitted==="boolean" && typeof v.state==="string";}
function validate(v:Inspection):boolean {
  return v?.format===1 && typeof v.installed==="boolean" && typeof v.healthy==="boolean" && typeof v.originals_complete==="boolean" && typeof v.config_matches==="boolean" && typeof v.detail==="string" && typeof v.checked_at==="string"
    && Array.isArray(v.parameters) && v.parameters.length===knownKeys.size && new Set(v.parameters.map(p=>p.key)).size===knownKeys.size
    && v.parameters.every(p=>knownKeys.has(p.key) && [p.actual,p.target,p.original,p.detail].every(x=>typeof x==="string") && [p.managed,p.original_known,p.reversible,p.drift].every(x=>typeof x==="boolean"))
    && Array.isArray(v.history) && v.history.length<=128 && v.history.every(transaction) && (v.pending===null || transaction(v.pending));
}
async function refresh(){
  if(disposed || loading.value || busy.value)return;
  const epoch=++generation;loading.value=true;error.value="";view.value=undefined;
  try{const out=await props.api<Inspection>("/software/system-hardening/inspection");if(disposed||epoch!==generation)return;if(!validate(out))throw Error("系统加固完整状态不可核对；未把旧状态当作健康");view.value=out;profile.value=out.profile || "baseline";}
  catch(e){if(!disposed&&epoch===generation)error.value=(e as Error).message;}
  finally{if(!disposed&&epoch===generation)loading.value=false;}
}
const drift=computed(()=>view.value?.parameters.filter(p=>p.drift).length || 0);
const rows=computed(()=>view.value?.parameters.filter(p=>filter.value==="all" || filter.value==="managed"&&p.managed || filter.value==="drift"&&p.drift || filter.value==="locked"&&!p.reversible) || []);
const disabled=computed(()=>!view.value || loading.value || busy.value || !!ticket.value || !!view.value.pending);
const profileName=(p:string)=>p==="strict"?"严格基线":p==="baseline"?"基础基线":"未安装";
const actionName=(a:string)=>({install:"安装",configure:"配置",uninstall:"卸载",update:"更新",recover:"显式恢复"}[a] || a);
function newKey(){return Array.from(crypto.getRandomValues(new Uint8Array(16)),v=>v.toString(16).padStart(2,"0")).join("");}
async function submit(action:"install"|"configure"|"uninstall"|"recover"){
  const captured=view.value;if(!captured || busy.value || ticket.value || loading.value || disposed)return;
  if(action!=="recover" && captured.pending)return;
  const pending=captured.pending;
  if(action==="recover" && (!pending || !pending.recovery_permitted))return;
  try{
    await ElMessageBox.confirm(action==="recover" ? `仅按原事务 ${pending!.id} 和完整 SHA-256 ${pending!.sha256} 核对恢复。若已持久提交，仅收尾记录，不回滚已提交基线；若存在外部修改则拒绝覆盖。` : action==="uninstall" ? "仅恢复完整原值记录，移除云栈受管配置；不重启系统，不猜测系统默认值。" : `应用${profileName(profile.value)}。先记录本次实际值和完整文件，再逐项验证；不可即时撤销的内核锁定值会被拒绝。`,actionName(action)+"系统基线加固",{type:"warning",confirmButtonText:action==="recover"?"按原事务恢复":"确认"});
    if(disposed || captured!==view.value)return;
    busy.value=true;error.value="";
    const original={action,key:newKey()} as {action:string;key:string;job?:string};ticket.value=original;
    const job=action==="install" ? await props.onInstall("system-hardening",{profile:profile.value}) : (await props.api<{job_id:string}>(`/software/system-hardening/${action}`,"POST",{settings:action==="recover"?{transaction_id:pending!.id,sha256:pending!.sha256,confirm:pending!.id}:action==="uninstall"?{}:{profile:profile.value}},original.key)).job_id;
    if(!id.test(job))throw Error("回复缺少有效原任务身份；未自动重发");original.job=job;
    if(disposed)return;
    await props.onJob(job);
  }catch(e){if(!disposed && (e as Error)?.message!=="cancel" && (e as Error)?.message!=="close")error.value=(e as Error)?.message || "请求结果未确认；请核对原任务，未自动重发";}
  finally{if(!disposed)busy.value=false;}
}
async function showOriginal(){const job=ticket.value?.job;if(job&&!busy.value)await props.onJob(job);}
onMounted(refresh);onUnmounted(()=>{disposed=true;++generation;});
</script>

<template>
  <section class="hardening-workspace" aria-label="系统基线加固工作台">
    <header><div><h3>系统基线加固</h3><p>内核参数 · 真实原值 · 偏差核对 · 原事务恢复</p></div><el-button :loading="loading" :disabled="busy" @click="refresh">只读刷新</el-button></header>
    <el-alert v-if="error" type="error" :title="error" :closable="false"/>
    <el-alert v-if="ticket" type="warning" :closable="false" :title="`原${actionName(ticket.action)}请求${ticket.job?'已入队 · '+ticket.job:'结果尚未确认 · '+ticket.key}。未自动重发；请保留原身份并核对任务。关闭本工作区不会取消后台任务，也不代表请求未提交。`"/>
    <el-button v-if="ticket?.job" :disabled="busy" @click="showOriginal">查看原任务</el-button>
    <el-empty v-if="!view && !loading" description="安装状态尚未核对；未开放变更"/>
    <template v-if="view">
      <div class="hardening-summary"><div><small>安装与当前基线</small><strong>{{ view.installed ? profileName(view.profile) : '未安装' }}</strong><span>{{ view.version ? 'v'+view.version : '—' }}</span></div><div><small>实际参数偏差</small><strong>{{ drift }}</strong><span>共 {{ view.parameters.length }} 项固定核对</span></div><div><small>原值与文件</small><strong>{{ view.originals_complete ? '原值完整' : view.installed ? '待核对' : '尚未记录' }}</strong><span>{{ view.config_matches ? '完整配置一致' : '配置需核对' }}</span></div><div><small>当前结果</small><strong>{{ view.pending ? '事务未闭合' : view.healthy ? '核对通过' : view.installed ? '需要处理' : '未启用' }}</strong><span>{{ formatPanelDateTime(view.checked_at) }}</span></div></div>
      <el-alert :type="view.healthy?'success':'warning'" :title="view.detail" :closable="false"/>
      <section v-if="view.pending" class="hardening-pending"><h4>原事务恢复</h4><dl><dt>原任务</dt><dd>{{ view.pending.id }}</dd><dt>完整摘要</dt><dd>{{ view.pending.sha256 }}</dd><dt>操作与状态</dt><dd>{{ actionName(view.pending.action) }} · {{ view.pending.state }} · {{ profileName(view.pending.from_profile) }} → {{ profileName(view.pending.to_profile) }}</dd></dl><p>{{ view.pending.detail }}</p><el-button type="warning" :disabled="busy || !!ticket || !view.pending.recovery_permitted" @click="submit('recover')">按原事务显式恢复</el-button><small>不是重试安装；提交时重新核对，外部变更不会被覆盖。</small></section>
      <el-tabs v-model="tab">
        <el-tab-pane label="内核参数" name="parameters"><el-radio-group v-model="filter"><el-radio-button value="all">全部</el-radio-button><el-radio-button value="managed">受管</el-radio-button><el-radio-button value="drift">有偏差</el-radio-button><el-radio-button value="locked">不可即时撤销</el-radio-button></el-radio-group><el-table :data="rows" max-height="390" empty-text="当前筛选无项目"><el-table-column prop="key" label="内核参数" min-width="285"/><el-table-column label="实际值" width="90"><template #default="{row}">{{ row.actual || '未知' }}</template></el-table-column><el-table-column label="基线值" width="90"><template #default="{row}">{{ row.managed ? row.target : '未受管' }}</template></el-table-column><el-table-column label="真实原值" width="100"><template #default="{row}">{{ row.original_known ? row.original : '未记录' }}</template></el-table-column><el-table-column label="核对" min-width="200"><template #default="{row}"><el-tag :type="row.drift || row.detail ? 'warning' : 'info'">{{ row.detail || (row.drift ? '存在偏差' : row.managed ? '一致' : '只读观察') }}</el-tag></template></el-table-column></el-table></el-tab-pane>
        <el-tab-pane label="基线设置" name="settings"><el-form label-position="top" :disabled="disabled"><el-form-item label="选择固定基线"><el-select v-model="profile"><el-option value="baseline" label="基础基线 · 链接保护、ptrace、重定向限制"/><el-option value="strict" label="严格基线 · 另加可逆 BPF 禁用与异常包日志"/></el-select></el-form-item></el-form><el-alert type="info" :closable="false" title="严格模式使用 BPF=2，不写入本次启动不可撤销的 BPF=1。切换回基础基线会释放新增参数并恢复实际原值。"/><div class="hardening-actions"><el-button type="primary" :disabled="disabled" @click="submit(view.installed?'configure':'install')">{{ view.installed ? '保存并核对实际基线' : '从签名应用仓库安装' }}</el-button><el-button v-if="view.installed" type="danger" plain :disabled="disabled || !view.originals_complete" @click="submit('uninstall')">恢复原值并卸载</el-button></div></el-tab-pane>
        <el-tab-pane label="事务回执" name="history"><p>终态回执证明对应原任务已闭合，不等于当前内核持续健康。原证据不自动清理；残留原子临时记录 {{ view.retained_temporaries }} 份。</p><el-table :data="view.history" max-height="360" empty-text="尚无完整持久回执"><el-table-column label="时间" min-width="165"><template #default="{row}">{{ formatPanelDateTime(row.finished_at || row.started_at) }}</template></el-table-column><el-table-column label="操作" width="90"><template #default="{row}">{{ actionName(row.action) }}</template></el-table-column><el-table-column prop="state" label="终态" width="130"/><el-table-column prop="id" label="原任务 ID" min-width="270"/><el-table-column prop="sha256" label="原计划 SHA-256" min-width="460"/></el-table></el-tab-pane>
      </el-tabs>
    </template>
  </section>
</template>

<style scoped>
.hardening-workspace{display:grid;gap:16px;color:#304960}.hardening-workspace header{display:flex;align-items:center;justify-content:space-between;gap:16px}.hardening-workspace h3,.hardening-workspace h4{margin:0 0 8px}.hardening-workspace p{line-height:1.6;margin:4px 0;color:#61768a}.hardening-summary{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:12px}.hardening-summary>div{background:#f5f8fa;border:1px solid #e2e9ee;border-radius:10px;padding:16px;display:grid;gap:8px}.hardening-summary strong{font-size:20px;color:#18362f}.hardening-summary small,.hardening-summary span{color:#61768a;font-size:12px}.hardening-pending{background:#fffbef;border:1px solid #f2db9e;border-radius:10px;padding:18px}.hardening-pending dl{display:grid;grid-template-columns:100px 1fr;gap:10px}.hardening-pending dd{margin:0;overflow-wrap:anywhere;font-family:monospace}.hardening-pending small{display:block;margin-top:10px}.hardening-actions{display:flex;gap:12px;flex-wrap:wrap;margin-top:20px}.el-radio-group{margin-bottom:14px}.el-select{width:min(600px,100%)}@media(max-width:760px){.hardening-summary{grid-template-columns:repeat(2,minmax(0,1fr))}.hardening-workspace header{align-items:flex-start}.hardening-pending dl{grid-template-columns:1fr}}
</style>
