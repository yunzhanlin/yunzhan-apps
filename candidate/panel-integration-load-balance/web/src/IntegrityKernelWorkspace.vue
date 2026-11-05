<script setup lang="ts">
import { computed, onBeforeUnmount, ref, shallowRef, watch } from 'vue';
import { canOpenAppModule, type AccessPlan } from './menuPermissions';
import { integrityKernelVersion, kernelActionInput, kernelAdmissionMatches, kernelFullAdministrator, kernelNewSubmissionKey, kernelOperationID, kernelPendingMatches, kernelPendingValid, kernelStateLabel, kernelStatusValid, type KernelOperation, type KernelPending, type KernelStatus } from './integrityKernel';

type API=<T>(path:string,method?:string,body?:unknown,idempotencyKey?:string,signal?:AbortSignal)=>Promise<T>;
const props=defineProps<{api:API;actor:string;access?:AccessPlan|null;active:boolean;installed:boolean;installedVersion?:string;sites:{id:string;name:string;domain?:string}[]}>();
const emit=defineEmits<{baseline:[]}>();
const site=ref(''),snapshot=shallowRef<KernelStatus>(),pending=shallowRef<KernelPending>(),accepted=shallowRef<KernelOperation>();
const busy=ref(false),error=ref(''),notice=ref('');
let generation=0,controller:AbortController|undefined,timer:ReturnType<typeof setTimeout>|undefined,failures=0;
const base='/app-modules/website-tamper-proof/kernel';
const readable=computed(()=>props.active&&props.installed&&/^[a-f0-9]{32}$/.test(props.actor)&&canOpenAppModule(props.access??null,'website-tamper-proof'));
const writable=computed(()=>readable.value&&props.installedVersion===integrityKernelVersion&&kernelFullAdministrator(props.access));
const selectedSite=computed(()=>props.sites.find(value=>value.id===site.value));
const operations=computed(()=>snapshot.value?.operations.slice(-20).reverse()??[]);
const label=computed(()=>snapshot.value?kernelStateLabel[snapshot.value.state]:'尚未读取当前状态');
function canAct(action:'enable'|'release') {
  if(!writable.value||busy.value||pending.value||!snapshot.value)return false;
  try{kernelActionInput(snapshot.value,action,site.value);return true}catch{return false}
}
function storageKey(actor:string){return `yunzhan-kernel-pending-v1/${actor}`}
function savePending(value:KernelPending){
  pending.value=value;
  try{sessionStorage.setItem(storageKey(value.actor),JSON.stringify(value))}catch{notice.value='浏览器不能保存提交标识；当前页面会保留它，服务端仍保留原任务。回执未知时请先核对原任务。'}
}
function clearPending(){const original=pending.value;pending.value=undefined;if(original)try{sessionStorage.removeItem(storageKey(original.actor))}catch{/* Original server record remains authoritative. */}}
function stop(){generation++;controller?.abort();controller=undefined;if(timer)clearTimeout(timer);timer=undefined;busy.value=false;snapshot.value=undefined;accepted.value=undefined}
function armPoll(){
  if(timer)clearTimeout(timer);
  if(!readable.value||!site.value||!pending.value&&!['queued','running'].includes(snapshot.value?.state??''))return;
  timer=setTimeout(()=>void refresh(),Math.min(30000,2500*2**Math.min(failures,3)));
}
async function refresh(){
  if(!readable.value||!/^[a-f0-9]{32}$/.test(site.value)||busy.value)return;
  const epoch=generation,actor=props.actor,chosen=site.value,request=new AbortController();controller=request;busy.value=true;error.value='';let reread=false;
  try{
    const value=await props.api<unknown>(`${base}?site_id=${chosen}`,'GET',undefined,undefined,request.signal);
    if(epoch!==generation||actor!==props.actor||chosen!==site.value||!readable.value||request.signal.aborted)return;
    if(!kernelStatusValid(value,chosen))throw Error('当前网站的原任务、修订、摘要或状态不能核对；未显示为已启用。');
    if(pending.value){
      const original=value.operations.find(op=>op.request.id===pending.value!.id);
      if(original){if(!kernelPendingMatches(pending.value,original))throw Error('原提交标识与操作者或输入不一致；保留原记录，不换键提交。');accepted.value=original;clearPending();notice.value='已从服务端核对原任务；没有重发内核操作。'}
      else{
        const ticket=pending.value;
        const admission=await props.api<unknown>(`${base}/admissions/${ticket.id}`,'GET',undefined,undefined,request.signal);
        if(epoch!==generation||actor!==props.actor||chosen!==site.value||!readable.value||request.signal.aborted)return;
        if(!kernelAdmissionMatches(ticket,admission))throw Error('原提交的受理或封存见证不能核对；没有换键执行。');
        if(admission.state==='sealed'){accepted.value=admission.operation;clearPending();notice.value=`原未开始提交已独立封存（${admission.closure!.id}），迟到请求不会执行；原数据与保护记录保留。`;reread=!!admission.operation}
        else if(admission.state==='original'){accepted.value=admission.operation;clearPending();notice.value='已核对原提交，保留其实际状态，没有重发操作。';reread=true}
        else notice.value='尚未发现原提交的明确回执，结果仍待核对。可明确封存尚未开始的原提交；已开始的操作不会被取消或改写。';
      }
    }
    if(accepted.value){const current=value.operations.find(op=>op.request.id===accepted.value!.request.id);if(current)accepted.value=current}
    snapshot.value=reread?undefined:value;failures=0;
  }catch(e){if(epoch===generation&&!request.signal.aborted){snapshot.value=undefined;error.value=e instanceof Error?e.message:String(e);failures++}}
  finally{if(epoch===generation){busy.value=false;if(controller===request)controller=undefined;if(reread)timer=setTimeout(()=>void refresh(),0);else armPoll()}}
}
async function submit(action:'enable'|'release'){
  if(!canAct(action)||!snapshot.value)return;
  const input=kernelActionInput(snapshot.value,action,site.value),actor=props.actor,epoch=generation,key=kernelNewSubmissionKey();
  const ticket:KernelPending={id:kernelOperationID(actor,key),key,actor,action,input};
  // Persist the original identity before sending. An unknown response is
  // reconciled only by GET; neither polling nor remount replays the POST.
  savePending(ticket);snapshot.value=undefined;accepted.value=undefined;busy.value=true;error.value='';
  const request=new AbortController();controller=request;
  try{
    const reply=await props.api<unknown>(`${base}/${action}`,'POST',input,key,request.signal);
    if(epoch!==generation||actor!==props.actor||!readable.value||request.signal.aborted)return;
    if(!kernelPendingMatches(ticket,reply))throw Error('原提交回执身份不能核对；保留原标识，只读查询。');
    accepted.value=reply;clearPending();notice.value='原后台任务已接收。只有完整原生验证通过后才显示完成；关闭页面不会取消服务端任务。';
  }catch(e){if(epoch===generation&&!request.signal.aborted)error.value=`提交结果待核对：${e instanceof Error?e.message:String(e)}。请保留原任务标识，只读刷新。`}
  finally{if(epoch===generation){busy.value=false;if(controller===request)controller=undefined;await refresh()}}
}
async function closeAdmission(){
  if(!writable.value||busy.value||!pending.value)return;
  const ticket={...pending.value,close_key:pending.value.close_key??kernelNewSubmissionKey()};savePending(ticket);
  const epoch=generation,actor=props.actor,request=new AbortController();controller=request;busy.value=true;error.value='';snapshot.value=undefined;
  try{
    const reply=await props.api<unknown>(`${base}/close-admission`,'POST',{original_key:ticket.key,action:ticket.action,input:ticket.input},ticket.close_key,request.signal);
    if(epoch!==generation||actor!==props.actor||!readable.value||request.signal.aborted)return;
    if(!kernelAdmissionMatches(ticket,reply)||reply.state==='absent')throw Error('原提交封存回执不能核对；保留原标识。');
    accepted.value=reply.operation;clearPending();notice.value=reply.state==='sealed'?'原未开始提交已封存，迟到请求不会执行；没有改变已开始的原操作。':'原任务已经开始或结束，保留实际结果，未用封存替代原操作。';
  }catch(e){if(epoch===generation&&!request.signal.aborted)error.value=`原提交封存结果待核对：${e instanceof Error?e.message:String(e)}。继续只读核对原标识。`}
  finally{if(epoch===generation){busy.value=false;if(controller===request)controller=undefined;await refresh()}}
}
watch(()=>[props.actor,props.access,props.active,props.installed,props.installedVersion],()=>{
  stop();error.value='';notice.value='';pending.value=undefined;failures=0;
  if(!readable.value)return;
  try{const saved=sessionStorage.getItem(storageKey(props.actor));if(saved){const value=JSON.parse(saved);if(!kernelPendingValid(value,props.actor))throw Error('原提交标识保存记录不能核对，请先核对服务器原任务。');pending.value=value;site.value=value.input.site_id}}
  catch(e){error.value=e instanceof Error?e.message:String(e);return}
  void refresh();
},{immediate:true,deep:true,flush:'sync'});
function chooseSite(){stop();error.value='';notice.value='';void refresh()}
onBeforeUnmount(stop);
</script>

<template>
  <section class="kernel-workspace" aria-label="网站内核写保护">
    <div class="kernel-heading"><div><h3>内核写保护</h3><p>基于实际 inode 的写入阻止。监控策略的暂停与这里的保护启停独立。</p></div><el-tag :type="snapshot?.state==='enabled'?'success':snapshot?.state==='needs-attention'?'danger':'info'">{{label}}</el-tag></div>
    <el-alert v-if="installedVersion!==integrityKernelVersion" title="先通过版本与更新安装网站防篡改 1.5.0。旧版保留监控、基线与备份，不会因为新界面自动取得内核权限。" type="info" :closable="false"/>
    <el-alert v-if="!kernelFullAdministrator(access)" title="内核写保护启停需要完整管理员权限；服务端会在执行前和每次修改前复核原授权。" type="info" :closable="false"/>
    <el-alert v-if="error" :title="error" type="error" :closable="false"/>
    <el-alert v-if="notice" :title="notice" type="info" :closable="false"/>
    <div class="kernel-toolbar">
      <label>保护网站<el-select v-model="site" aria-label="内核保护网站" placeholder="选择网站后读取实际状态" filterable :teleported="false" :disabled="busy||!!pending||!readable" @change="chooseSite"><el-option v-for="value in sites" :key="value.id" :label="`${value.name}${value.domain?' · '+value.domain:''}`" :value="value.id"/></el-select></label>
      <el-button :disabled="busy||!site||!readable" :loading="busy" @click="refresh">只读刷新</el-button>
      <el-button :disabled="busy||!!pending" @click="emit('baseline')">基线与排除目录</el-button>
    </div>
    <div v-if="pending" class="kernel-original"><p>原提交标识：<code>{{pending.id}}</code>。正在只读核对；不会自动重新提交。</p><el-button type="warning" :disabled="busy||!writable" @click="closeAdmission">封存未开始的原提交</el-button><small>只有原生开始记录不存在时才会封存；已开始、失败或待核对的原操作会保留原结果。</small></div>
    <p v-else-if="accepted" class="kernel-original">已接收原任务：<code>{{accepted.request.id}}</code> · {{kernelStateLabel[accepted.state]??accepted.state}}。</p>
    <template v-if="snapshot">
      <div class="kernel-cards">
        <article><span>当前网站</span><strong>{{selectedSite?.name??snapshot.site_id}}</strong><small>{{selectedSite?.domain??snapshot.site_id}}</small></article>
        <article><span>当前签名基线</span><strong>{{snapshot.baseline_files}} 个文件</strong><small>{{snapshot.baseline_sha?'签名已验证':'尚未建立或不能核对'}}</small></article>
        <article><span>实际执行器能力</span><strong>{{snapshot.cap_linux_immutable?'可使用原生标记':'缺少内核权限'}}</strong><small>修订 {{snapshot.revision}} · {{snapshot.verified_at}}</small></article>
      </div>
      <el-alert v-if="snapshot.error" :title="snapshot.error" type="warning" :closable="false"/>
      <div class="kernel-actions"><el-button type="primary" :disabled="!canAct('enable')" @click="submit('enable')">启用内核写保护</el-button><el-button type="warning" :disabled="!canAct('release')" @click="submit('release')">{{snapshot.state==='needs-attention'?'核对原任务并解除本应用保护':'解除本应用保护'}}</el-button></div>
      <p class="kernel-explanation">启用前请在“基线与排除目录”保留缓存、上传及数据库等动态目录。启用后，受保护目录内的发布、改名和删除也会被阻止；维护网站前先在这里解除。只清除本应用添加的标记，原有不可变标记保留。</p>
      <details class="kernel-digest"><summary>签名应用、基线与原任务摘要</summary><p>签名应用 SHA-256：<code>{{snapshot.app_sha||'尚未核对签名收据'}}</code></p><p>基线签名：<code>{{snapshot.baseline_sha||'无'}}</code></p><template v-if="snapshot.latest"><p>原请求 SHA-256：<code>{{snapshot.latest.request_sha256}}</code></p><p>原 inode 计划 SHA-256：<code>{{snapshot.latest.plan_sha||'尚无完整计划'}}</code></p><p>原启用任务：<code>{{snapshot.latest.enable_operation||'尚未执行'}}</code></p></template></details>
      <h4>原操作记录 <span>共 {{snapshot.operations.length}} 条，显示最近 20 条</span></h4>
      <div class="kernel-table" tabindex="0" aria-label="原内核保护操作记录">
        <table><thead><tr><th>原任务与时间</th><th>动作与修订</th><th>实际结果</th><th>处理对象</th></tr></thead><tbody><tr v-for="op in operations" :key="op.request.id"><td><code>{{op.request.id}}</code><small>{{op.request.created_at}}</small></td><td>{{op.request.action==='enable'?'启用':'解除'}} · {{op.revision}}</td><td>{{kernelStateLabel[op.state]??op.state}}<small v-if="op.error" class="kernel-error">{{op.error}}</small></td><td>{{op.files}} 文件 / {{op.directories}} 目录<small v-if="['queued','running'].includes(op.state)">等待完整原生校验结果</small><small v-else>逐项校验 {{op.completed}} 项</small></td></tr><tr v-if="!operations.length"><td colspan="4">当前网站尚无内核保护操作。</td></tr></tbody></table>
      </div>
      <details class="kernel-limits"><summary>保护范围与运行限制</summary><p>{{snapshot.scope}}</p><p>每站最多 10000 文件、4096 子目录，单文件 8 MiB、内容总计 256 MiB。私有原任务最多 512 份、512 MiB 逻辑预算；新启用预留一次解除容量，不自动删除历史。它不是防止其他程序耗尽磁盘的硬配额。程序升级或卸载前须先解除仍在启用或待核对的内核保护。</p></details>
    </template>
    <p v-else-if="!site" class="kernel-empty">选择要保护的网站。此页面不会自动建立基线、启用保护或修改网站文件。</p>
  </section>
</template>

<style scoped>
.kernel-workspace{min-width:0}.kernel-heading{display:flex;align-items:flex-start;justify-content:space-between;gap:16px;flex-wrap:wrap}.kernel-heading h3{margin:4px 0;font-size:19px}.kernel-heading p,.kernel-explanation,.kernel-limits p{color:var(--el-text-color-secondary);line-height:1.65}.kernel-workspace .el-alert{margin:12px 0}.kernel-toolbar{display:flex;align-items:flex-end;gap:12px;flex-wrap:wrap;margin:20px 0}.kernel-toolbar label{display:grid;gap:8px;flex:1 1 260px;min-width:0}.kernel-toolbar .el-select{width:100%}.kernel-cards{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:12px}.kernel-cards article{display:grid;gap:8px;padding:17px;border:1px solid var(--el-border-color-light);background:var(--el-fill-color-blank);border-radius:8px;min-width:0}.kernel-cards span,.kernel-cards small{font-size:12px;color:var(--el-text-color-secondary)}.kernel-cards strong{font-size:17px;font-weight:600}.kernel-workspace small{display:block;line-height:1.6;overflow-wrap:anywhere}.kernel-workspace code{font-size:12px;overflow-wrap:anywhere;white-space:normal}.kernel-original,.kernel-digest p{overflow-wrap:anywhere;line-height:1.6}.kernel-actions{display:flex;gap:12px;flex-wrap:wrap;margin:18px 0}.kernel-actions .el-button+.el-button,.kernel-toolbar .el-button+.el-button{margin-left:0}.kernel-workspace h4{display:flex;gap:10px;flex-wrap:wrap;margin:24px 0 12px}.kernel-workspace h4 span{font-size:12px;font-weight:400;color:var(--el-text-color-secondary)}.kernel-table{max-width:100%;overflow:auto;border:1px solid var(--el-border-color-light);border-radius:8px;max-height:420px}.kernel-table table{width:100%;min-width:650px;border-collapse:collapse;table-layout:fixed;font-size:13px}.kernel-table th,.kernel-table td{padding:12px;text-align:left;vertical-align:top;border-bottom:1px solid var(--el-border-color-lighter);overflow-wrap:anywhere}.kernel-table th{background:var(--el-fill-color-light);position:sticky;top:0}.kernel-table th:first-child{width:31%}.kernel-error{color:var(--el-color-danger)}.kernel-digest,.kernel-limits{padding:12px;border:1px solid var(--el-border-color-light);border-radius:6px;margin-top:16px}.kernel-workspace summary{cursor:pointer;font-size:13px}.kernel-empty{padding:24px 0;color:var(--el-text-color-secondary)}@media(max-width:700px){.kernel-cards{grid-template-columns:1fr}.kernel-toolbar label{flex-basis:100%}.kernel-actions .el-button{max-width:100%;white-space:normal;height:auto;min-height:34px;padding:10px}.kernel-heading .el-tag{max-width:100%;height:auto;min-height:24px;white-space:normal}.kernel-toolbar{gap:10px}}
</style>
