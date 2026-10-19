<script setup lang="ts">
import {computed,onMounted,onUnmounted,ref,watch} from 'vue';
import {menuPermissionIDs,validAccessPlan,type AccessPlan} from './menuPermissions';
type API=<T>(path:string,method?:string,body?:unknown)=>Promise<T>;
type Grant={grant_id:string;commands:string[];expires_at:number;revoked:boolean;owner_id:string;installation_id:string;legacy_unbound:boolean;revocable:boolean};
type Plan={plan:{format:number;sha256:string;commands:string[]};grant_id:string;actor_id:string;allowed_commands:string[];expires_at:number};
type Operation={request_id:string;command:string;expected_plan_sha256:string;confirm:string};
type Record={format:number;request:{format:number;grant_id:string;actor_id:string;input:Operation};request_sha256:string;state:string;outcome:string};
const props=defineProps<{api:API;access?:(AccessPlan&{user_id?:string})|null;installed:boolean;installationId:string}>();
const reloadAllowed=computed(()=>validAccessPlan(props.access)&&props.access.role==='admin'&&menuPermissionIDs.every(id=>props.access?.menu_ids.includes(id)));
const base='/app-modules/platform-ops/maintenance';
const grants=ref<Grant[]>([]),operations=ref<Array<{request_id:string;command:string;state:string;outcome:string;request_sha256:string}>>([]),busy=ref(false),error=ref(''),message=ref(''),secret=ref(''),grantUnknown=ref(false);
const commands=ref(['nginx-check']),minutes=ref(60),grantConfirm=ref(''),address=ref(''),token=ref(''),plan=ref<Plan>(),command=ref('nginx-check'),reloadConfirm=ref('');
const pending=ref<{url:string;token:string;actor_id:string;operation:Operation}>();let epoch=0;
let secretGrantID='',secretTimer:ReturnType<typeof setTimeout>|undefined;
function hideSecret(){secret.value='';secretGrantID='';if(secretTimer!==undefined)clearTimeout(secretTimer);secretTimer=undefined;}
function displaySecret(value:string,id:string,expires:number){hideSecret();secret.value=value;secretGrantID=id;secretTimer=setTimeout(()=>{if(secretGrantID===id)hideSecret()},Math.max(0,expires*1000-Date.now()));}
const hex=(v:unknown,n:number):v is string=>typeof v==='string'&&new RegExp(`^[a-f0-9]{${n}}$`).test(v);
function clear(){epoch++;hideSecret();token.value='';plan.value=undefined;pending.value=undefined;reloadConfirm.value='';grantConfirm.value='';commands.value=['nginx-check'];command.value='nginx-check';grants.value=[];operations.value=[];grantUnknown.value=false;error.value='';message.value='';}
watch(()=>props.access,clear,{deep:true});onUnmounted(clear);
watch(()=>props.installationId,clear);
async function sha(text:string){if(!globalThis.crypto?.subtle)throw Error('需 HTTPS 或本机安全连接核对回执');return [...new Uint8Array(await crypto.subtle.digest('SHA-256',new TextEncoder().encode(text)))].map(v=>v.toString(16).padStart(2,'0')).join('');}
async function refresh(){if(busy.value)return;busy.value=true;error.value='';const e=epoch;try{
 const g=await props.api<{entries:Grant[];limit:number;read_only:boolean}>(base+'/grants');const o=await props.api<{entries:typeof operations.value;limit:number;read_only:boolean}>(base+'/operations');
 if(e!==epoch)return;if(g.limit!==128||g.read_only!==true||!Array.isArray(g.entries)||g.entries.length>128||g.entries.some(x=>!hex(x.grant_id,64)||!hex(x.owner_id,32)||!Array.isArray(x.commands)||x.commands.length<1||x.commands.length>2||x.commands.some(c=>!['nginx-check','nginx-reload'].includes(c))||!Number.isSafeInteger(x.expires_at)||typeof x.revoked!=='boolean'||typeof x.revocable!=='boolean'||typeof x.legacy_unbound!=='boolean'||x.legacy_unbound!==(x.installation_id==='')||!x.legacy_unbound&&!hex(x.installation_id,32))||new Set(g.entries.map(x=>x.grant_id)).size!==g.entries.length)throw Error('完整授权库存不可核对');
 if(o.limit!==1024||o.read_only!==true||!Array.isArray(o.entries)||o.entries.length>1024||o.entries.some(x=>!hex(x.request_id,32)||!hex(x.request_sha256,64)||!['nginx-check','nginx-reload'].includes(x.command)||!['dispatched','needs_attention','completed','failed'].includes(x.state)))throw Error('完整原操作库存不可核对');grants.value=g.entries;operations.value=o.entries;grantUnknown.value=false;
 if(secret.value){const current=g.entries.find(g=>g.grant_id===secretGrantID);if(!current||current.revoked||current.legacy_unbound||current.expires_at*1000<=Date.now()||current.installation_id!==props.installationId||current.owner_id!==props.access?.user_id)hideSecret();}
 }catch(x){if(e===epoch){hideSecret();error.value=(x as Error).message;grants.value=[];operations.value=[]}}finally{busy.value=false}}
async function issue(){if(busy.value||!props.installed||!hex(props.installationId,32)||grantUnknown.value||grantConfirm.value!=='GRANT NGINX MAINTENANCE'||commands.value.includes('nginx-reload')&&!reloadAllowed.value)return;busy.value=true;error.value='';message.value='';hideSecret();const e=epoch,expectedInstallation=props.installationId;
 const submitted={commands:[...commands.value].sort(),minutes:minutes.value,confirm:grantConfirm.value};
 try{const out=await props.api<{token:string;grant_id:string;commands:string[];expires_at:number;scope:string;one_time_secret:boolean;installation_id:string}>(base+'/grants','POST',submitted);if(e!==epoch)return;
 const digest=await sha(out.token);if(e!==epoch)return;
 if(!hex(out.token,64)||!hex(out.grant_id,64)||digest!==out.grant_id||out.scope!=='nginx-maintenance'||out.one_time_secret!==true||JSON.stringify(out.commands)!==JSON.stringify(submitted.commands)||!Number.isSafeInteger(out.expires_at)||out.expires_at*1000<=Date.now()||out.expires_at*1000>Date.now()+86400*1000+120000||out.installation_id!==expectedInstallation)throw Error('原授权或安装实例回执不同；不能恢复秘密，请只读核对授权清单');displaySecret(out.token,out.grant_id,out.expires_at);grantConfirm.value='';message.value='维护秘密仅本次显示，不保存到浏览器存储；到期或只读核对发现撤销、身份变化时清空。绑定当前安装实例，重装后不恢复旧权限。发送给受信的协调面板；不要公开分享。';
 }catch(x){if(e===epoch){grantUnknown.value=true;error.value=(x as Error).message}}finally{busy.value=false}}
async function revoke(id:string){if(busy.value||!hex(id,64))return;busy.value=true;error.value='';const e=epoch;try{const out=await props.api<{grant_id:string;revoked:boolean}>(`${base}/grants/${id}/revoke`,'POST',{});if(e!==epoch)return;if(out.grant_id!==id||out.revoked!==true)throw Error('撤销回执不同，请只读核对');message.value='已撤销后续维护授权；不承诺取消已经派发的在途命令。';hideSecret()}catch(x){if(e===epoch)error.value=(x as Error).message}finally{busy.value=false}if(e===epoch)await refresh()}
async function loadPlan(){if(busy.value||!props.installed||pending.value)return;busy.value=true;error.value='';plan.value=undefined;const e=epoch,submitted={url:address.value.trim(),token:token.value};
 try{const out=await props.api<Plan>(base+'/remote/plan','POST',submitted);if(e!==epoch)return;const digest=await sha(submitted.token);if(e!==epoch)return;if(out.plan?.format!==1||!hex(out.plan.sha256,64)||!hex(out.actor_id,32)||!hex(out.grant_id,64)||digest!==out.grant_id||!Array.isArray(out.allowed_commands)||out.allowed_commands.length<1||out.allowed_commands.length>2||out.allowed_commands.some(c=>!['nginx-check','nginx-reload'].includes(c))||new Set(out.allowed_commands).size!==out.allowed_commands.length||!Number.isSafeInteger(out.expires_at)||out.expires_at*1000<=Date.now())throw Error('远端原计划身份或有效期不可核对');plan.value=out;command.value=out.allowed_commands[0];reloadConfirm.value='';
 }catch(x){if(e===epoch)error.value=(x as Error).message}finally{busy.value=false}}
function invalidate(){if(pending.value)return;plan.value=undefined;reloadConfirm.value=''}
async function inspectOrSubmit(inspect:boolean){if(busy.value||!inspect&&pending.value)return;
 if(!inspect){const p=plan.value;if(!props.installed||!p||!p.allowed_commands.includes(command.value)||command.value==='nginx-reload'&&(!reloadAllowed.value||reloadConfirm.value!==`RELOAD NGINX ${p.plan.sha256}`))return;const id=[...crypto.getRandomValues(new Uint8Array(16))].map(x=>x.toString(16).padStart(2,'0')).join('');pending.value={url:address.value.trim(),token:token.value,actor_id:p.actor_id,operation:{request_id:id,command:command.value,expected_plan_sha256:p.plan.sha256,confirm:command.value==='nginx-reload'?reloadConfirm.value:''}}}
 const ticket=pending.value;if(!ticket)return;busy.value=true;error.value='';message.value='';const e=epoch;
 try{const out=await props.api<Record|{request_id:string;state:string;retry_allowed:boolean}>(base+'/remote/commands'+(inspect?'/status':''),'POST',ticket);if(e!==epoch||pending.value!==ticket)return;
 if('retry_allowed' in out){if(out.request_id!==ticket.operation.request_id||out.state!=='needs_attention'||out.retry_allowed!==false)throw Error('待核对回执不是原操作');message.value='原命令结果未确认；保留原 ID 和参数，仅允许只读核对，不自动重发。';return}
 const grantDigest=await sha(ticket.token);if(e!==epoch||pending.value!==ticket)return;
 if(out.format!==1||out.request?.format!==1||out.request.grant_id!==grantDigest||out.request.actor_id!==ticket.actor_id||JSON.stringify(out.request.input)!==JSON.stringify(ticket.operation)||!hex(out.request_sha256,64)||!['completed','failed'].includes(out.state))throw Error('远端终态与原授权或命令不同');
 const expected={format:1,grant_id:out.request.grant_id,actor_id:ticket.actor_id,input:ticket.operation};const requestDigest=await sha(JSON.stringify(expected));if(e!==epoch||pending.value!==ticket)return;if(requestDigest!==out.request_sha256)throw Error('远端原请求摘要不同');
 if(out.state==='completed'&&out.outcome!==(ticket.operation.command==='nginx-check'?'config_valid':'reload_signal_submitted')||out.state==='failed'&&!['command_failed','plan_changed_before_command'].includes(out.outcome))throw Error('命令结果含未经核对的成功解释');message.value=out.state==='failed'?'原命令失败，保留原回执，不自动重跑。':out.outcome==='config_valid'?'远端配置检查完成；这不等于网站业务健康。':'已核对重载命令提交；这不等于所有网站或新工作进程已验收。';pending.value=undefined;plan.value=undefined;reloadConfirm.value='';token.value='';
 }catch(x){if(e===epoch)error.value=(x as Error).message}finally{busy.value=false}}
async function reconcile(id:string){if(busy.value||!hex(id,32))return;busy.value=true;error.value='';const e=epoch;try{const out=await props.api<Record|{state:string;request_id:string;retry_allowed:boolean}>(`${base}/operations/${id}/reconcile`,'POST',{});if(e!==epoch)return;message.value='已只读核对原生原回执，没有重发命令。';if('request_id' in out&&out.state==='needs_attention')message.value='原生终态仍未核对；保留原任务，禁止换 ID 重载。'}catch(x){if(e===epoch)error.value=(x as Error).message}finally{busy.value=false}if(e===epoch)await refresh()}
onMounted(refresh);
</script>
<template>
 <section class="maintenance" aria-label="受限跨主机维护">
  <p>此通道独立于旧健康读取。维护授权限时且可撤销，只允许固定 Nginx 检查和重载；不执行自由脚本、补丁安装或文件修改。重载是主机级操作，仅完整权限管理员可授权。撤销阻止后续认证，不承诺中止已授权的在途操作。</p>
  <el-alert v-if="!installed" type="warning" title="需明确更新并核对平台运维1.3.0，旧版仍仅提供健康读取。不能签发或派发新命令；原授权仍可撤销，原操作仍可只读核对。" :closable="false"/>
  <el-alert v-if="error" type="error" :title="error" :closable="false"/><el-alert v-if="message" type="info" :title="message" :closable="false"/>
  <el-button :disabled="busy" @click="refresh">只读刷新本机授权与原操作</el-button>
  <h4>在目标面板签发独立维护授权</h4>
  <el-checkbox-group v-model="commands" aria-label="维护授权命令范围" :disabled="busy||!installed"><el-checkbox label="Nginx 配置检查" value="nginx-check"/><el-checkbox label="Nginx 受控重载" value="nginx-reload" :disabled="!reloadAllowed"/></el-checkbox-group>
  <label>有效期（分钟，5–1440）<el-input-number v-model="minutes" :min="5" :max="1440" :disabled="busy"/></label>
  <el-input v-model="grantConfirm" aria-label="确认签发维护授权" placeholder="GRANT NGINX MAINTENANCE" :disabled="busy||grantUnknown"/>
  <el-button :disabled="busy||!installed||grantUnknown||!commands.length||grantConfirm!=='GRANT NGINX MAINTENANCE'||commands.includes('nginx-reload')&&!reloadAllowed" @click="issue">生成一次性维护秘密</el-button>
  <el-input v-if="secret" v-model="secret" readonly type="password" show-password aria-label="一次性维护秘密"/>
  <div class="table-scroll"><table><thead><tr><th>授权标识（不是秘密）</th><th>命令范围</th><th>到期（UTC）</th><th>状态</th><th>操作</th></tr></thead><tbody><tr v-for="g in grants" :key="g.grant_id"><td>{{g.grant_id}}</td><td>{{g.commands.join('、')}}</td><td>{{new Date(g.expires_at*1000).toISOString()}}</td><td>{{g.revoked?'已撤销':g.legacy_unbound?'旧原型未绑定，不能授权':g.installation_id!==installationId?'原安装实例已变化':'绑定当前安装实例'}}</td><td><el-button text :disabled="busy||g.revoked||!g.revocable" @click="revoke(g.grant_id)">撤销原授权</el-button></td></tr></tbody></table></div>
  <h4>在协调面板核对并执行远端命令</h4>
  <el-input v-model="address" aria-label="远端 HTTPS 面板地址" placeholder="https://受信面板地址/" :disabled="busy||!!pending" @input="invalidate"/>
  <el-input v-model="token" aria-label="远端独立维护秘密" type="password" :disabled="busy||!!pending" autocomplete="off" @input="invalidate"/>
  <el-button :disabled="busy||!installed||!!pending||!address||!token" @click="loadPlan">只读核对远端维护计划</el-button>
  <template v-if="plan"><p>原计划 SHA-256：{{plan.plan.sha256}}；授权到期：{{new Date(plan.expires_at*1000).toISOString()}}</p><select v-model="command" aria-label="远端固定维护命令" :disabled="busy||!!pending"><option v-for="c in plan.allowed_commands" :key="c" :value="c">{{c==='nginx-check'?'Nginx 配置检查':'Nginx 受控重载'}}</option></select>
   <el-input v-if="command==='nginx-reload'" v-model="reloadConfirm" aria-label="确认原计划 Nginx 重载" :placeholder="`RELOAD NGINX ${plan.plan.sha256}`" :disabled="busy||!!pending"/>
   <el-button :disabled="busy||!installed||!!pending||command==='nginx-reload'&&(!reloadAllowed||reloadConfirm!==`RELOAD NGINX ${plan.plan.sha256}`)" @click="inspectOrSubmit(false)">执行已授权原命令一次</el-button>
  </template>
  <template v-if="pending"><p>原操作 ID：{{pending.operation.request_id}}。仅原回执核对，不换 ID、不自动重试。页面关闭会清除本机内存秘密；可由目标面板管理员在原操作列表核对。</p><el-button :disabled="busy" @click="inspectOrSubmit(true)">只读核对原远端操作</el-button></template>
  <h4>本机维护原操作</h4><div class="table-scroll"><table><thead><tr><th>原操作 ID</th><th>命令</th><th>状态</th><th>结果代码</th><th>操作</th></tr></thead><tbody><tr v-for="o in operations" :key="o.request_id"><td>{{o.request_id}}</td><td>{{o.command}}</td><td>{{o.state}}</td><td>{{o.outcome}}</td><td><el-button text :disabled="busy" @click="reconcile(o.request_id)">只读核对原回执</el-button></td></tr></tbody></table></div>
 </section>
</template>
<style scoped>
.maintenance{min-width:0}.maintenance p,.maintenance td{overflow-wrap:anywhere}.maintenance p{line-height:1.65;color:var(--el-text-color-secondary)}.maintenance .el-input{margin:8px 0}.maintenance .el-alert{margin:10px 0}.maintenance label{display:flex;gap:12px;align-items:center;margin:12px 0}.table-scroll{max-width:100%;overflow:auto;max-height:360px;margin:12px 0;border:1px solid var(--el-border-color);border-radius:6px}.table-scroll table{width:100%;min-width:740px;border-collapse:collapse;table-layout:fixed;font-size:12px}.table-scroll td,.table-scroll th{padding:10px;border-bottom:1px solid var(--el-border-color-lighter);text-align:left;vertical-align:top}.table-scroll th{position:sticky;top:0;background:var(--el-fill-color-light)}.maintenance select{padding:8px;border:1px solid var(--el-border-color);border-radius:4px;background:var(--el-bg-color);color:var(--el-text-color-regular);max-width:100%}
</style>
