<script setup lang="ts">
import {computed,onMounted,onBeforeUnmount,ref,watch} from 'vue';
import {mobileWebURL,mobileWebIsLoopback,mobileWebInstallAvailable,watchMobileWebInstall,requestMobileWebInstall} from './mobileWeb';
const props=defineProps<{active:boolean;available:boolean}>();
const address=mobileWebURL(window.location.href);
const loopback=address?mobileWebIsLoopback(address):false;
const secure=window.isSecureContext;
const online=ref(navigator.onLine),standalone=ref(false),installable=ref(mobileWebInstallAvailable());
const worker=ref('尚未检查'),notice=ref(''),checking=ref(false),addressInput=ref<HTMLInputElement>();
let epoch=0,stopInstall:()=>void=()=>{};
const mode=computed(()=>standalone.value?'已在独立窗口打开':installable.value?'可请求浏览器安装':'使用浏览器菜单安装');
function network(){online.value=navigator.onLine;}
function display(){standalone.value=window.matchMedia('(display-mode: standalone)').matches||(navigator as Navigator&{standalone?:boolean}).standalone===true;}
async function inspect(){
 const ticket=++epoch;checking.value=true;installable.value=mobileWebInstallAvailable();display();network();
 try {
  let value='当前浏览器不支持 Service Worker';
  if(!secure)value='当前连接不是安全上下文，使用普通网页版';
  else if('serviceWorker'in navigator&&address){const registration=await navigator.serviceWorker.getRegistration(address);value=registration?.active?'已启用在线访问与离线提示':registration?'正在准备，稍后可刷新状态':'尚未启用，普通网页版仍可使用';}
  if(ticket===epoch&&props.active)worker.value=value;
 }catch{if(ticket===epoch&&props.active)worker.value='浏览器未允许读取状态，普通网页版仍可使用';}
 finally{if(ticket===epoch)checking.value=false;}
}
async function copy(){
 if(!props.available||!address)return;
 try{await navigator.clipboard.writeText(address);notice.value='已复制访问地址。';}
 catch{addressInput.value?.focus();addressInput.value?.select();notice.value='浏览器未允许复制，已选中地址，可手动复制。';}
}
async function install(){
 if(!props.available||!props.active)return;
 try{const outcome=await requestMobileWebInstall();notice.value=outcome==='accepted'?'浏览器已接受安装请求；安装结果以浏览器为准。':outcome==='dismissed'?'已取消安装，可继续使用网页版。':'当前没有安装提示，请使用浏览器菜单。';}
 catch{notice.value='浏览器未完成安装，可继续使用网页版。';}
}
watch(()=>props.active,value=>{if(value)void inspect();else{epoch++;checking.value=false;}},{immediate:true});
onMounted(()=>{stopInstall=watchMobileWebInstall(()=>{installable.value=mobileWebInstallAvailable();display();});window.addEventListener('online',network);window.addEventListener('offline',network);window.addEventListener('focus',display);});
onBeforeUnmount(()=>{epoch++;stopInstall();window.removeEventListener('online',network);window.removeEventListener('offline',network);window.removeEventListener('focus',display);});
</script>
<template>
 <section class="mobile-web-workspace" aria-label="手机网页版">
  <el-alert v-if="!available" title="更新云栈移动端到 1.4.0 后使用手机网页版工作区。原有访问地址和原生交付包保留。" type="info" :closable="false" />
  <p>用手机浏览器打开面板，直接管理已授权的网站、文件、任务和应用。沿用面板登录、双重验证及原有权限。</p>
  <label for="mobile-web-address">当前网页访问地址</label>
  <input id="mobile-web-address" ref="addressInput" :value="address || ''" readonly autocomplete="off" spellcheck="false" />
  <div class="mobile-web-actions">
   <a v-if="available && address" :href="address" target="_blank" rel="noopener noreferrer" class="el-button el-button--primary">打开网页版</a>
   <el-button :disabled="!available || !address" @click="copy">复制访问地址</el-button>
   <el-button :disabled="!available || !secure || !installable || standalone" @click="install">安装到桌面</el-button>
   <el-button :loading="checking" @click="inspect">刷新浏览器状态</el-button>
  </div>
  <p v-if="notice" role="status">{{notice}}</p>
  <el-alert v-if="loopback" type="warning" :closable="false" title="这是本机地址：手机上的 127.0.0.1 或 localhost 指手机自身。请在手机上使用服务器可达的域名和端口。" />
  <el-alert v-if="!secure" type="warning" :closable="false" title="请使用有效证书的 HTTPS 地址。当前连接不能安装网页版，也不建议远程传输管理凭据。" />
  <el-alert v-if="!online" type="warning" :closable="false" title="浏览器报告网络离线。运维操作需要连接服务器；未确认的提交请先查询原任务，不要重复提交。" />
  <dl><dt>浏览器网络</dt><dd>{{online?'浏览器报告网络可用；服务器状态需单独核对':'离线'}}</dd><dt>打开方式</dt><dd>{{mode}}</dd><dt>网页后台</dt><dd>{{worker}}</dd></dl>
  <h4>添加到手机主屏幕</h4>
  <ol><li>在手机浏览器中打开服务器的 HTTPS 面板地址并登录。</li><li>支持安装提示时点击“安装到桌面”；iPhone Safari 可使用“分享 → 添加到主屏幕”，其他浏览器可使用“安装应用”或“添加到主屏幕”。</li><li>从新图标打开后，使用原面板账户和双重验证。退出登录会撤销当前服务器会话。</li></ol>
  <p class="mobile-web-note">需要联网，不缓存管理页面、接口响应或凭据，不提供离线运维或系统推送。地址不包含临时令牌、查询参数和会话。安装入口由当前浏览器决定；网页安装不等于 Android/iOS 原生客户端验收。</p>
 </section>
</template>
<style scoped>
.mobile-web-workspace{display:grid;gap:14px;min-width:0}.mobile-web-workspace p{margin:0;line-height:1.7}.mobile-web-workspace input{box-sizing:border-box;width:100%;min-width:0;padding:10px;border:1px solid var(--el-border-color);border-radius:6px;background:var(--el-fill-color-blank);color:var(--el-text-color-primary)}.mobile-web-actions{display:flex;flex-wrap:wrap;gap:10px}.mobile-web-actions .el-button{margin:0}.mobile-web-workspace dl{display:grid;grid-template-columns:auto minmax(0,1fr);gap:10px 18px;margin:0}.mobile-web-workspace dd{margin:0;overflow-wrap:anywhere}.mobile-web-workspace ol{padding-left:22px;margin:0;line-height:1.8}.mobile-web-note{color:var(--el-text-color-secondary);font-size:13px}
</style>
