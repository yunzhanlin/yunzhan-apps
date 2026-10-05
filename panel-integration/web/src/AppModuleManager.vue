<script setup lang="ts">
import { ref } from "vue";
import { ElMessage } from "element-plus";
type API=<T>(path:string,method?:string,body?:unknown,idempotencyKey?:string)=>Promise<T>;
interface Field { key:string; label:string; kind:string }
interface Definition { id:string; name:string; actions:string[]; fields:Field[]|null }
const props=defineProps<{api:API; onJob:(id:string)=>Promise<void>}>();
const visible=ref(false),busy=ref(false),error=ref("");
const definition=ref<Definition>(),installed=ref(false),healthy=ref(false),report=ref<unknown>();
const form=ref<Record<string,any>>({}),sites=ref<{id:string;name:string;domain:string}[]>([]);
const labels:Record<string,string>={run:"刷新报告",baseline:"建立基线",check:"检查变更",restore:"恢复所选文件",preview:"同步预览",sync:"开始同步",save:"保存入口",probe:"健康检测",remove:"移除入口",terminate:"终止受管进程",create:"创建",update:"更新",revoke:"撤销会话",delete:"删除",add:"添加主机","issue-token":"生成只读令牌","revoke-token":"撤销只读令牌",mount:"挂载",unmount:"卸载挂载",start:"启动",stop:"停止",restart:"重启",logs:"读取日志"};
async function show(id:string){busy.value=true;error.value="";visible.value=true;report.value=undefined;try{const page=await props.api<{definition:Definition;status:{installed:boolean;healthy:boolean};report:unknown}>(`/app-modules/${id}`);definition.value=page.definition;installed.value=page.status.installed;healthy.value=page.status.healthy;report.value=page.report;sites.value=await props.api<typeof sites.value>("/sites");form.value={role:"viewer",read_only:true,auto_restore:false,nodes:'[{"address":"127.0.0.1:21001","weight":1,"backup":false},{"address":"127.0.0.1:21002","weight":1,"backup":false}]',site_ids:"[]",excludes:"[]"};}catch(e){error.value=e instanceof Error?e.message:String(e)}finally{busy.value=false}}
async function execute(action:string){if(!definition.value||busy.value)return;busy.value=true;error.value="";try{const body:Record<string,unknown>={};for(const f of definition.value.fields||[]){const v=form.value[f.key];if(v!==undefined&&v!=="")body[f.key]=f.kind==="json"?JSON.parse(v):v;}report.value=await props.api(`/app-modules/${definition.value.id}/${action}`,"POST",body);if(action!=="run"&&action!=="logs"&&action!=="probe"&&action!=="check"&&action!=="preview")ElMessage.success("操作已执行并记录审计");for(const f of definition.value.fields||[])if(f.kind==="password")form.value[f.key]="";}catch(e){error.value=e instanceof Error?e.message:String(e)}finally{busy.value=false}}
async function uninstall(){if(!definition.value||busy.value)return;busy.value=true;try{const out=await props.api<{job_id:string}>(`/software/${definition.value.id}/uninstall`,"POST",{settings:{}});visible.value=false;await props.onJob(out.job_id)}catch(e){error.value=e instanceof Error?e.message:String(e)}finally{busy.value=false}}
defineExpose({show});
</script>
<template>
 <el-dialog v-model="visible" :title="definition?.name||'应用管理'" width="850px" class="app-module-dialog" destroy-on-close>
  <div v-loading="busy">
   <el-alert v-if="error" :title="error" type="error" :closable="false"/>
   <template v-if="definition">
    <p><el-tag :type="healthy?'success':'warning'">{{installed?(healthy?'已安装 · 依赖正常':'已安装 · 需要核对'):'未安装'}}</el-tag> <span>配置和报告保存在服务器，重启后保留。</span></p>
    <el-form label-position="top" class="module-fields">
     <el-form-item v-for="field in definition.fields||[]" :key="field.key" :label="field.label">
      <el-select v-if="field.kind==='site'" v-model="form[field.key]" placeholder="选择网站"><el-option v-for="site in sites" :key="site.id" :value="site.id" :label="`${site.name} · ${site.domain}`"/></el-select>
      <el-switch v-else-if="field.kind==='boolean'" v-model="form[field.key]"/>
      <el-input-number v-else-if="field.kind==='number'" v-model="form[field.key]" :min="0" :max="field.key==='start_time'?Number.MAX_SAFE_INTEGER:field.key==='pid'?4194304:65535"/>
      <el-select v-else-if="field.key==='role'" v-model="form.role"><el-option value="viewer" label="viewer · 只读"/><el-option value="operator" label="operator · 指定网站操作"/><el-option value="admin" label="admin · 管理员"/></el-select>
      <el-input v-else v-model="form[field.key]" :type="field.kind==='password'?'password':field.kind==='json'?'textarea':'text'" :show-password="field.kind==='password'" :rows="field.kind==='json'?4:1" autocomplete="off"/>
     </el-form-item>
    </el-form>
    <div class="module-actions"><el-button v-for="action in definition.actions" :key="action" :disabled="!installed||busy" :type="['delete','terminate','remove','unmount'].includes(action)?'danger':'primary'" @click="execute(action)">{{labels[action]||action}}</el-button></div>
    <section aria-label="执行报告"><h3>实际执行结果</h3><p v-if="report===undefined||report===null">选择参数并执行操作，报告将显示在这里。</p><pre v-else class="module-report">{{JSON.stringify(report,null,2)}}</pre></section>
   </template>
  </div>
  <template #footer><el-button v-if="installed" type="danger" plain :disabled="busy" @click="uninstall">卸载模块 · 保留报告和备份</el-button><el-button @click="visible=false">关闭</el-button></template>
 </el-dialog>
</template>
<style scoped>
.module-fields{display:grid;grid-template-columns:1fr 1fr;gap:0 20px}.module-fields .el-select{width:100%}.module-actions{display:flex;flex-wrap:wrap;gap:10px}.module-actions .el-button{margin-left:0}.module-report{max-height:400px;overflow:auto;background:#f4f7fa;padding:16px;border-radius:8px;white-space:pre-wrap;overflow-wrap:anywhere;font-size:12px}h3{font-size:15px}p{color:#657181}
@media(max-width:600px){.module-fields{grid-template-columns:1fr}}
</style>
<style>.app-module-dialog{max-width:calc(100vw - 24px)!important}.app-module-dialog .el-dialog__body{overflow-x:hidden}</style>
