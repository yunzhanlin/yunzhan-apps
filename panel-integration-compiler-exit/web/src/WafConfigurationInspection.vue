<script setup lang="ts">
import {onUnmounted,ref,watch}from"vue";
import{readWafConfigurationInspection,wafDifferenceLabel,type WafConfigurationInspection}from"./wafConfigurationInspection";
type API=<T>(path:string,method?:string,body?:unknown,key?:string)=>Promise<T>;
const props=defineProps<{api:API;version:string}>();
const result=ref<WafConfigurationInspection>(),busy=ref(false),error=ref("");
let generation=0,disposed=false;
async function inspect(){
 if(disposed||busy.value)return;
 const token=++generation,current=()=>!disposed&&token===generation,version=props.version;
 busy.value=true;result.value=undefined;error.value="";
 try{const next=await readWafConfigurationInspection(props.api,current,version);if(current()&&version===props.version)result.value=next;}
 catch(e){if(current())error.value=e instanceof Error?e.message:"已安装 WAF 配置差异尚未核实";}
 finally{if(current())busy.value=false;}
}
watch(()=>props.version,()=>{++generation;result.value=undefined;error.value="";busy.value=false;});
onUnmounted(()=>{disposed=true;++generation;});
const mode=(exists:boolean,value:number)=>exists?"0"+value.toString(8):"不存在";
</script>
<template>
 <section class="waf-inspection">
  <div class="inspection-heading"><div><h4>已安装配置差异</h4><p>按原安装版本渲染并核对实际文件；只读查看，不覆盖配置、不重载或迁移。</p></div><el-button :loading="busy" @click="inspect">核对已安装配置</el-button></div>
  <el-alert v-if="error" :title="error" type="error" :closable="false"/>
  <template v-if="result">
   <el-alert :type="result.filesystem_matches?'info':'warning'" :closable="false" :title="result.filesystem_matches?'原版本文件与清单一致；本次未检查 Nginx 语法或实际加载，不能据此认定防护生效。':'原版本配置存在差异。保留原文件并核对外部修改；此处没有自动修复、签名升级或覆盖操作。'"/>
   <p>原版本 {{result.installed_version}} · 原配置修订 {{result.policy_revision}} · {{result.differences.length}} 项差异</p>
   <el-table v-if="result.differences.length" :data="result.differences" max-height="300" class="inspection-table">
    <el-table-column label="资源" min-width="180"><template #default="{row}">{{wafDifferenceLabel(row)}}</template></el-table-column>
    <el-table-column label="实际文件" min-width="220"><template #default="{row}"><small>{{mode(row.actual_exists,row.actual_mode)}} · {{row.actual_bytes}} 字节</small><code>{{row.actual_sha256}}</code></template></el-table-column>
    <el-table-column label="原清单对应文件" min-width="220"><template #default="{row}"><small>{{mode(row.expected_exists,row.expected_mode)}} · {{row.expected_bytes}} 字节</small><code>{{row.expected_sha256}}</code></template></el-table-column>
   </el-table>
   <details><summary>原清单语义指纹（不是磁盘原文哈希或更新凭据）</summary><code>{{result.semantic_record_sha256}}</code></details>
  </template>
 </section>
</template>
<style scoped>
.waf-inspection{padding:14px;border:1px solid #dce5ed;border-radius:9px;margin:12px 0;background:#f8fafb}.inspection-heading{display:flex;gap:16px;align-items:center;justify-content:space-between}.inspection-heading h4{margin:0 0 5px}.inspection-heading p,.waf-inspection>p{font-size:12px;color:#5d7084;margin:5px 0 10px}.waf-inspection code{display:block;font-size:11px;word-break:break-all;white-space:normal}.waf-inspection details{font-size:12px;margin-top:10px}.waf-inspection .el-alert{margin-top:8px}@media(max-width:600px){.inspection-heading{align-items:flex-start;flex-direction:column;gap:6px}.inspection-table{max-width:100%;overflow:auto}}
</style>

