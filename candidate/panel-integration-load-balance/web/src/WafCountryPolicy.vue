<script setup lang="ts">
import {computed,ref} from 'vue';
import {countryPolicyDraftProblem,countryDataAgeDays,type CountryPolicy,type CountryRule} from './wafCountryPolicy';
const props=defineProps<{modelValue?:CountryPolicy;sites:{id:string;domain:string}[];disabled:boolean}>();
const emit=defineEmits<{'update:modelValue':[CountryPolicy|undefined];'prepare-data':[]}>();
const selectedSite=ref('');
const problem=computed(()=>countryPolicyDraftProblem(props.modelValue));
const age=computed(()=>countryDataAgeDays(props.modelValue?.data.release||''));
function name(code:string){try{return new Intl.DisplayNames(['zh-CN'],{type:'region'}).of(code)||code;}catch{return code;}}
function edit(change:(value:CountryPolicy)=>void){if(props.disabled||!props.modelValue)return;const next=JSON.parse(JSON.stringify(props.modelValue)) as CountryPolicy;change(next);emit('update:modelValue',next);}
function ruleMode(site:string,mode:CountryRule['mode']){edit(p=>{const rule=site?p.sites.find(x=>x.site_id===site)!.rule:p.global;rule.mode=mode;if(mode==='off'||mode==='inherit'){rule.list='';rule.countries=[];}else if(!rule.list){rule.list='deny';}});}
function ruleList(site:string,list:CountryRule['list']){edit(p=>{(site?p.sites.find(x=>x.site_id===site)!.rule:p.global).list=list;});}
function ruleCountries(site:string,codes:string[]){edit(p=>{(site?p.sites.find(x=>x.site_id===site)!.rule:p.global).countries=[...new Set(codes)].sort();});}
function addSite(){const id=selectedSite.value;if(!props.sites.some(s=>s.id===id))return;edit(p=>{if(p.sites.length>=64||p.sites.some(s=>s.site_id===id))return;p.sites.push({site_id:id,rule:{mode:'inherit',list:'',countries:[]}});p.sites.sort((a,b)=>a.site_id.localeCompare(b.site_id));});selectedSite.value='';}
</script>
<template>
 <section class="country-policy" aria-label="国家与地区防护策略">
  <h3>国家 / 地区策略</h3>
  <p>先准备并完整验证数据，再选择防护动作。这里编辑草稿；使用工作台的“保存并验证”后，配置通过 Nginx 校验和生效检查才会提交。</p>
  <el-button :disabled="disabled" @click="emit('prepare-data')">准备或选择数据集</el-button>
  <el-empty v-if="!modelValue" description="尚未选择地域数据；现有防护不受影响"/>
  <template v-else>
   <el-descriptions :column="1" border>
    <el-descriptions-item label="数据版本">{{modelValue.data.release}} r{{modelValue.data.revision}} · {{modelValue.data.countries.map(name).join('、')}}</el-descriptions-item>
    <el-descriptions-item label="原签名摘要"><code>{{modelValue.data.data_manifest_sha256}}</code></el-descriptions-item>
    <el-descriptions-item label="数据集"><code>{{modelValue.data.dataset}}</code></el-descriptions-item>
   </el-descriptions>
   <p>数据来源：<a href="https://db-ip.com/" target="_blank" rel="noopener noreferrer">IP Geolocation by DB-IP Lite</a> · <a href="https://creativecommons.org/licenses/by/4.0/" target="_blank" rel="noopener noreferrer">CC BY 4.0</a>。月度近似网络归属，有覆盖和精度限制。名单外、公网未覆盖和内网地址统一为“未匹配所选地区”；允许名单会拒绝这些请求，拒绝名单会放行这些请求。</p>
   <el-alert v-if="age!==undefined&&age>90" title="这份数据距发布月份已超过90天，请先准备更新的数据。现有运行策略不会因日期变化被自动停用。" type="warning" :closable="false"/>
   <el-form label-position="top" :disabled="disabled">
    <el-form-item label="地域防护总开关"><el-switch :model-value="modelValue.enabled" @update:model-value="(v:boolean)=>edit(p=>{p.enabled=v;})"/><span class="hint">停用会移除生效的地域数据引用，保留规则选择；再次启用仍需保存并验证。</span></el-form-item>
    <h4>全局默认规则</h4>
    <div class="rule-row">
     <el-select :model-value="modelValue.global.mode" aria-label="全局地域动作" @update:model-value="(v:CountryRule['mode'])=>ruleMode('',v)"><el-option label="停用" value="off"/><el-option label="仅观察" value="observe"/><el-option label="阻断" value="block"/></el-select>
     <el-select v-if="modelValue.global.mode!=='off'" :model-value="modelValue.global.list" aria-label="全局地域名单类型" @update:model-value="(v:CountryRule['list'])=>ruleList('',v)"><el-option label="拒绝所选地区" value="deny"/><el-option label="仅允许所选地区" value="allow"/></el-select>
     <el-select v-if="modelValue.global.mode!=='off'" :model-value="modelValue.global.countries" multiple filterable aria-label="全局地区选择" @update:model-value="(v:string[])=>ruleCountries('',v)"><el-option v-for="code in modelValue.data.countries" :key="code" :value="code" :label="name(code)+' · '+code"/></el-select>
    </div>
    <h4>站点独立规则</h4><div class="rule-row"><el-select v-model="selectedSite" filterable placeholder="选择受管网站" aria-label="新增地域策略站点"><el-option v-for="site in sites.filter(s=>!modelValue!.sites.some(x=>x.site_id===s.id))" :key="site.id" :value="site.id" :label="site.domain"/></el-select><el-button :disabled="!selectedSite||modelValue.sites.length>=64" @click="addSite">添加站点规则</el-button></div>
    <el-table :data="modelValue.sites" empty-text="所有受管站点使用全局默认规则">
     <el-table-column label="网站" min-width="150"><template #default="{row}">{{sites.find(s=>s.id===row.site_id)?.domain||row.site_id}}</template></el-table-column>
     <el-table-column label="动作" min-width="130"><template #default="{row}"><el-select :model-value="row.rule.mode" @update:model-value="(v:CountryRule['mode'])=>ruleMode(row.site_id,v)"><el-option label="继承全局" value="inherit"/><el-option label="停用" value="off"/><el-option label="仅观察" value="observe"/><el-option label="阻断" value="block"/></el-select></template></el-table-column>
     <el-table-column label="名单" min-width="170"><template #default="{row}"><el-select v-if="!['off','inherit'].includes(row.rule.mode)" :model-value="row.rule.list" @update:model-value="(v:CountryRule['list'])=>ruleList(row.site_id,v)"><el-option label="拒绝所选地区" value="deny"/><el-option label="仅允许所选地区" value="allow"/></el-select><span v-else>—</span></template></el-table-column>
     <el-table-column label="地区" min-width="240"><template #default="{row}"><el-select v-if="!['off','inherit'].includes(row.rule.mode)" :model-value="row.rule.countries" multiple filterable @update:model-value="(v:string[])=>ruleCountries(row.site_id,v)"><el-option v-for="code in modelValue.data.countries" :key="code" :value="code" :label="name(code)+' · '+code"/></el-select></template></el-table-column>
     <el-table-column label="操作" width="80"><template #default="{row}"><el-button text type="danger" @click="edit(p=>{p.sites=p.sites.filter(x=>x.site_id!==row.site_id);})">删除</el-button></template></el-table-column>
    </el-table>
   </el-form>
   <el-alert v-if="problem" :title="problem" type="warning" :closable="false"/>
   <p>原有全局/站点停用与观察模式、站点退出 WAF、健康探针和管理员白名单继续优先。地域规则不能将这些请求提升为阻断。保存失败恢复原配置，准备新数据不会切换正在运行的规则。</p>
   <el-button type="warning" plain :disabled="disabled" @click="emit('update:modelValue',undefined)">从草稿移除地域策略引用</el-button>
  </template>
 </section>
</template>
<style scoped>
.country-policy p{line-height:1.7;color:var(--el-text-color-secondary)}.country-policy code{overflow-wrap:anywhere;word-break:break-all}.rule-row{display:flex;flex-wrap:wrap;gap:12px;margin:12px 0}.rule-row .el-select{min-width:180px;flex:1}.hint{margin-left:12px;color:var(--el-text-color-secondary)}
</style>
