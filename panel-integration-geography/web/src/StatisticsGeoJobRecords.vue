<script setup lang="ts">
import {onMounted,ref} from 'vue';
type API=<T>(path:string,method?:string,body?:unknown,key?:string)=>Promise<T>;
type Row={job_id:string;state:'pending'|'succeeded'|'failed';sha256:string;bytes:number;archived:boolean};
type Page={inventory:{entries:Row[];active_max:number;archive_max:number;read_only:boolean};committed:string[]};
const props=defineProps<{api:API;onJob:(id:string)=>Promise<void>}>();
const page=ref<Page>(),busy=ref(false),error=ref(''),message=ref(''),selected=ref<Row>(),confirm=ref(''),pending=ref<Row>();
const id=(v:unknown):v is string=>typeof v==='string'&&/^[a-f0-9]{32}$/.test(v);
const sha=(v:unknown):v is string=>typeof v==='string'&&/^[a-f0-9]{64}$/.test(v);
function validRow(v:Row){return v&&id(v.job_id)&&Number.isSafeInteger(v.bytes)&&v.bytes>0&&v.bytes<=3*1048576+40*1024&&typeof v.archived==='boolean'&&(v.state==='pending'&&!v.archived&&v.sha256===''||['succeeded','failed'].includes(v.state)&&sha(v.sha256));}
async function refresh(){busy.value=true;error.value='';try{
  const out=await props.api<Page>('/software/website-statistics-v2/geodata-job-records');const inv=out?.inventory;
  if(!inv||inv.active_max!==128||inv.archive_max!==512||inv.read_only!==true||!Array.isArray(inv.entries)||inv.entries.length>640||!Array.isArray(out.committed)||out.committed.length>512)throw new Error('地域任务完整库存格式不可核对');
  let previous='';for(const row of inv.entries){if(!validRow(row)||row.job_id<=previous)throw new Error('原任务库存含损坏或重复记录');previous=row.job_id;}
  if(inv.entries.filter(r=>r.archived).length>512||inv.entries.filter(r=>!r.archived).length>128||new Set(out.committed).size!==out.committed.length||out.committed.some(key=>!id(key)||!inv.entries.some(row=>row.job_id===key&&row.archived)))throw new Error('原归档提交标记与库存不同');
  page.value=out;
}catch(e){page.value=undefined;error.value=(e as Error).message;}finally{busy.value=false;}}
function choose(row:Row){if(pending.value&&pending.value.job_id!==row.job_id){error.value='上次交接未核对，请先使用原任务与摘要核对';return;}selected.value={...row};confirm.value='';message.value='';}
async function archive(){const row=pending.value??selected.value;if(!row||busy.value)return;
  if(!validRow(row)||row.state==='pending'||!sha(row.sha256)||!pending.value&&confirm.value!==`ARCHIVE GEODATA JOB ${row.job_id}`){error.value='请核对原任务的终态、摘要并填写完整确认';return;}
  pending.value??={...row};busy.value=true;error.value='';message.value='';
  try{const result=await props.api<{record:Row;replayed:boolean}>('/software/website-statistics-v2/geodata-job-records/archive','POST',{job_id:row.job_id,expected_sha256:row.sha256,confirm:`ARCHIVE GEODATA JOB ${row.job_id}`});
    if(!result||typeof result.replayed!=='boolean'||!validRow(result.record)||!result.record.archived||result.record.job_id!==row.job_id||result.record.sha256!==row.sha256||result.record.state!==row.state||result.record.bytes!==row.bytes)throw new Error('原归档回执不能核对；保留原标识与摘要');
    pending.value=undefined;selected.value=undefined;confirm.value='';message.value='原终态证据已归档并完成审计；所有字节和原任务保留，没有切换地理库。';
  }catch(e){error.value=(e as Error).message;}finally{busy.value=false;}
  if(!pending.value)await refresh();
}
onMounted(refresh);
</script>
<template>
  <section class="geo-records" aria-label="地域任务证据归档">
    <h4>后台任务容量与原始证据</h4>
    <p>活动区最多 128 份，私有归档区最多 512 份。只移动已核对成功/失败终态的全部原文件；不删除记录、不重跑任务、不切换地理库，也不改网站。待处理、运行中、证据不完整或摘要已变化的任务禁止归档。归档区满后仍需后续导出与受控清理能力，不会自动删除旧证据。</p>
    <el-alert v-if="error" :title="error" type="error" :closable="false"/><el-alert v-if="message" :title="message" type="success" :closable="false"/>
    <el-button :loading="busy" @click="refresh">核对完整任务库存</el-button>
    <el-button v-if="pending" type="warning" :disabled="busy" @click="archive">核对原任务归档交接</el-button>
    <template v-if="page">
      <p>执行器活动区：{{page.inventory.entries.filter(r=>!r.archived).length}} / 128；私有归档：{{page.inventory.entries.filter(r=>r.archived).length}} / 512；面板已核对归档：{{page.committed.length}}。只有两侧终态和提交均已核对，才释放面板活动容量。</p>
      <el-table :data="page.inventory.entries" empty-text="没有 Root 地域任务证据" max-height="400">
        <el-table-column prop="job_id" label="原任务 ID" min-width="210"/><el-table-column label="原终态" width="110"><template #default="{row}">{{({pending:'待核对',succeeded:'成功',failed:'失败'} as Record<string,string>)[row.state]}}</template></el-table-column>
        <el-table-column label="位置" width="155"><template #default="{row}">{{row.archived?(page.committed.includes(row.job_id)?'已归档并核对':'文件已归档 · 面板待核对'):'活动区'}}</template></el-table-column>
        <el-table-column label="完整证据" min-width="200"><template #default="{row}"><span>{{(row.bytes/1024).toFixed(1)}} KiB</span><small>{{row.sha256||'尚无完整终态摘要'}}</small></template></el-table-column>
        <el-table-column label="操作" width="195"><template #default="{row}"><el-button text @click="onJob(row.job_id)">原任务</el-button><el-button text :disabled="busy||row.state==='pending'||page.committed.includes(row.job_id)||!!pending" @click="choose(row)">{{row.archived?'完成交接核对':'归档证据'}}</el-button></template></el-table-column>
      </el-table>
    </template>
    <div v-if="selected" class="geo-confirm">
      <p>仅归档原任务 {{selected.job_id}}，SHA-256 {{selected.sha256}}。完整输入 <code>ARCHIVE GEODATA JOB {{selected.job_id}}</code>：</p>
      <el-input v-model="confirm" aria-label="确认归档原地域任务" :disabled="busy||!!pending" maxlength="64"/>
      <el-button :disabled="busy||!!pending||confirm!==`ARCHIVE GEODATA JOB ${selected.job_id}`" @click="archive">保留全部原证据并归档</el-button>
      <el-button :disabled="busy||!!pending" @click="selected=undefined">取消选择</el-button>
    </div>
  </section>
</template>
<style scoped>
.geo-records{margin-top:20px;min-width:0}.geo-records p{line-height:1.7;color:var(--el-text-color-secondary);overflow-wrap:anywhere}.geo-records small{display:block;font-size:11px;overflow-wrap:anywhere}.geo-records .el-alert{margin:12px 0}.geo-confirm{margin:16px 0;padding:12px;border:1px solid var(--el-border-color);border-radius:8px}.geo-confirm .el-input{margin-bottom:10px}
</style>
