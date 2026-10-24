import {wafCommittedConfiguration,type WafApplyKind} from "./wafApplyTask.ts";
export type WafApplyEngine="nginx-waf"|"apache-waf";
export interface WafOriginalSummary {id:string;target_id:WafApplyEngine;kind:WafApplyKind;state:string;created_at:string;request_sha256:string;signed_install_binding:boolean}
export interface WafOriginalPage {entries:WafOriginalSummary[];next_cursor:string;read_only:true}
export interface WafOriginalRequest {request:WafOriginalSummary;error:string;settings:Record<string,unknown>;read_only:true}
type Read=(path:string)=>Promise<unknown>;
const object=(v:unknown):v is Record<string,unknown>=>!!v&&typeof v==="object"&&!Array.isArray(v)&&[Object.prototype,null].includes(Object.getPrototypeOf(v));
const keys=(v:Record<string,unknown>,fields:string[])=>Object.keys(v).sort().join(",")===[...fields].sort().join(",");
const id=(v:unknown):v is string=>typeof v==="string"&&/^[a-f0-9]{32}$/.test(v);
const digest=(v:unknown):v is string=>typeof v==="string"&&/^[a-f0-9]{64}$/.test(v);
const engine=(v:string)=>["nginx-waf","apache-waf"].includes(v);
const stamp=(v:unknown):v is string=>typeof v==="string"&&/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/.test(v)&&Number.isFinite(Date.parse(v))&&new Date(v).toISOString().replace(".000Z","Z")===v;

export function decodeWafOriginalSummary(app:WafApplyEngine,value:unknown):WafOriginalSummary {
  if(!engine(app)||!object(value)||!keys(value,["id","target_id","kind","state","created_at","request_sha256","signed_install_binding"])||!id(value.id)||value.target_id!==app||!["software_install","software_configure"].includes(String(value.kind))||typeof value.kind!=="string"||typeof value.state!=="string"||!["queued","running","succeeded","failed","needs_attention","cancelled"].includes(value.state)||!stamp(value.created_at)||!digest(value.request_sha256)||typeof value.signed_install_binding!=="boolean"||value.kind==="software_configure"&&value.signed_install_binding)throw new Error("原请求目录身份不可完整核对；未恢复任务或宣称安装通过。");
  return value as unknown as WafOriginalSummary;
}
export function decodeWafOriginalPage(app:WafApplyEngine,value:unknown,cursor=""):WafOriginalPage {
  if(cursor!==""&&!id(cursor)||!object(value)||!keys(value,["entries","next_cursor","read_only"])||value.read_only!==true||!Array.isArray(value.entries)||value.entries.length>20||typeof value.next_cursor!=="string")throw new Error("当前账户的原请求目录不可完整核对；未返回部分目录或空记录结论。");
  let previous=cursor;
  for(const item of value.entries){const row=decodeWafOriginalSummary(app,item);if(row.id<=previous)throw new Error("原请求目录重复或游标倒退。");previous=row.id;}
  if(value.next_cursor!==""&&(value.entries.length!==20||value.next_cursor!==previous))throw new Error("原请求目录下一页身份不可核对。");
  return value as unknown as WafOriginalPage;
}
export function decodeWafOriginalRequest(app:WafApplyEngine,value:unknown,selected:WafOriginalSummary):WafOriginalRequest {
  const chosen=decodeWafOriginalSummary(app,selected);
  if(!object(value)||!keys(value,["request","error","settings","read_only"])||value.read_only!==true||typeof value.error!=="string"||new TextEncoder().encode(value.error).length>32768)throw new Error("原任务配置回复不可核对；未替换当前草稿或重新提交。");
  const original=decodeWafOriginalSummary(app,value.request);
  // The job may finish between the directory and detail reads; state is not
  // immutable identity, nor is either state a package/activation receipt.
  for(const field of ["id","target_id","kind","created_at","request_sha256","signed_install_binding"] as const)if(original[field]!==chosen[field])throw new Error("原请求详情与所选身份不一致；未采用另一个请求。");
  const settings=value.settings;
  const known=["profile","rate_per_second","policy","body","trusted_proxy","body_log_rotation","body_log_retention"];
  if(!object(settings)||Object.keys(settings).some(k=>!known.includes(k))||!["balanced","strict"].includes(String(settings.profile))||typeof settings.rate_per_second!=="number"||!Number.isInteger(settings.rate_per_second)||settings.rate_per_second<5||settings.rate_per_second>200||!object(settings.policy)||!keys(settings.policy,["schema_version","revision","mode","cc_enabled","burst","groups","lists","rules","sites","cc_rules"])||settings.policy.schema_version!==2||typeof settings.policy.revision!=="number"||!Number.isSafeInteger(settings.policy.revision)||settings.policy.revision<0||settings.policy.revision>=Number.MAX_SAFE_INTEGER||!object(settings.policy.groups)||!object(settings.policy.lists)||!Array.isArray(settings.policy.rules)||!Array.isArray(settings.policy.sites)||!Array.isArray(settings.policy.cc_rules)||!wafCommittedConfiguration(settings,{...settings,policy:{...settings.policy,revision:settings.policy.revision+1}}))throw new Error("原任务配置超出规范 JSON/128 KiB 边界；未采用不完整配置。语义验证及原始摘要由账号绑定的服务端核对，此读取不触发预览、安装或配置。");
  return value as unknown as WafOriginalRequest;
}
export async function readWafOriginalPage(read:Read,current:()=>boolean,app:WafApplyEngine,cursor=""):Promise<WafOriginalPage>{
  if(!engine(app)||cursor!==""&&!id(cursor)||!current())throw new Error("原请求工作区已关闭或游标无效。");
  const value=await read(`/software/${app}/requests${cursor?'?cursor='+cursor:''}`);
  if(!current())throw new Error("原请求工作区已关闭，未发布迟到目录。");
  return decodeWafOriginalPage(app,value,cursor);
}
export async function readWafOriginalRequest(read:Read,current:()=>boolean,app:WafApplyEngine,selected:WafOriginalSummary):Promise<WafOriginalRequest>{
  const row=decodeWafOriginalSummary(app,selected);
  if(!current())throw new Error("原请求工作区已关闭，未读取详情。");
  const value=await read(`/software/${app}/requests/${row.id}`);
  if(!current())throw new Error("原请求工作区已关闭，未采用迟到任务身份。");
  return decodeWafOriginalRequest(app,value,row);
}
export function wafRecoveredApplyTicket(app:WafApplyEngine,original:WafOriginalRequest){
  const verified=decodeWafOriginalRequest(app,original,original.request);
  const settings=JSON.parse(JSON.stringify(verified.settings)) as Record<string,unknown>;
  const freeze=(v:unknown)=>{if(v&&typeof v==="object"){Object.values(v).forEach(freeze);Object.freeze(v);}};freeze(settings);
  // An intentionally unusable queue key: this restored, already-known job
  // must only be rechecked by GET, never reconstructed as a fresh POST.
  return Object.freeze({kind:verified.request.kind,key:"",job:verified.request.id,settings});
}
