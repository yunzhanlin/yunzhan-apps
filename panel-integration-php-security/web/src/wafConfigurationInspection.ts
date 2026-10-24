export interface WafConfigurationDifference {
 scope:string;site_id:string;actual_exists:boolean;expected_exists:boolean;actual_sha256:string;expected_sha256:string;actual_mode:number;expected_mode:number;actual_bytes:number;expected_bytes:number;
}
export interface WafConfigurationInspection {
 format:1;read_only:true;installed_version:string;policy_revision:string;semantic_record_sha256:string;filesystem_matches:boolean;enforcement_verified:false;differences:WafConfigurationDifference[];
}
type API=<T>(path:string,method?:string,body?:unknown,key?:string)=>Promise<T>;
const top=["format","read_only","installed_version","policy_revision","semantic_record_sha256","filesystem_matches","enforcement_verified","differences"],rowKeys=["scope","site_id","actual_exists","expected_exists","actual_sha256","expected_sha256","actual_mode","expected_mode","actual_bytes","expected_bytes"],versions=["2.0.1","2.1.0","2.1.1","2.2.0","2.3.0","2.4.0","2.5.0","2.5.1","2.5.2"],sha=(s:unknown):s is string=>typeof s==="string"&&/^[a-f0-9]{64}$/.test(s),emptySHA="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
function object(v:unknown,keys:string[]):v is Record<string,unknown>{return !!v&&typeof v==="object"&&!Array.isArray(v)&&Object.keys(v).length===keys.length&&keys.every(k=>Object.hasOwn(v,k));}
export function decodeWafConfigurationInspection(value:unknown):WafConfigurationInspection{
 const bad=()=>new Error("已安装 WAF 配置差异无法完整核对；未返回部分成功结果");
 if(!object(value,top)||value.format!==1||value.read_only!==true||value.enforcement_verified!==false||typeof value.installed_version!=="string"||!versions.includes(value.installed_version)||!sha(value.semantic_record_sha256)||typeof value.policy_revision!=="string"||!/^(0|[1-9][0-9]{0,18})$/.test(value.policy_revision)||BigInt(value.policy_revision)>9223372036854775807n||!Array.isArray(value.differences)||value.differences.length>4110||typeof value.filesystem_matches!=="boolean"||value.filesystem_matches!==(value.differences.length===0))throw bad();
 let bytes=0;const seen=new Set<string>();
 for(const row of value.differences){
  if(!object(row,rowKeys)||typeof row.scope!=="string"||!["nginx-main","http-rules","server-rules","native-log","manifest","site","body-site"].includes(row.scope)||typeof row.site_id!=="string"||(["site","body-site"].includes(row.scope)?!/^[a-f0-9]{32}$/.test(row.site_id):row.site_id!=="")||typeof row.actual_exists!=="boolean"||typeof row.expected_exists!=="boolean"||!sha(row.actual_sha256)||!sha(row.expected_sha256))throw bad();
  for(const k of ["actual_mode","expected_mode","actual_bytes","expected_bytes"]){const n=row[k];if(typeof n!=="number"||!Number.isSafeInteger(n)||n<0||n>(k.endsWith("mode")?511:8*1048576))throw bad();}
  if(!row.actual_exists&&(row.actual_bytes!==0||row.actual_mode!==0||row.actual_sha256!==emptySHA)||!row.expected_exists&&(row.expected_bytes!==0||row.expected_mode!==0||row.expected_sha256!==emptySHA)||row.actual_exists===row.expected_exists&&row.actual_mode===row.expected_mode&&row.actual_sha256===row.expected_sha256)throw bad();
  const key=row.scope+"/"+row.site_id;if(seen.has(key))throw bad();seen.add(key);bytes+=(row.actual_bytes as number)+(row.expected_bytes as number);if(bytes>8*1048576)throw bad();
 }
 return value as unknown as WafConfigurationInspection;
}
export async function readWafConfigurationInspection(api:API,current:()=>boolean,installedVersion:string):Promise<WafConfigurationInspection>{
 if(!current())throw new Error("原配置核对已失效，未发送请求");
 const raw=await api<unknown>("/software/nginx-waf/config-inspection","GET");
 if(!current())throw new Error("旧配置核对回复已失效，未显示为当前结果");
 const out=decodeWafConfigurationInspection(raw);if(out.installed_version!==installedVersion)throw new Error("已安装 WAF 版本已变化，请刷新原状态后再核对");
 return out;
}
export function wafDifferenceLabel(row:WafConfigurationDifference):string {
 const label:Record<string,string>={"nginx-main":"Nginx 主配置","http-rules":"HTTP 层规则","server-rules":"Server 层规则","native-log":"请求体日志配置",manifest:"原安装清单",site:"受管站点配置","body-site":"受管站点请求体策略"};
 return (label[row.scope]||"未知资源")+(row.site_id?" · "+row.site_id:"");
}

