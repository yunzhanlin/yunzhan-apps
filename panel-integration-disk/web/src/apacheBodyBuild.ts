// Build readiness is deliberately not a website activation or install receipt.
export interface ApacheBodyBuild {
  job_id:string; state:string; error?:string; build_only:true;
  architecture?:string; engine_version?:string; yajl_version?:string;
  crs_version?:string; apache_version?:string;
  integrity_verified?:boolean; module_abi_validated?:boolean;
  elf_hardening_validated?:boolean; compiler_groups_collected?:boolean;
  historical_integrity_verified?:boolean;
  steps:{time:string;message:string}[];
}
export function apacheBodyBuildRow(value:unknown, expectedID?:string):value is ApacheBodyBuild {
  const v=value as ApacheBodyBuild;
  if(!v || typeof v.job_id!=="string" || !/^[a-f0-9]{32}$/.test(v.job_id) || expectedID && v.job_id!==expectedID || v.build_only!==true
    || !["queued","running","ready","failed","needs_attention","retained_unsupported"].includes(v.state)
    || v.error!==undefined && (typeof v.error!=="string" || v.error.length>4096 || v.error.includes("\0"))
    || !Array.isArray(v.steps) || v.steps.length>48 || v.steps.some(step=>!step || typeof step.time!=="string" || !Number.isFinite(Date.parse(step.time))
      || typeof step.message!=="string" || !step.message || step.message.length>512 || step.message.includes("\0"))) return false;
  if(v.state==="failed" && !v.error)return false;
  if(v.state==="retained_unsupported")return !!v.error && v.historical_integrity_verified===true
    && v.integrity_verified===false && v.module_abi_validated===false && v.elf_hardening_validated===false && v.compiler_groups_collected===false
    && ["amd64","arm64"].includes(v.architecture || "") && v.apache_version==="2.4.68"
    && v.engine_version==="2.9.15-yz4" && v.yajl_version==="2.1.0-debian5-yz1" && v.crs_version==="4.30.0";
  if(v.state!=="ready")return true;
  return !v.error && v.historical_integrity_verified!==true && v.integrity_verified===true && v.module_abi_validated===true
    && v.elf_hardening_validated===true && v.compiler_groups_collected===true
    && ["amd64","arm64"].includes(v.architecture || "") && v.apache_version==="2.4.68"
    && v.engine_version==="2.9.15-yz5" && v.yajl_version==="2.1.0-debian5-yz1" && v.crs_version==="4.30.0";
}
export function apacheBodyBuildInventory(value:unknown):value is {entries:ApacheBodyBuild[]} {
  const v=value as {entries:unknown[];build_only:boolean;activation_requires_explicit_site_policy:boolean};
  return !!v && v.build_only===true && v.activation_requires_explicit_site_policy===true
    && Array.isArray(v.entries) && v.entries.length<=192 && v.entries.every(row=>apacheBodyBuildRow(row))
    && new Set(v.entries.map(row=>(row as ApacheBodyBuild).job_id)).size===v.entries.length;
}
export function apacheBodyQueueReply(value:unknown):value is {job_id:string} {
  const v=value as {job_id:string};
  return !!v && typeof v.job_id==="string" && /^[a-f0-9]{32}$/.test(v.job_id) && Object.keys(v).length===1;
}
