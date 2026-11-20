export interface ApacheRuntimeStatus {
 selected_id:string;running_id:string;service_state:string;recommended_id:string;
 target_installed:boolean;native_engine_required:boolean;waf_version:string;
 activation_needed:boolean;checked_at:string;
}
export function parseApacheRuntimeStatus(value:unknown):ApacheRuntimeStatus {
 const v=value as ApacheRuntimeStatus;
 const reviewed=["apache-2.4.68","apache-2.4.71"];
 if(!v||!reviewed.includes(v.selected_id)||v.running_id!==""&&!reviewed.includes(v.running_id)
  || !["active","inactive","failed"].includes(v.service_state)||v.recommended_id!=="apache-2.4.71"
  ||typeof v.target_installed!=="boolean"||typeof v.native_engine_required!=="boolean"||typeof v.waf_version!=="string"
  ||typeof v.activation_needed!=="boolean"||!Number.isFinite(Date.parse(v.checked_at))
  ||(v.service_state==="active")!==(v.running_id!=="")
  ||v.activation_needed!==(v.selected_id!==v.recommended_id||v.running_id!==v.selected_id||!v.target_installed))
  throw Error("Apache 原生状态响应不完整或相互矛盾，未用安装记录推断已切换");
 return v;
}
