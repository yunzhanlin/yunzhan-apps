export interface ApacheBodyPolicyDraft {
 engine_job_id:string;
 sites:{site_id:string;policy:{mode:string;paranoia_level:number;inbound_threshold:number;body_limit_kib:number;non_file_limit_kib:number;json_depth:number;argument_limit:number}}[];
}
export function apacheBodyPolicySupported(installed:unknown,version:unknown,implementation:unknown):boolean{
 return installed===true && version==="2.4.0" && implementation==="2.4.0";
}
export function apacheBodyPolicyAddSite(body:ApacheBodyPolicyDraft|undefined,site:string,knownSites:{id:string;status:string}[]):ApacheBodyPolicyDraft{
 if(!body || !/^[a-f0-9]{32}$/.test(body.engine_job_id))throw Error("先选择已核实的本机引擎");
 if(!/^[a-f0-9]{32}$/.test(site) || !knownSites.some(s=>s.id===site && s.status==="running"))throw Error("只能选择正在运行的受管Apache网站");
 if(body.sites.length>=64 || body.sites.some(s=>s.site_id===site))throw Error("请求体网站重复或达到64个上限");
 return {engine_job_id:body.engine_job_id,sites:[...body.sites.map(s=>({site_id:s.site_id,policy:{...s.policy}})),{site_id:site,policy:{mode:"observe",paranoia_level:1,inbound_threshold:5,body_limit_kib:1024,non_file_limit_kib:256,json_depth:64,argument_limit:256}}]};
}

