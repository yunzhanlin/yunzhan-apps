export interface CountrySelection {
  action: "download"; app_version: "2.6.0"; app_manifest_sha256: string;
  installation_sha256: string; release: string; revision: number;
  data_manifest_sha256: string; countries: string[];
}
export interface CountryTicket { key: string; selection: CountrySelection; job?: string }
export interface CountryRecord extends CountryTicket { format: 1; actor: string }
export interface CountryStorageResult { ticket?: CountryTicket; fresh?: boolean }
export interface CountryStorageChange { put?: CountryRecord; remove?: boolean; result?: CountryStorageResult }
export interface CountryAtomicStorage {
  run(actor: string, write: boolean, change: (current: unknown, count: number) => CountryStorageChange): Promise<CountryStorageResult | undefined>;
}
export interface CountryOperation {
  format: number; job_id: string; actor_id: string; selection: CountrySelection;
  payload_sha256: string; request_sha256: string; requested_cache_plan_sha256: string;
  state: string; error: string; data_only: boolean; automatic_replay_allowed: boolean;
  cache?: {dataset: string;data_manifest_sha256: string;countries: string[];release: string;revision: number;original_job_id: string;plan_sha256: string;prepared_at: string;bytes: number;networks: number;published: boolean;reused: boolean;activated_nginx_policy: boolean};
}
export interface CountryDetail {
  actor_id: string; request: {id: string;state: string;created_at: string;payload_sha256: string};
  selection: CountrySelection; read_only: boolean; error: string;
  result?: CountryOperation; result_sha256?: string;
}
export interface CountryLookup {
  actor_id: string;request_id: string;state_known: boolean;request?: CountryDetail;
  read_only: boolean;automatic_replay_allowed: boolean;
}
const id=/^[a-f0-9]{32}$/,sha=/^[a-f0-9]{64}$/,code=/^[A-Z]{2}$/;
const bad=()=>new Error("原国家数据请求、账户或完整回复无法核对；保留原编号，不创建替代任务");
export function canonicalCountrySelection(v: CountrySelection): CountrySelection {
  if(!v||Array.isArray(v)||Object.keys(v).sort().join()!=="action,app_manifest_sha256,app_version,countries,data_manifest_sha256,installation_sha256,release,revision"||v.action!=="download"||v.app_version!=="2.6.0"||typeof v.app_manifest_sha256!=="string"||!sha.test(v.app_manifest_sha256)||typeof v.installation_sha256!=="string"||!sha.test(v.installation_sha256)||typeof v.data_manifest_sha256!=="string"||!sha.test(v.data_manifest_sha256)||typeof v.release!=="string"||!/^20[2-9][0-9]-(0[1-9]|1[0-2])$/.test(v.release)||!Number.isSafeInteger(v.revision)||v.revision<1||v.revision>1000||!Array.isArray(v.countries)||v.countries.length<1||v.countries.length>32||v.countries.some((c,i)=>typeof c!=="string"||!code.test(c)||c==="ZZ"||i>0&&c<=v.countries[i-1]!))throw bad();
  return {action:"download",app_version:"2.6.0",app_manifest_sha256:v.app_manifest_sha256,installation_sha256:v.installation_sha256,release:v.release,revision:v.revision,data_manifest_sha256:v.data_manifest_sha256,countries:[...v.countries]};
}
function same(a: CountrySelection,b: CountrySelection){return JSON.stringify(canonicalCountrySelection(a))===JSON.stringify(canonicalCountrySelection(b));}
function saved(value: unknown,actor: string): CountryRecord|undefined {
  if(value===undefined)return;
  if(!value||typeof value!=="object"||Array.isArray(value))throw bad();
  const v=value as CountryRecord;
  if(Object.keys(v).some(k=>!["format","actor","key","selection","job"].includes(k))||v.format!==1||v.actor!==actor||typeof v.key!=="string"||!id.test(v.key)||v.job!==undefined&&(typeof v.job!=="string"||!id.test(v.job)))throw bad();
  return {format:1,actor,key:v.key,selection:canonicalCountrySelection(v.selection),...(v.job===undefined?{}:{job:v.job})};
}
function ticket(v: CountryRecord): CountryTicket{return{key:v.key,selection:canonicalCountrySelection(v.selection),...(v.job===undefined?{}:{job:v.job})};}
function detailOriginal(value: CountryDetail,old: CountryRecord): CountryDetail {
  if(!value||value.actor_id!==old.actor||value.read_only!==true||!value.request||typeof value.request.id!=="string"||!id.test(value.request.id)||old.job&&old.job!==value.request.id||!same(value.selection,old.selection)||!["queued","running","succeeded","failed","needs_attention"].includes(value.request.state)||typeof value.request.payload_sha256!=="string"||!sha.test(value.request.payload_sha256)||typeof value.error!=="string"||value.error.length>4096)throw bad();
  if(value.result){
    const r=value.result,c=r.cache;
    if(r.format!==1||r.job_id!==value.request.id||r.actor_id!==old.actor||!same(r.selection,old.selection)||r.payload_sha256!==value.request.payload_sha256||typeof r.request_sha256!=="string"||!sha.test(r.request_sha256)||typeof r.requested_cache_plan_sha256!=="string"||!sha.test(r.requested_cache_plan_sha256)||r.data_only!==true||r.automatic_replay_allowed!==false||r.state!==value.request.state||r.error!==value.error||typeof value.result_sha256!=="string"||!sha.test(value.result_sha256)||!["succeeded","failed","needs_attention"].includes(r.state))throw bad();
    if(c&&(c.published!==true||c.activated_nginx_policy!==false||c.data_manifest_sha256!==old.selection.data_manifest_sha256||JSON.stringify(c.countries)!==JSON.stringify(old.selection.countries)||c.release!==old.selection.release||c.revision!==old.selection.revision||typeof c.original_job_id!=="string"||!id.test(c.original_job_id)||typeof c.plan_sha256!=="string"||!sha.test(c.plan_sha256)||typeof c.dataset!=="string"||!new RegExp("^"+old.selection.data_manifest_sha256+"-[a-f0-9]{64}$").test(c.dataset)||c.reused!==(c.original_job_id!==value.request.id)||!Number.isSafeInteger(c.bytes)||c.bytes<1||c.bytes>64*1024*1024||!Number.isSafeInteger(c.networks)||c.networks<1||c.networks>1048576))throw bad();
    if(r.state==="succeeded"&&(!c||r.error!==""))throw bad();
  }
  if(value.request.state==="succeeded"&&!value.result||["failed","needs_attention"].includes(value.request.state)&&value.error==="")throw bad();
  if(["queued","running"].includes(value.request.state)&&(value.error!==""||value.result!==undefined))throw bad();
  return value;
}

export function readCountryDetail(value:CountryDetail,actor:string,job:string):CountryDetail {
  if(typeof actor!=="string"||!id.test(actor)||typeof job!=="string"||!id.test(job))throw bad();
  return detailOriginal(value,{format:1,actor,key:job,job,selection:canonicalCountrySelection(value?.selection)});
}

// Browser continuity ONLY, not source/signature/Root authority. The first
// durable cross-tab creator alone receives fresh=true. Existing/unknown
// records are observation-only unless a user explicitly restores THAT key.
export class CountryRequestIdentity {
  constructor(private storage:CountryAtomicStorage,private actor:string,private random:()=>string){if(typeof actor!=="string"||!id.test(actor))throw bad();}
  async read():Promise<CountryTicket|undefined>{return(await this.storage.run(this.actor,false,value=>{const v=saved(value,this.actor);return{result:{ticket:v?ticket(v):undefined}};}))?.ticket;}
  begin(selection:CountrySelection):Promise<CountryStorageResult|undefined>{
    const input=canonicalCountrySelection(selection);
    return this.storage.run(this.actor,true,(value,count)=>{
      const old=saved(value,this.actor);if(old){if(!same(old.selection,input))throw bad();return{result:{ticket:ticket(old),fresh:false}};}
      if(!Number.isSafeInteger(count)||count<0||count>=128)throw bad();
      const random=this.random();if(typeof random!=="string")throw bad();const key=/^[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/.test(random)?random.replaceAll("-",""):random;
      if(!id.test(key))throw bad();const next:CountryRecord={format:1,actor:this.actor,key,selection:input};return{put:next,result:{ticket:ticket(next),fresh:true}};
    });
  }
  async accepted(original:CountryTicket,reply:{job_id:string;request_id:string;replayed:boolean;data_only:boolean}):Promise<CountryTicket|undefined>{
    return(await this.storage.run(this.actor,true,value=>{
      const old=saved(value,this.actor);if(!old||old.key!==original.key||!same(old.selection,original.selection)||!reply||reply.request_id!==old.key||reply.data_only!==true||typeof reply.replayed!=="boolean"||typeof reply.job_id!=="string"||!id.test(reply.job_id)||old.job&&old.job!==reply.job_id)throw bad();
      const next={...old,job:reply.job_id};return{put:next,result:{ticket:ticket(next)}};
    }))?.ticket;
  }
  async observe(outcome:CountryLookup,expected?:CountryTicket):Promise<CountryTicket|undefined>{
    return(await this.storage.run(this.actor,true,value=>{
      const persisted=saved(value,this.actor);
      const old=persisted||(expected?saved({format:1,actor:this.actor,key:expected.key,selection:canonicalCountrySelection(expected.selection),...(expected.job===undefined?{}:{job:expected.job})},this.actor):undefined);
      if(!old||!outcome||outcome.actor_id!==this.actor||outcome.request_id!==old.key||typeof outcome.state_known!=="boolean"||outcome.read_only!==true||outcome.automatic_replay_allowed!==false)throw bad();
      // Another tab may already have removed this exact terminal pending.
      // Only the caller's already-bound original + a complete terminal can
      // finish its local view; never recreate a row or erase a NEW request.
      if(!persisted&&(!outcome.state_known||!["succeeded","failed"].includes(outcome.request?.request.state||'')))throw bad();
      if(!outcome.state_known){if(outcome.request!==undefined)throw bad();return{result:{ticket:ticket(old)}};}
      const detail=detailOriginal(outcome.request!,old);
      if(["succeeded","failed"].includes(detail.request.state))return persisted?{remove:true}:{};
      const next={...old,job:detail.request.id};return{put:next,result:{ticket:ticket(next)}};
    }))?.ticket;
  }
}

// Overlapping readwrite transactions serialize across tabs, unlike a sequence
// of localStorage get/set calls. Return the ticket only AFTER transaction
// completion. Strict durability is requested, not a power-loss acceptance claim.
// Spec: https://www.w3.org/TR/IndexedDB/#transaction-scheduling
export class IndexedCountryStorage implements CountryAtomicStorage {
  constructor(private factory: IDBFactory | undefined = globalThis.indexedDB) {}
  run(actor: string, write: boolean, change: (current: unknown, count: number) => CountryStorageChange): Promise<CountryStorageResult | undefined> {
    return new Promise((resolve,reject)=>{
      if(!this.factory||typeof actor!=="string"||!id.test(actor)){reject(bad());return;}
      let open:IDBOpenDBRequest;
      try{open=this.factory.open("yunzhan-waf-country-requests-v1",1);}catch{reject(bad());return;}
      let settled=false;
      const fail=(reason:unknown)=>{if(!settled){settled=true;reject(reason instanceof Error?reason:bad());}};
      open.onblocked=()=>fail(new Error("原国家数据请求存储被其他页面占用；未创建新请求"));open.onerror=()=>fail(bad());
      open.onupgradeneeded=()=>{const db=open.result;if(settled||db.objectStoreNames.length!==0){open.transaction?.abort();return;}db.createObjectStore("requests",{keyPath:"actor"});};
      open.onsuccess=()=>{
        const db=open.result;if(settled){db.close();return;}
        db.onversionchange=()=>db.close();
        let tx:IDBTransaction;
        try{
          if(db.version!==1||db.objectStoreNames.length!==1||!db.objectStoreNames.contains("requests"))throw bad();
          tx=db.transaction("requests",write?"readwrite":"readonly",write?{durability:"strict"}:undefined);
        }catch(e){db.close();fail(e);return;}
        let result:CountryStorageResult|undefined,reason:unknown,getDone=false,countDone=false;
        const store=tx.objectStore("requests");
        if(store.keyPath!=="actor"||store.autoIncrement){tx.abort();db.close();fail(bad());return;}
        const get=store.get(actor),count=store.count();
        const apply=()=>{if(!getDone||!countDone)return;try{
          const next=change(get.result,count.result);if((next.put||next.remove)&&!write||next.put&&next.remove)throw bad();
          if(next.put){if(next.put.actor!==actor)throw bad();store.put(next.put);}else if(next.remove)store.delete(actor);
          result=next.result;
        }catch(e){reason=e;tx.abort();}};
        get.onsuccess=()=>{getDone=true;apply();};count.onsuccess=()=>{countDone=true;apply();};
        tx.onabort=()=>{db.close();fail(reason??bad());};tx.onerror=()=>{reason??=bad();};
        tx.oncomplete=()=>{db.close();if(!settled){settled=true;resolve(result);}};
      };
    });
  }
}
