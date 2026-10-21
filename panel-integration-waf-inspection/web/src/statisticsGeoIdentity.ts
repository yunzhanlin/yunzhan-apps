export interface StatisticsGeoSelection {
  action: "install" | "rollback" | "archive" | "restore";
  app_version: string; app_manifest_sha256: string; installation_id: string;
  release: string; data_manifest_sha256: string;
}
export interface StatisticsGeoTicket { key: string; selection: StatisticsGeoSelection; job?: string }
export interface StatisticsGeoOutcome { request_id: string; job_id: string; selection?: StatisticsGeoSelection; state: string; state_known: boolean }
export interface StatisticsGeoRecord extends StatisticsGeoTicket { format: 1; actor: string }
export interface GeoStorageChange { put?: StatisticsGeoRecord; remove?: boolean; result?: StatisticsGeoTicket }
export interface GeoAtomicStorage {
  run(actor: string, write: boolean, change: (current: unknown, count: number) => GeoStorageChange): Promise<StatisticsGeoTicket | undefined>;
}
const id = /^[a-f0-9]{32}$/, sha = /^[a-f0-9]{64}$/;
const bad = () => new Error("原地域请求的浏览器记录或回复不能核对；保留原编号，未创建替代任务");
export function canonicalGeoSelection(value: StatisticsGeoSelection): StatisticsGeoSelection {
  if (!value || Array.isArray(value) || Object.keys(value).sort().join() !== "action,app_manifest_sha256,app_version,data_manifest_sha256,installation_id,release" ||
      !["install","rollback","archive","restore"].includes(value.action) || value.app_version !== "2.6.0" || typeof value.installation_id !== "string" || !id.test(value.installation_id) ||
      typeof value.app_manifest_sha256 !== "string" || !sha.test(value.app_manifest_sha256) || typeof value.data_manifest_sha256 !== "string" || !sha.test(value.data_manifest_sha256) || typeof value.release !== "string" || !/^20[2-9][0-9]-(0[1-9]|1[0-2])$/.test(value.release)) throw bad();
  return {action:value.action,app_version:value.app_version,app_manifest_sha256:value.app_manifest_sha256,installation_id:value.installation_id,release:value.release,data_manifest_sha256:value.data_manifest_sha256};
}
function saved(value: unknown, actor: string): StatisticsGeoRecord | undefined {
  if (value === undefined) return;
  if (!value || typeof value !== "object" || Array.isArray(value)) throw bad();
  const v = value as StatisticsGeoRecord;
  if (Object.keys(v).some(k => !["format","actor","key","selection","job"].includes(k)) || v.format !== 1 || v.actor !== actor || typeof v.key !== "string" || !id.test(v.key) || v.job !== undefined && (typeof v.job !== "string" || !id.test(v.job))) throw bad();
  return {format:1,actor,key:v.key,selection:canonicalGeoSelection(v.selection),...(v.job === undefined?{}:{job:v.job})};
}
function ticket(value: StatisticsGeoRecord): StatisticsGeoTicket { return {key:value.key,selection:{...value.selection},...(value.job===undefined?{}:{job:value.job})}; }

// Browser-local equality/continuity only, NEVER signing or server authority.
// One serialized record per actor survives reload and installation changes.
export class StatisticsGeoRequestIdentity {
  constructor(private storage: GeoAtomicStorage, private actor: string, private random: () => string) { if (typeof actor !== "string" || !id.test(actor)) throw bad(); }
  read(): Promise<StatisticsGeoTicket | undefined> { return this.storage.run(this.actor,false,value=>{const v=saved(value,this.actor);return {result:v?ticket(v):undefined};}); }
  begin(selection: StatisticsGeoSelection): Promise<StatisticsGeoTicket | undefined> {
    const input=canonicalGeoSelection(selection);
    return this.storage.run(this.actor,true,(value,count)=>{
      const old=saved(value,this.actor);
      if(old){if(JSON.stringify(old.selection)!==JSON.stringify(input))throw bad();return{result:ticket(old)};}
      if(!Number.isSafeInteger(count)||count<0||count>=128)throw bad();
      const random=this.random();if(typeof random!=="string")throw bad();const key=/^[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/.test(random)?random.replaceAll("-",""):random;
      if(!id.test(key))throw bad();const next:StatisticsGeoRecord={format:1,actor:this.actor,key,selection:input};return{put:next,result:ticket(next)};
    });
  }
  accepted(original: StatisticsGeoTicket, job: string): Promise<StatisticsGeoTicket | undefined> {
    return this.storage.run(this.actor,true,value=>{
      const old=saved(value,this.actor);if(!old||old.key!==original.key||JSON.stringify(old.selection)!==JSON.stringify(canonicalGeoSelection(original.selection))||typeof job!=="string"||!id.test(job)||old.job&&old.job!==job)throw bad();
      const next={...old,job};return{put:next,result:ticket(next)};
    });
  }
  observe(outcome: StatisticsGeoOutcome): Promise<StatisticsGeoTicket | undefined> {
    return this.storage.run(this.actor,true,value=>{
      const old=saved(value,this.actor);if(!old||!outcome||outcome.request_id!==old.key||typeof outcome.state_known!=="boolean")throw bad();
      if(!outcome.state_known){if(outcome.state!=="unknown"||outcome.job_id!==""||outcome.selection!==undefined)throw bad();return{result:ticket(old)};}
      if(!["queued","running","succeeded","failed","needs_attention"].includes(outcome.state)||typeof outcome.job_id!=="string"||!id.test(outcome.job_id)||old.job&&old.job!==outcome.job_id||JSON.stringify(canonicalGeoSelection(outcome.selection!))!==JSON.stringify(old.selection))throw bad();
      if(["succeeded","failed"].includes(outcome.state))return{remove:true};
      const next={...old,job:outcome.job_id};return{put:next,result:ticket(next)};
    });
  }
}

// Overlapping readwrite transactions serialize across tabs, unlike a sequence
// of localStorage get/set calls. Return the ticket only AFTER transaction
// completion. Strict durability is requested, not a power-loss acceptance claim.
// Spec: https://www.w3.org/TR/IndexedDB/#transaction-scheduling
export class IndexedStatisticsGeoStorage implements GeoAtomicStorage {
  constructor(private factory: IDBFactory | undefined = globalThis.indexedDB) {}
  run(actor: string, write: boolean, change: (current: unknown, count: number) => GeoStorageChange): Promise<StatisticsGeoTicket | undefined> {
    return new Promise((resolve,reject)=>{
      if(!this.factory||typeof actor!=="string"||!id.test(actor)){reject(bad());return;}
      let open:IDBOpenDBRequest;
      try{open=this.factory.open("yunzhan-statistics-geodata-requests-v1",1);}catch{reject(bad());return;}
      let settled=false;
      const fail=(reason:unknown)=>{if(!settled){settled=true;reject(reason instanceof Error?reason:bad());}};
      open.onblocked=()=>fail(new Error("原地域请求存储被其他页面占用；未创建新请求"));open.onerror=()=>fail(bad());
      open.onupgradeneeded=()=>{const db=open.result;if(settled||db.objectStoreNames.length!==0){open.transaction?.abort();return;}db.createObjectStore("requests",{keyPath:"actor"});};
      open.onsuccess=()=>{
        const db=open.result;if(settled){db.close();return;}
        db.onversionchange=()=>db.close();
        let tx:IDBTransaction;
        try{
          if(db.version!==1||db.objectStoreNames.length!==1||!db.objectStoreNames.contains("requests"))throw bad();
          tx=db.transaction("requests",write?"readwrite":"readonly",write?{durability:"strict"}:undefined);
        }catch(e){db.close();fail(e);return;}
        let result:StatisticsGeoTicket|undefined,reason:unknown,getDone=false,countDone=false;
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
