import {registryFingerprint} from "./registryRequestIdentity.ts";
export function newRemoteRequestID(): string {
  const value = new Uint8Array(16);
  crypto.getRandomValues(value);
  return Array.from(value, byte => byte.toString(16).padStart(2, "0")).join("");
}
export function validRemoteJob(value: unknown): value is Record<string, any> {
  if (!value || typeof value !== "object" || Array.isArray(value)) return false;
  const v = value as Record<string, any>;
  return /^[0-9a-f]{32}$/.test(v.remote_request_id) &&
    /^[a-z0-9][a-z0-9-]{2,63}$/.test(v.remote_target_id) && /^[0-9a-f]{32}$/.test(v.site_id) &&
    Number.isSafeInteger(v.revision) && v.revision > 0 &&
    ["queued", "running", "succeeded", "conflicts", "failed", "interrupted", "recovered"].includes(v.state) &&
    Number.isInteger(v.copied_count) && v.copied_count >= 0 && v.copied_count <= 10000 &&
    Number.isInteger(v.skipped_count) && v.skipped_count >= 0 && v.skipped_count <= 10000 && v.copied_count+v.skipped_count<=10000;
}
export function remoteJobTerminal(value: unknown): boolean {
  return validRemoteJob(value) && ["succeeded", "conflicts", "failed", "recovered"].includes(value.state);
}
export function remoteQueueReplyMatches(value: unknown, body: Record<string, unknown>): boolean {
  return validRemoteJob(value) && value.remote_request_id === body.remote_request_id &&
    value.remote_target_id === body.remote_target_id && value.site_id === body.site_id &&
    value.revision === body.expected_revision;
}

// Only public connection policy crosses into selectable table rows. Do not
// carry arbitrary nested server objects, credentials or encrypted records.
export function remoteConnectionRow(value: Record<string, any>): Record<string, any> {
  const target = value.remote_target;
  if (!target || typeof target !== "object" || Array.isArray(target) ||
      !Number.isSafeInteger(target.port) || target.port < 1 || target.port > 65535 ||
      !["address","username","host_key","root","backup_root"].every(key =>
        typeof target[key] === "string" && target[key].length > 0 && target[key].length <= (key === "host_key" ? 2048 : 512))) return {};
  return {remote_target: Object.fromEntries(["address","port","username","host_key","root","backup_root"].map(key => [key,target[key]]))};
}
export interface RemoteRequestTicket {
  actor: string; key: string; target: string; site: string; revision: number; fingerprint: string;
}
type RemoteStore = Pick<Storage,"getItem"|"setItem"|"removeItem">;
const remoteStorageKey="panel-remote-sync-pending-v1";
const hexID=/^[a-f0-9]{32}$/, targetID=/^[a-z0-9][a-z0-9-]{2,63}$/;
function validTicket(v: any): v is RemoteRequestTicket {
  return !!v && typeof v === "object" && !Array.isArray(v) &&
    Object.keys(v).length===6 && Object.keys(v).every(key=>["actor","key","target","site","revision","fingerprint"].includes(key)) &&
    hexID.test(v.actor) && hexID.test(v.key) && targetID.test(v.target) && hexID.test(v.site) &&
    Number.isSafeInteger(v.revision) && v.revision>0 && /^[a-f0-9]{64}$/.test(v.fingerprint);
}
export class RemoteRequestIdentity {
  private actor="";
  private pending=new Map<string,RemoteRequestTicket>();
  private error="";
  constructor(private storage:RemoteStore,private newKey:()=>string=newRemoteRequestID,private changed:()=>void=()=>{}){}
  bind(actor:string):void {
    this.actor=actor;this.pending.clear();this.error="";
    try {
      const raw=this.storage.getItem(remoteStorageKey);
      if(!hexID.test(actor)){this.storage.removeItem(remoteStorageKey);this.error="账户请求标识未就绪，未提交远端任务";}
      else if(raw) {
        if(raw.length>16*1024)throw new Error("too large");
        const saved=JSON.parse(raw);
        if(!saved || saved.format!==1 || !hexID.test(saved.actor) || Object.keys(saved).some(k=>!["format","actor","pending"].includes(k)) ||
           !Array.isArray(saved.pending) || saved.pending.length>16 || !saved.pending.every(validTicket) ||
           saved.pending.some((row:RemoteRequestTicket)=>row.actor!==saved.actor) ||
           new Set(saved.pending.map((row:RemoteRequestTicket)=>row.target)).size!==saved.pending.length ||
           new Set(saved.pending.map((row:RemoteRequestTicket)=>row.key)).size!==saved.pending.length)throw new Error("invalid record");
        if(saved.actor===actor)for(const row of saved.pending)this.pending.set(row.target,{...row});
        else this.storage.removeItem(remoteStorageKey);
      }
    }catch{this.error="待核对远端任务记录不可读取；先读取服务器持久任务，未提交新任务";}
    this.changed();
  }
  list():RemoteRequestTicket[]{return Array.from(this.pending.values(),row=>({...row}));}
  private save(next:Map<string,RemoteRequestTicket>):void {
    try{this.storage.setItem(remoteStorageKey,JSON.stringify({format:1,actor:this.actor,pending:Array.from(next.values())}));}
    catch{throw new Error("不能保存待核对任务标识，未提交；请允许本站会话存储");}
    this.pending=next;this.changed();
  }
  begin(body:Record<string,unknown>):RemoteRequestTicket {
    if(this.error)throw new Error(this.error);
    const {remote_target_id:target,site_id:site,expected_revision:revision}=body;
    if(!hexID.test(this.actor) || typeof target!=="string" || !targetID.test(target) || typeof site!=="string" || !hexID.test(site) ||
       typeof revision!=="number" || !Number.isSafeInteger(revision) || revision<1 ||
       Object.keys(body).some(key=>!["remote_target_id","site_id","expected_revision","remote_request_id","excludes"].includes(key)))throw new Error("远端任务身份或来源无效，未提交");
    const excludes=body.excludes ?? [];
    if(!Array.isArray(excludes) || excludes.length>64 || excludes.some(path=>typeof path!=="string" || path.length>512))throw new Error("排除项无效，未提交");
    const fingerprint=registryFingerprint(JSON.stringify({target,site,revision,excludes:[...excludes].sort()}));
    const old=this.pending.get(target);
    if(old) {
      if(old.fingerprint!==fingerprint || body.remote_request_id && body.remote_request_id!==old.key)throw new Error("远端有待核对的原任务；先读取实际进度，未提交不同来源或配置的新任务");
      return {...old};
    }
    if(this.pending.size>=16)throw new Error("待核对远端任务达到上限，请先读取原任务");
    const key=body.remote_request_id || this.newKey();
    if(typeof key!=="string" || !hexID.test(key) || this.list().some(row=>row.key===key))throw new Error("远端任务标识无效，未提交");
    const ticket={actor:this.actor,key,target,site,revision,fingerprint};
    this.save(new Map(this.pending).set(target,ticket)); // BEFORE network fetch.
    return {...ticket};
  }
  release(job:unknown):void {
    if(!remoteJobTerminal(job))throw new Error("原任务尚未明确结束，保留原标识");
    const j=job as Record<string,any>,old=this.pending.get(j.remote_target_id);
    if(!old || old.actor!==this.actor || old.key!==j.remote_request_id || old.site!==j.site_id || old.revision!==j.revision)throw new Error("原任务回执与本账户待核对记录不一致，未创建新任务");
    const next=new Map(this.pending);next.delete(old.target);this.save(next);
  }
}
