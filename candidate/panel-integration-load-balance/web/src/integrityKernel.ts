import { sha256 } from '@noble/hashes/sha2.js';
import { bytesToHex } from '@noble/hashes/utils.js';
import { menuPermissionIDs, validAccessPlan, type AccessPlan } from './menuPermissions';

export const integrityKernelVersion = '1.5.0';
const id = /^[a-f0-9]{32}$/, sha = /^[a-f0-9]{64}$/;
export interface KernelInput {
  site_id: string; expected_revision: number; expected_app_version: string;
  baseline_sha: string; source_operation: string; source_sha: string; confirm: string;
}
export interface KernelRequest {
  format: number; id: string; actor_id: string; access_revision: number; app_sha: string;
  action: 'enable' | 'release'; input: KernelInput; created_at: string;
}
export interface KernelOperation {
  request: KernelRequest; request_sha256: string; state: string; revision: number;
  plan_sha: string; enable_operation: string; files: number; directories: number;
  completed: number; error: string; finished_at: string;
}
export interface KernelStatus {
	 site_id: string; app_version: string; app_sha:string; revision: number; state: string;
  baseline_sha: string; baseline_files: number; cap_linux_immutable: boolean;
  verified_at: string; error: string; latest?: KernelOperation; operations: KernelOperation[]; scope: string;
}
export interface KernelPending {
  id: string; key:string; close_key?:string; actor: string; action: 'enable' | 'release'; input: KernelInput;
}
export interface KernelClosure {format:number;id:string;request:KernelRequest;original_request_sha256:string;sealed_at:string}
export interface KernelAdmission {id:string;state:'absent'|'original'|'sealed';operation?:KernelOperation;closure?:KernelClosure}
const hash = (text: string) => bytesToHex(sha256(new TextEncoder().encode(text)));
const integer = (n: unknown, max: number) => Number.isSafeInteger(n) && (n as number) >= 0 && (n as number) <= max;
const utc = (text: unknown) => typeof text === 'string' && /^20\d\d-\d\d-\d\dT[\d:.]+Z$/.test(text) && Number.isFinite(Date.parse(text));

export function kernelFullAdministrator(access: AccessPlan | null | undefined) {
  return validAccessPlan(access) && access.role === 'admin' && access.menu_ids.length === menuPermissionIDs.length;
}
export function kernelOperationID(actor: string, key: string) {
  if (!id.test(actor) || !key || key.length > 128 || key.trim() !== key) throw Error('原操作者或提交键无效');
  return hash(`integrity-kernel-operation-v1\0${actor}\0${key}`).slice(0, 32);
}
export function kernelNewSubmissionKey() {
  return bytesToHex(crypto.getRandomValues(new Uint8Array(16)));
}
function kernelInputIdentity(v:KernelInput) {
  return JSON.stringify({site_id:v.site_id,expected_revision:v.expected_revision,expected_app_version:v.expected_app_version,baseline_sha:v.baseline_sha,source_operation:v.source_operation,source_sha:v.source_sha,confirm:v.confirm});
}
export function kernelInputValid(action: string, value: unknown): value is KernelInput {
  const v = value as KernelInput;
  if (!v || !id.test(v.site_id) || !integer(v.expected_revision, Number.MAX_SAFE_INTEGER - 1) || v.expected_app_version !== integrityKernelVersion) return false;
  if (action === 'enable') return sha.test(v.baseline_sha) && v.source_operation === '' && v.source_sha === '' && v.confirm === `PROTECT SITE ${v.site_id}`;
  if (action === 'release') return v.baseline_sha === '' && id.test(v.source_operation) && sha.test(v.source_sha) && v.confirm === `RELEASE SITE ${v.site_id}`;
  return false;
}
export function kernelRequestSHA(r: KernelRequest) {
  // All values in this closed contract are ASCII. Keep Go's struct field
  // order explicitly; never hash an arbitrary caller's object key order.
  return hash(JSON.stringify({format:r.format,id:r.id,actor_id:r.actor_id,access_revision:r.access_revision,app_sha:r.app_sha,action:r.action,input:{site_id:r.input.site_id,expected_revision:r.input.expected_revision,expected_app_version:r.input.expected_app_version,baseline_sha:r.input.baseline_sha,source_operation:r.input.source_operation,source_sha:r.input.source_sha,confirm:r.input.confirm},created_at:r.created_at}));
}
export function kernelOperationValid(value: unknown): value is KernelOperation {
  const v=value as KernelOperation, r=v?.request;
  if (!r || r.format!==1 || !id.test(r.id) || !id.test(r.actor_id) || !integer(r.access_revision,Number.MAX_SAFE_INTEGER) || r.access_revision<1 || !sha.test(r.app_sha) || !kernelInputValid(r.action,r.input) || !utc(r.created_at)) return false;
  if (v.request_sha256!==kernelRequestSHA(r) || v.revision!==r.input.expected_revision+1 || !integer(v.files,10000) || !integer(v.directories,4097) || !integer(v.completed,v.files+v.directories) || typeof v.error!=='string' || v.error.length>2048 || typeof v.finished_at!=='string' || typeof v.plan_sha!=='string' || typeof v.enable_operation!=='string') return false;
  if (v.plan_sha!==''&&!sha.test(v.plan_sha) || v.enable_operation!==''&&!id.test(v.enable_operation)) return false;
  if (v.state==='queued'||v.state==='running') return v.error===''&&v.finished_at==='';
  if (v.state==='needs-attention') return v.error!=='';
  if(v.state==='cancelled')return v.error!==''&&utc(v.finished_at)&&v.plan_sha===''&&v.enable_operation===''&&v.completed===0&&v.files===0&&v.directories===0;
  if (v.state==='declined') return r.action==='enable'&&v.error!==''&&utc(v.finished_at);
  return v.state==='succeeded'&&v.error===''&&utc(v.finished_at)&&sha.test(v.plan_sha)&&id.test(v.enable_operation)&&v.directories>0&&v.completed===v.files+v.directories;
}
export function kernelStatusValid(value: unknown, site: string): value is KernelStatus {
  const v=value as KernelStatus;
  if (!v||v.site_id!==site||!id.test(site)||!['',integrityKernelVersion].includes(v.app_version)||typeof v.app_sha!=='string'||v.app_sha!==''&&!sha.test(v.app_sha)||!integer(v.revision,Number.MAX_SAFE_INTEGER)||!integer(v.baseline_files,10000)||typeof v.cap_linux_immutable!=='boolean'||!utc(v.verified_at)||typeof v.error!=='string'||typeof v.scope!=='string'||typeof v.baseline_sha!=='string'||v.baseline_sha!==''&&!sha.test(v.baseline_sha)||!Array.isArray(v.operations)||v.operations.length>512) return false;
  if (!['needs-baseline','ready','upgrade-required','unsupported','queued','running','enabled','released','needs-attention'].includes(v.state)) return false;
  let revision=0;
  let previous:KernelOperation|undefined;
  for (const op of v.operations) {
    if (!kernelOperationValid(op)||op.request.input.site_id!==site||op.revision!==revision+1) return false;
    if(op.request.action==='release'&&(!previous||op.request.input.source_operation!==previous.request.id||op.request.input.source_sha!==previous.request_sha256))return false;
    revision=op.revision;
    previous=op;
  }
  if (v.revision!==revision || Boolean(v.latest)!==Boolean(v.operations.length)) return false;
  if (v.latest) {
    if(!kernelOperationValid(v.latest))return false;
    const last=v.operations.at(-1)!;
    for(const field of ['request_sha256','state','revision','plan_sha','enable_operation','files','directories','completed','error','finished_at'] as const)if(v.latest[field]!==last[field])return false;
  }
  if (v.state==='enabled' && (v.latest?.request.action!=='enable'||v.latest.state!=='succeeded'||v.app_version!==integrityKernelVersion||!sha.test(v.app_sha))) return false;
  if (v.state==='released' && (v.latest?.request.action!=='release'||v.latest.state!=='succeeded')) return false;
  return true;
}
export function kernelActionInput(status: KernelStatus, action: 'enable'|'release', expectedSite:string): KernelInput {
  if (!kernelStatusValid(status,expectedSite) || status.app_version!==integrityKernelVersion || !sha.test(status.app_sha)) throw Error('当前网站、签名应用收据或版本尚未核对');
  const input:KernelInput={site_id:status.site_id,expected_revision:status.revision,expected_app_version:integrityKernelVersion,baseline_sha:'',source_operation:'',source_sha:'',confirm:''};
  if(!status.cap_linux_immutable)throw Error('先恢复执行器的原生标记控制权限，再执行启停。');
  if (action==='enable') {
    if (!status.cap_linux_immutable || !['ready','released'].includes(status.state) || !sha.test(status.baseline_sha)) throw Error('先核对可用能力、当前签名基线和原保护状态');
    input.baseline_sha=status.baseline_sha;input.confirm=`PROTECT SITE ${status.site_id}`;
  } else {
    const original=status.latest;
    if (!original || !['enabled','needs-attention'].includes(status.state) || ['queued','running','declined'].includes(original.state) || original.state==='succeeded'&&original.request.action==='release') throw Error('原任务尚不能解除；先只读核对');
    input.source_operation=original.request.id;input.source_sha=original.request_sha256;input.confirm=`RELEASE SITE ${status.site_id}`;
  }
  return input;
}
export function kernelPendingValid(value: unknown, actor: string): value is KernelPending {
  const v=value as KernelPending;
  return !!v&&v.actor===actor&&id.test(v.id)&&id.test(actor)&&typeof v.key==='string'&&/^[a-f0-9]{32}$/.test(v.key)&&v.id===kernelOperationID(actor,v.key)&&(v.close_key===undefined||/^[a-f0-9]{32}$/.test(v.close_key))&&kernelInputValid(v.action,v.input);
}
export function kernelPendingMatches(pending: KernelPending, value: unknown): value is KernelOperation {
  return kernelOperationValid(value)&&value.request.id===pending.id&&value.request.actor_id===pending.actor&&value.request.action===pending.action&&kernelInputIdentity(value.request.input)===kernelInputIdentity(pending.input);
}
export function kernelAdmissionMatches(pending:KernelPending,value:unknown):value is KernelAdmission {
  const v=value as KernelAdmission;
  if(!v||v.id!==pending.id)return false;
  if(v.state==='absent')return v.operation===undefined&&v.closure===undefined;
  if(v.state==='original')return v.closure===undefined&&kernelPendingMatches(pending,v.operation);
  if(v.state!=='sealed'||!v.closure)return false;
  const c=v.closure,r=c.request;
  if(c.format!==1||!id.test(c.id)||!utc(c.sealed_at)||!r||r.format!==1||r.id!==pending.id||r.actor_id!==pending.actor||r.action!==pending.action||!kernelInputValid(r.action,r.input)||kernelInputIdentity(r.input)!==kernelInputIdentity(pending.input)||!integer(r.access_revision,Number.MAX_SAFE_INTEGER)||r.access_revision<1||!sha.test(r.app_sha)||!utc(r.created_at)||typeof c.original_request_sha256!=='string')return false;
  if(v.operation)return v.operation.state==='cancelled'&&kernelPendingMatches(pending,v.operation)&&c.original_request_sha256===v.operation.request_sha256;
  return c.original_request_sha256==='';
}
export const kernelStateLabel:Record<string,string>={
  'needs-baseline':'尚无可信基线',ready:'可启用', 'upgrade-required':'需要更新应用',unsupported:'系统能力不可用',queued:'已排队',running:'正在执行',enabled:'内核保护已核对',released:'本应用保护已解除','needs-attention':'原结果待核对',succeeded:'已完成',declined:'启用未执行',cancelled:'原排队提交已封存',
};
