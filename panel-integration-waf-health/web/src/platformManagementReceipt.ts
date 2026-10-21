import { browserSHA256 } from './browserSHA256.ts';
export type PlatformMutation = 'add' | 'remove' | 'issue-token' | 'revoke-token';
export type PlatformObservation = {action:PlatformMutation; resourceID:string; tokenID:string; address:string; requiredRead:'run'|'token-list';state:'unverified'|'acknowledged'|'refresh_failed'};
const hex64=(value:unknown):value is string=>typeof value==='string'&&/^[a-f0-9]{64}$/.test(value);
const hostID=(value:unknown):value is string=>typeof value==='string'&&/^[a-z][a-z0-9-]{2,31}$/.test(value);
const object=(value:unknown):value is Record<string,unknown>=>!!value&&typeof value==='object'&&!Array.isArray(value)&&Object.getPrototypeOf(value)===Object.prototype;
const keys=(value:Record<string,unknown>,expected:string[])=>Object.keys(value).length===expected.length&&expected.every(key=>Object.hasOwn(value,key));
const stamp=(value:unknown):value is string=>typeof value==='string'&&/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/.test(value)&&Number.isFinite(Date.parse(value))&&new Date(value).toISOString().replace(/\.000Z$/,'Z')===value;
function address(value:unknown):value is string {
 if(typeof value!=='string'||value.length>2048)return false;
 try {const u=new URL(value);return u.protocol==='https:'&&!!u.hostname&&!u.username&&!u.password&&!u.search&&!u.hash;}catch{return false;}
}
async function digest(value:string):Promise<string>{return browserSHA256(value);}
export function isPlatformMutation(action:string):action is PlatformMutation{return ['add','remove','issue-token','revoke-token'].includes(action);}
export function platformHostSnapshotSHA(form:Record<string,unknown>,selectedID:string):string{return hostID(form.resource_id)&&form.resource_id===selectedID&&hex64(form.expected_sha)?form.expected_sha:'';}
export function platformActionBody(action:string,form:Record<string,unknown>,selectedID:string):Record<string,unknown>{
 const allowed:Record<string,string[]>={run:[],'token-list':[],'issue-token':[],add:['resource_id','url','token'],remove:['resource_id'],'revoke-token':['token','token_id']};
 const body=Object.fromEntries((allowed[action]||[]).filter(key=>typeof form[key]==='string'&&form[key]!=='').map(key=>[key,form[key]]));
 if(['add','remove'].includes(action)){const sha=platformHostSnapshotSHA(form,selectedID);if(sha)body.expected_sha=sha;}
 return body;
}
export function platformMutationNeedsRead(observation:PlatformObservation|undefined,action:string):boolean{return !!observation&&observation.state!=='acknowledged'&&isPlatformMutation(action);}
// Deliberately retain no plaintext secret, invalid URL credentials, or entire
// request. Revocation can bind a public identifier derived before transmission.
export async function platformObservation(action:PlatformMutation,input:Record<string,unknown>):Promise<PlatformObservation>{
 let tokenID=hex64(input.token_id)?input.token_id:'';
 if(hex64(input.token)&&!tokenID)tokenID=await digest(input.token);
 return {action,resourceID:hostID(input.resource_id)?input.resource_id:'',tokenID,address:address(input.url)?input.url:'',requiredRead:action==='add'||action==='remove'?'run':'token-list',state:'unverified'};
}
export async function platformMutationReplyMatches(observation:PlatformObservation,value:unknown):Promise<boolean>{
 if(!object(value))return false;
 switch(observation.action){
 case 'add':return keys(value,['id','url','expected_sha'])&&hex64(value.expected_sha)&&!!observation.resourceID&&!!observation.address&&value.id===observation.resourceID&&value.url===observation.address;
 case 'remove':return keys(value,['removed','already_absent'])&&!!observation.resourceID&&value.removed===observation.resourceID&&typeof value.already_absent==='boolean';
 case 'issue-token':return keys(value,['token','token_id','scope','endpoint'])&&hex64(value.token)&&hex64(value.token_id)&&value.scope==='health-read-only'&&value.endpoint==='/api/platform/agent'&&await digest(value.token)===value.token_id;
 case 'revoke-token':return keys(value,['revoked','token_id','already_absent'])&&value.revoked===true&&!!observation.tokenID&&value.token_id===observation.tokenID&&typeof value.already_absent==='boolean';
 }
}
export function platformReadKnown(action:string,value:unknown):boolean{
 if(!object(value))return false;
 if(action==='token-list'){
  if(!keys(value,['tokens','total','limit','read_only','scope'])||!Array.isArray(value.tokens)||value.tokens.length>128||value.total!==value.tokens.length||value.limit!==128||value.read_only!==true||typeof value.scope!=='string')return false;
  const seen=new Set<string>();
  return value.tokens.every(row=>{if(!object(row)||!keys(row,['token_id','created_at','scope'])||!hex64(row.token_id)||seen.has(row.token_id)||!stamp(row.created_at)||row.scope!=='health-read-only')return false;seen.add(row.token_id);return true;});
 }
 if(action==='run'){
  if(!keys(value,['hosts','checked_at','scope'])||!Array.isArray(value.hosts)||value.hosts.length>12||!stamp(value.checked_at)||typeof value.scope!=='string')return false;
  const seen=new Set<string>();
  return value.hosts.every(row=>{
   if(!object(row)||Object.keys(row).some(key=>!['id','url','expected_sha','healthy','telemetry_complete','error','status','report'].includes(key))||!hostID(row.id)||seen.has(row.id)||!hex64(row.expected_sha)||typeof row.url!=='string'||typeof row.healthy!=='boolean')return false;
   seen.add(row.id);
   if(row.healthy){return address(row.url)&&typeof row.telemetry_complete==='boolean'&&row.status===200&&object(row.report)&&row.report.version==='app-modules-1'&&stamp(row.report.time)&&object(row.report.health);}
   return row.report===undefined&&typeof row.error==='string'&&!!row.error&&(row.telemetry_complete===undefined||row.telemetry_complete===false);
  });
 }
 return false;
}
