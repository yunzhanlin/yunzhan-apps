// Source-only browser-model fixtures. None is an installed/native receipt.
import {readFileSync} from 'node:fs';
import ts from '../web/node_modules/typescript/lib/typescript.js';
const source=p=>readFileSync(new URL('../web/src/'+p+'.ts',import.meta.url),'utf8');
const url=text=>'data:text/javascript;base64,'+Buffer.from(text).toString('base64');
const compile=p=>ts.transpileModule(source(p),{compilerOptions:{target:ts.ScriptTarget.ES2022,module:ts.ModuleKind.ESNext}}).outputText;
const identity=url(compile('registryRequestIdentity')),permissions=url(compile('menuPermissions'));
export const model=await import(url(compile('loadBalanceStream').replace('"./registryRequestIdentity"',JSON.stringify(identity)).replace('"./menuPermissions"',JSON.stringify(permissions))));
export const actor='a'.repeat(32),other='b'.repeat(32),requestID='c'.repeat(32);
export const access={user_id:actor,role:'admin',permission_revision:1,menu_ids:['overview','sites','databases','files','security','runtimes','schedules','monitor','terminal','panel-access','audit','system-tools']};
export const policy={protocol:'tcp',port:42000,nodes:[{address:'192.0.2.10:41001',weight:1,backup:false},{address:'[2001:db8::11]:41002',weight:3,backup:false}],method:'round-robin',connect_milliseconds:2000,session_seconds:30,max_sessions:64,udp_requests:0,udp_responses:0};
export const entry=model.streamEntry({format:1,revision:7,name:'fixture.lb.invalid',...policy,probe_port:43000,removed:false});
export const mutation=model.streamMutation({format:1,action:'create',name:entry.name,expected_revision:0,expected_fingerprint:'',policy});
export function row(state='reserved',actorID=actor,id=requestID,change=mutation){
  const operation={format:1,kind:'load-balance-stream-control-v1',request_id:id,actor_id:actorID,mutation:change};
  return {created_at:'2026-10-26T00:00:00Z',operation,access_revision:1,manifest_sha256:'1'.repeat(64),state};
}
export function workspace(entries=[],generation=0){return {format:1,version:'1.9.0',available:true,state:generation?(entries.some(e=>!e.removed)?'running':'stopped'):'empty',detail:'Synthetic configuration observation; not native traffic or business health.',bind_address:'127.0.0.1',configuration_verified:generation>0,generation,request_id:generation?requestID:'',configuration_sha256:generation?'3'.repeat(64):'',entries,available_memory_bytes:4*1024**3,memory_high_bytes:generation?128*1024**2:0,memory_max_bytes:generation?384*1024**2:0,retiring_workers:0};}
