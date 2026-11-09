import assert from 'node:assert/strict';
import {test} from 'node:test';
import fs from 'node:fs';
import path from 'node:path';
import {fileURLToPath,pathToFileURL} from 'node:url';
const root=path.resolve(path.dirname(fileURLToPath(import.meta.url)),'..');
const ts=await import(pathToFileURL(path.join(root,'web/node_modules/typescript/lib/typescript.js')).href);
const data=code=>'data:text/javascript;base64,'+Buffer.from(code).toString('base64');
const compile=name=>ts.transpileModule(fs.readFileSync(path.join(root,'web/src',name),'utf8'),{compilerOptions:{target:ts.ScriptTarget.ES2022,module:ts.ModuleKind.ESNext}}).outputText;
const menu=data(compile('menuPermissions.ts'));
let source=compile('remoteIndependentBackup.ts').replaceAll("'./menuPermissions'",JSON.stringify(menu));
for(const dep of ['@noble/hashes/sha2.js','@noble/hashes/utils.js'])source=source.replaceAll("'"+dep+"'",JSON.stringify(pathToFileURL(path.join(root,'web/node_modules',dep)).href));
const b=await import(data(source)),m=await import(menu),{createHash}=await import('node:crypto');
const hash=bytes=>createHash('sha256').update(bytes).digest('hex'),clone=v=>structuredClone(v);
const bytes=Buffer.alloc(b.independentChunkBytes+3,0x61),actor='1'.repeat(32),tx='2'.repeat(32);
const file={name:'staged',bytes:bytes.length,sha256:hash(bytes)};
const row={remote_target_id:'owned-target',backup_transaction_id:tx,revision:7,source_snapshot_sha256:'a'.repeat(64),copy_intent_sha256:'b'.repeat(64),copy_state_sha256:'c'.repeat(64),independent_copy_state:'committed',copy_bytes:bytes.length,retained_bytes:bytes.length,retained_attempts:1,created_at:'2026-11-05T01:02:03Z',completed_at:'2026-11-05T01:02:04Z',content_verified:true,pending_recovery:false,files:[file]};
const src={remote_target_id:row.remote_target_id,backup_transaction_id:tx,revision:7,backup_snapshot_sha256:row.source_snapshot_sha256,backup_archive_state:'committed',backup_bytes:bytes.length,content_verified:true,pending_recovery:false};
function server(edit=()=>{}){let calls=0;const api=async p=>{const part=Number(p.match(/chunks\/(\d+)/)?.[1]);assert.equal(p,`/app-modules/files-sync/independent-backups/${row.remote_target_id}/${tx}/staged/chunks/${part}?sha=${row.copy_intent_sha256}`);const data=bytes.subarray(part*b.independentChunkBytes,(part+1)*b.independentChunkBytes);const chunk={remote_target_id:row.remote_target_id,backup_transaction_id:tx,name:'staged',intent_sha256:row.copy_intent_sha256,file_sha256:file.sha256,file_bytes:file.bytes,part,data:data.toString('base64'),chunk_sha256:hash(data),files_changed:false};edit(chunk,part);calls++;return chunk};return {api,calls:()=>calls}}
test('complete copy and full administrator identities are verified',()=>{
 assert(b.independentCopyValid(row,row.remote_target_id,7));
 assert(b.independentFullAdministrator({role:'admin',menu_ids:[...m.menuPermissionIDs]}));
 assert(!b.independentFullAdministrator({role:'admin',menu_ids:['system-tools']}));
 assert(!b.independentFullAdministrator({role:'viewer',menu_ids:[...m.menuPermissionIDs]}));
});
for(const [name,edit]of Object.entries({other_target:v=>v.remote_target_id='other-target',wrong_transaction:v=>v.backup_transaction_id='../source',old_revision:v=>v.revision=6,partial_as_success:v=>v.independent_copy_state='needs-review',invented_state:v=>v.independent_copy_state='saved',lost_digest:v=>v.copy_state_sha256='',duplicate_files:v=>v.files.push(clone(file)),wrong_size:v=>v.copy_bytes++,unbounded_attempts:v=>v.retained_attempts=9,unknown_recovery:v=>v.pending_recovery=true,stale_time:v=>v.completed_at='2026-11-04T00:00:00Z',unsafe_filename:v=>v.files[0].name='../other'}))test('rejects unbound copy: '+name,()=>{const v=clone(row);edit(v);assert(!b.independentCopyValid(v,row.remote_target_id,7))});
test('source creation and recovery bind different original state digests',()=>{
 const pending={...clone(row),independent_copy_state:'needs-review',pending_recovery:true,content_verified:false,completed_at:''};
 assert.equal(b.independentMutationBody('copy-remote-backup',src,'COPY BACKUP '+tx).expected_sha,src.backup_snapshot_sha256);
 assert.equal(b.independentMutationBody('recover-remote-copy',pending,'RECOVER COPY '+tx).expected_sha,pending.copy_state_sha256);
 assert.equal(b.independentMutationBody('retain-remote-copy',pending,'RETAIN COPY '+tx).expected_sha,pending.copy_state_sha256);
 assert.throws(()=>b.independentMutationBody('copy-remote-backup',{...src,content_verified:false},'COPY BACKUP '+tx));
 assert.throws(()=>b.independentMutationBody('recover-remote-copy',row,'RECOVER COPY '+tx));
 assert.throws(()=>b.independentMutationBody('copy-remote-backup',src,'COPY BACKUP '+tx+' '));
 assert.throws(()=>b.independentMutationBody('delete',src,'RETAIN COPY '+tx));
 assert.deepEqual(Object.keys(b.independentMutationBody('copy-remote-backup',{...src,password:'never-forward'},'COPY BACKUP '+tx)),['remote_target_id','expected_revision','resource_id','expected_sha','confirm']);
});
test('array-coerced identifiers and digests never become a valid copy or authority',()=>{
 for(const field of ['backup_transaction_id','source_snapshot_sha256','copy_intent_sha256','copy_state_sha256']){const v=clone(row);v[field]=[v[field]];assert(!b.independentCopyValid(v,row.remote_target_id,7))}
 const v=clone(row);v.files[0].sha256=[v.files[0].sha256];assert(!b.independentCopyValid(v,row.remote_target_id,7));
 assert(!b.independentSourceValid({...src,backup_snapshot_sha256:[src.backup_snapshot_sha256]},src.remote_target_id,7));
});
test('pending requests remain bound to the original actor and authority',()=>{
 const p={actor,target:row.remote_target_id,revision:7,transaction:tx,sha256:row.copy_state_sha256,action:'recover-remote-copy'};
 assert(b.independentPendingValid(p,actor));assert(!b.independentPendingValid(p,'3'.repeat(32)));assert(!b.independentPendingValid({...p,action:'remove'},actor));
});
test('download checks both chunks and the full file before returning bytes',async()=>{
 const s=server();const result=await b.independentDownload(s.api,row,file,new AbortController().signal,()=>true);
 assert.deepEqual(Buffer.from(result),bytes);assert.equal(s.calls(),2);
});
for(const [name,edit]of Object.entries({other_target:v=>v.remote_target_id='other-target',other_transaction:v=>v.backup_transaction_id='4'.repeat(32),other_file:v=>v.name='previous',other_intent:v=>v.intent_sha256='d'.repeat(64),other_file_hash:v=>v.file_sha256='e'.repeat(64),wrong_part:v=>v.part++,wrong_size:v=>v.file_bytes--,short_data:v=>v.data='',invalid_base64:v=>v.data='?'.repeat(v.data.length),wrong_chunk_hash:v=>v.chunk_sha256='0'.repeat(64),hidden_mutation:v=>v.files_changed=true}))test('download refuses forged segment: '+name,async()=>{
 const s=server(edit);await assert.rejects(b.independentDownload(s.api,row,file,new AbortController().signal,()=>true));assert.equal(s.calls(),1);
});
test('consistent malicious per-chunk hashes cannot replace the original file digest',async()=>{
 const s=server(v=>{const bytes=Buffer.from(v.data,'base64');bytes.fill(0x62);v.data=bytes.toString('base64');v.chunk_sha256=hash(bytes)});
 await assert.rejects(b.independentDownload(s.api,row,file,new AbortController().signal,()=>true),/完整文件摘要/);assert.equal(s.calls(),2);
});
test('revoked authority discards the received segment without requesting the next one',async()=>{
 let current=true;const s=server(()=>{current=false});await assert.rejects(b.independentDownload(s.api,row,file,new AbortController().signal,()=>current));assert.equal(s.calls(),1);
});
test('aborted request and unverified inventory never start download',async()=>{
 const s=server(),abort=new AbortController();abort.abort();await assert.rejects(b.independentDownload(s.api,row,file,abort.signal,()=>true));
 await assert.rejects(b.independentDownload(s.api,{...row,content_verified:false},file,new AbortController().signal,()=>true));assert.equal(s.calls(),0);
});
test('a failed second segment never returns a partial file',async()=>{
 const s=server();let calls=0;const api=async path=>{calls++;if(calls===2)throw Error('connection interrupted');return s.api(path)};
 await assert.rejects(b.independentDownload(api,row,file,new AbortController().signal,()=>true));assert.equal(calls,2);
});
test('empty original files still require one bound empty segment and exact full digest',async()=>{
 const empty={name:'previous',bytes:0,sha256:hash(Buffer.alloc(0))},copy={...row,copy_bytes:0,retained_bytes:0,files:[empty]};let calls=0;
 const api=async()=>{calls++;return {remote_target_id:row.remote_target_id,backup_transaction_id:tx,name:'previous',part:0,intent_sha256:row.copy_intent_sha256,file_sha256:empty.sha256,file_bytes:0,data:'',chunk_sha256:empty.sha256,files_changed:false}};
 assert.equal((await b.independentDownload(api,copy,empty,new AbortController().signal,()=>true)).length,0);assert.equal(calls,1);
});
