// Integrity and interpretation of copied original evidence, NOT a CI rerun of
// installed panels, TLS or native Nginx commands.
import test from 'node:test';
import assert from 'node:assert/strict';
import {readFile,readdir,lstat} from 'node:fs/promises';
import {createHash} from 'node:crypto';
const directory=new URL('../registry/reviewed-maintenance/24bfce/',import.meta.url);
const read=name=>readFile(new URL(name,directory));
const sha=b=>createHash('sha256').update(b).digest('hex');
const index=JSON.parse(await read('index.json'));
function nativeRequestSHA(r){
 const op=r.input;
 return sha(JSON.stringify({format:r.format,grant_id:r.grant_id,actor_id:r.actor_id,input:{request_id:op.request_id,command:op.command,expected_plan_sha256:op.expected_plan_sha256,confirm:op.confirm}}));
}
test('copied original4 native request/terminal pairs bind exact fixed commands, identities and original SHA, with no token or arbitrary command fields',async()=>{
 assert.equal(index.passed,true);assert.equal(index.native_commands,4);assert.equal(index.remote_command_posts,4);assert.equal(index.status_inspections,1);
 assert.equal(index.operations.length,4);assert.equal(new Set(index.operations.map(o=>o.request_id)).size,4);
 const expected=['amd:nginx-check:config_valid','amd:nginx-reload:reload_signal_submitted','amd:nginx-reload:reload_signal_submitted','arm:nginx-check:config_valid'];
 assert.deepEqual(index.operations.map(o=>[o.target,o.command,o.outcome].join(':')),expected);
 assert.deepEqual((await readdir(directory)).sort(),['index.json',...Object.keys(index.artifacts)].sort());assert.equal(Object.keys(index.artifacts).length,12);
 for(const [name,artifact]of Object.entries(index.artifacts)){
  assert.match(name,/^[a-z0-9.-]+$/);const file=new URL(name,directory),s=await lstat(file);assert(s.isFile()&&!s.isSymbolicLink());assert.equal(sha(await read(name)),artifact.sha256,name);
 }
 for(const op of index.operations){
  const started=JSON.parse(await read(op.request_id+'.request.json')),done=JSON.parse(await read(op.request_id+'.result.json'));
  for(const row of [started,done]){
   assert.deepEqual(Object.keys(row).sort(),['format','outcome','request','request_sha256','state']);assert.equal(row.format,1);
   assert.deepEqual(Object.keys(row.request).sort(),['actor_id','format','grant_id','input']);assert.equal(row.request.format,1);assert.match(row.request.grant_id,/^[a-f0-9]{64}$/);assert.match(row.request.actor_id,/^[a-f0-9]{32}$/);
   const input=row.request.input;assert.deepEqual(Object.keys(input).sort(),['command','confirm','expected_plan_sha256','request_id']);assert.equal(input.request_id,op.request_id);assert.equal(input.command,op.command);assert.equal(input.expected_plan_sha256,op.plan_sha256);
   assert.equal(input.confirm,op.command==='nginx-reload'?'RELOAD NGINX '+op.plan_sha256:'');assert.equal(nativeRequestSHA(row.request),op.request_sha256);assert.equal(row.request_sha256,op.request_sha256);
  }
  assert.deepEqual(done.request,started.request);assert.equal(started.state,'started');assert.equal(started.outcome,'unknown');assert.equal(done.state,'completed');assert.equal(done.outcome,op.outcome);
 }
});
test('retained transport log proves original completed reload response was dropped then only original GET-observed, not fabricated or retransmitted',async()=>{
 const trace=(await read('original-transport-loss.jsonl')).toString().trim().split('\n').map(s=>JSON.parse(s));
 assert.equal(trace.length,4);assert(trace.every(t=>t.actual_core_upstream===true));
 const writes=trace.filter(t=>t.method==='POST'),drops=trace.filter(t=>t.response_dropped);assert.equal(writes.length,1);assert.equal(drops.length,1);assert.equal(writes[0],drops[0]);
 const op=index.operations.find(o=>o.response_lost);assert.equal(op.request_id,'375a4c8beadbe2332daedeb5835f6057');assert.equal(op.submit_http,503);assert.equal(op.status_inspections,1);assert.equal(op.receipt_verified,true);
 assert.equal(drops[0].request_id,op.request_id);assert.equal(drops[0].original_http_status,200);assert.equal(drops[0].original_state,'completed');assert.equal(drops[0].original_outcome,'reload_signal_submitted');
 const terminal=await read(op.request_id+'.result.json');assert.equal(drops[0].original_response_sha256,sha(Buffer.concat([terminal,Buffer.from('\n')])));
 assert.deepEqual(trace.filter(t=>t.method==='GET'&&t.path.includes('/commands/')).map(t=>t.path),['/api/platform-maintenance/commands/'+op.request_id]);
 assert.equal(index.authority.automatic_mutation_retry,false);assert.equal(index.authority.original_id_changed_after_loss,false);assert.equal(index.authority.fake_api_results,false);assert.equal(index.authority.production_test_override,false);
});
test('actual selected original-key1.3 updates and temporary cleanup cannot rewrite the earlier publication or claim all50/Main/public-network qualification',async()=>{
 const update=JSON.parse(await read('amd-original-signed-app-update.json')),u=index.genuine_signature_update;
 assert.equal(update.ok,true);assert.equal(update.old_version,'1.0');assert.equal(update.new_version,'1.3.0');assert.equal(update.original_job_id,u.amd.job);assert.equal(update.installation_id,u.amd.instance);assert.equal(update.manifest_sha256,u.manifest_sha256);
 assert.notEqual(u.arm.instance,u.amd.instance);assert.equal(update.actual_update_hint_cleared,true);assert.equal(update.original_job_receipt_verified,true);assert.equal(update.other19_records_unchanged,true);assert.equal(update.settings_install_time_preserved,true);assert.equal(update.app_installs,0);assert.equal(update.native_commands,0);assert.equal(update.previous_failure_rewritten,false);
 const catalog=await readFile(new URL('../dist/catalog-v1.json',import.meta.url)),pub=await readFile(new URL('../signatures/catalog-v1.pub.pem',import.meta.url));assert.equal(sha(catalog),u.catalog_sha256);assert.equal(sha(pub),u.publisher_public_key_sha256);
 assert.equal(sha(await readFile(new URL('../dist/apps/platform-ops/1.3.0/manifest.json',import.meta.url))),u.manifest_sha256);
 const publication=JSON.parse(await readFile(new URL('../registry/platform-maintenance-app-release.json',import.meta.url)));assert.equal(publication.installed_app_update_verified_at_publication,false);assert.equal(u.publication_snapshot_rewritten,false);
 for(const name of ['arm','amd']){
  const c=JSON.parse(await read(name+'-cleanup.json'));assert.equal(c.ok,true);assert.equal(c.original_ca_bundle_restored,true);assert.equal(c.native_receipts_deleted,false);assert.equal(c.temporary_public_files_removed,2);assert.equal(c.main_mutated,false);
 }
 for(const key of ['commercial_all50','platform_ops_commercial','main_delivered'])assert.equal(index[key],false,key);
 assert.equal(index.preserved.sql_sites,178);assert.equal(index.preserved.app_records,40);assert.deepEqual(index.preserved.nginx_master_pids,[981,1039]);assert.equal(index.grants_issued_and_revoked,2);
 assert.equal(index.cleanup.pinned_ssh_tunnels_stopped,true);assert.equal(index.cleanup.original_system_ca_bundles_byte_restored,true);
 assert.equal(index.installed_ui.display_gap_fix_installed_at_this_snapshot,false);assert(index.boundaries.some(s=>s.includes('not public-network')));assert(index.boundaries.some(s=>s.includes('not native bare-metal')));assert(index.boundaries.some(s=>s.includes('not all sites')));
});
