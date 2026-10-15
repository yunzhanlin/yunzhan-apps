import test from 'node:test';
import assert from 'node:assert/strict';
import {readFile,lstat,readdir} from 'node:fs/promises';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
import {sha256} from '../tools/lib.mjs';

const root=fileURLToPath(new URL('../',import.meta.url));
const read=p=>readFile(path.join(root,p));
const json=async p=>JSON.parse(await read(p));
const index='registry/disk-host-installed-diagnostic-acceptance.json';
const program='0.1.0-dev.proapps24diskdiagbfrc';
const inputs='d5f48fbfbe9ebae8054b28468276beca28d9b5de8870e362a65cc46e4f528c68';
const oldFailure='da6afef0660f5a8522ce3011247e57392b4f90b6c843e822ed46e6b552d4c295';
const manager={file:'AppModuleManager-Hca6S3hl.js',sha256:'ada1bb95b6156e6175d69d01f55aeec66ca3be78fcf7cae094129a8d8a26fe48'};
const policy={capabilities:'CAP_DAC_READ_SEARCH',no_new_privileges:true,cpu_max:'20000 100000',memory_max:'536870912',memory_swap_max:'0',pids_max:'32'};

async function evidence(){
 const r=await json(index),out={};
 assert.equal(r.program,program);assert.equal(r.source_inputs_sha256,inputs);
 assert.equal(r.evidence_root,'registry/reviewed-disk-diagnostics/24bfrc-installed');
 assert.deepEqual((await readdir(path.join(root,r.evidence_root))).sort(),Object.keys(r.evidence_sha256).sort());
 assert.equal(Object.keys(r.evidence_sha256).length,6);
 for(const [name,pin]of Object.entries(r.evidence_sha256)){
  assert.match(name,/^[a-z0-9.-]+\.json$/);assert.match(pin,/^[a-f0-9]{64}$/);
  const file=r.evidence_root+'/'+name,stat=await lstat(path.join(root,file)),bytes=await read(file);
  assert(stat.isFile()&&!stat.isSymbolicLink()&&stat.size<16384);assert.equal(sha256(bytes),pin);
  assert.doesNotMatch(bytes.toString(),/BEGIN (?:EC |RSA |OPENSSH )?PRIVATE KEY|\/Volumes\/|\/var\/lib\/|\/srv\/|"(?:password|csrf|token|username|credentials|actor_id|owner_id|site_id|key)"/);
  const e=JSON.parse(bytes);assert.equal(e.program,program);assert.equal(e.source_inputs_sha256,inputs);assert.equal(e.commercial_all50,false);assert.match(e.original_proof_sha256,/^[a-f0-9]{64}$/);out[name]=e;
 }
 return{r,e:out};
}

test('installed evidence appends to exact approved source without rewriting the original source-stage or failed acceptance',async()=>{
 const {r,e}=await evidence();
 assert.equal(r.historical_candidate,'registry/disk-host-diagnostic-candidate.json');
 assert.equal(r.historical_candidate_sha256,'b34fd3994562b50599290471c51b6d3a30bbec15fdfa01dae22c54ed29482496');
 assert.equal(sha256(await read(r.historical_candidate)),r.historical_candidate_sha256);
 const old=await json(r.historical_candidate);assert.equal(old.candidate_program_deployed,false);assert.equal(old.amd_fault_recovery_proven,false);assert.equal(old.actual_larger_amd_scan_fixed,false);
 assert.equal(r.source_export,old.source_export);assert.equal((await json(r.source_export+'/source-sha256.json')).release.frozen_inputs_sha256,inputs);
 assert.equal(sha256(await read('dist/catalog-v1.json')),r.catalog_sha256_unchanged);
 assert.equal(sha256(await read('dist/apps/disk-analysis/1.4.0/manifest.json')),r.disk14_manifest_sha256_unchanged);
 const c=e['source-ci-and-merge.json'];assert.equal(c.head,'e8196a1646f520a8ebaa07af215d0b0f49b0a1eb');assert.equal(c.merge_commit,'6081184d7645729dc2501baccdaf093ef94a2903');assert.equal(c.check_run_id,116501017679);assert.equal(c.run_id,38757872902);assert.equal(c.check_status,'completed');assert.equal(c.conclusion,'success');assert.equal(c.has_more,false);assert.deepEqual(c.statuses,[]);assert.equal(c.matched_head_normal_merge,true);
});

test('both real normal signed program-only upgrades preserve original applications, sites and all native receipt history',async()=>{
 const {e}=await evidence(),old=await json('registry/disk-host-diagnostic-candidate.json');
 for(const arch of ['arm64','amd64']){
  const u=e['actual-normal-signed-upgrade-'+arch+'.json'];assert.equal(u.arch,arch);assert(u.ok&&u.original_key_verified&&u.check_run_launcher_verified);assert.equal(u.archive_sha256,old.normal_original_key_archives[arch]);assert.equal(u.journal_phase,'committed');assert.equal(u.pending,false);assert.match(u.journal_sha256,/^[a-f0-9]{64}$/);assert.match(u.executor_sha256,/^[a-f0-9]{64}$/);
  assert.equal(u.apps,20);assert.equal(u.sites,arch==='arm64'?82:96);assert.equal(u.protected_table_projections,97);assert(u.protected_files>400);assert(u.nginx_master_unchanged&&u.original_host_history_and_receipts_unchanged&&u.genuine_installation_epoch_preserved);assert.equal(u.disk_app_version,'1.4.0');assert.equal(u.application_installs_updates,0);assert.equal(u.host_dispatches,0);assert.equal(u.main_updated,false);
 }
});

test('successful new65536-file native scan with concurrent audit does not promote the original genuine failure into a causal fix',async()=>{
 const {r,e}=await evidence(),s=e['actual-large-scan-amd64.json'];assert(s.ok&&s.terminal_verified);assert.equal(s.arch,'amd64');assert.equal(s.original_scans,1);assert.equal(s.replayed,false);assert.equal(s.state,'complete');assert.equal(s.error_code,'');assert(s.enumeration_complete&&s.index_flushed);assert.deepEqual(s.partial_reasons,[]);
 assert.equal(s.original_proof_sha256,'ef162954ca13b6a5c79ddac66e7fbb2d4a9283d50e9194ed29d7d22a7e9ccfe7');assert.match(s.original_result_sha256,/^[a-f0-9]{64}$/);
 assert.equal(s.metadata_entries_read,'66048');assert.equal(s.regular_file_entries,'65536');assert.equal(s.unique_regular_files,'65536');assert.equal(s.directory_entries,'513');assert.equal(s.inode_allocated_bytes,'2113536');assert.deepEqual(s.independent_reference,{directories:513,regular_files:65536,entries:66049,logical_bytes:0,allocated_bytes:2113536});assert(s.concurrent_original_readonly_audit_verified);
 assert(s.worker_exited&&s.scope_empty&&s.both_leases_free&&s.database_exact);assert.equal(s.result_audits,1);assert(s.old_history_preserved&&s.actual_ui_and_exact_json_export_verified);assert.deepEqual(s.manager_asset,manager);assert.deepEqual(s.policy,policy);assert.equal(s.old_failure_result_sha256,oldFailure);
 assert.equal(s.snapshot_consistent,false);assert.equal(s.exclusive_physical_bytes,false);assert.equal(s.matched_diagnostic_lines,0);for(const k of ['installed_failure_diagnostic_capture_verified','original_failure_cause_proven','original_failure_fixed'])assert.equal(s[k],false,k);assert.equal(r.original_failure_fixed,false);
 const bad=await json('registry/reviewed-disk-diagnostics/24bfrc/retained-real-larger-scan-failure-amd64.json');assert.equal(bad.original_result_sha256,oldFailure);assert.equal(bad.state,'failed');assert.equal(bad.metadata_entries_read,'11904');assert.equal(bad.success_claimed,false);assert.equal(bad.rewritten,false);
});

test('same signed installed program on both architectures seals a real interrupted failure without any fabricated result or export',async()=>{
 const {e}=await evidence();
 const pins={amd64:{proof:'07ba62002092147b347888f54f17dd9daade8ff96e935df5047d4b13d13e71a3',closure:'4f16cf61db207e01f9ba6f3c944315695c3bef28af9cb54bacf5be058f479986'},arm64:{proof:'eed8cd635d7fede4bcab1fb41defdac82c84ef203ec28ad2b662cc1f3ac4b95b',closure:'b2fe597c38e6ebdf67ec6c02e9674c3a6905ecf7a3d933dc3a07e4ed54d7ae6e'}};
 for(const arch of ['arm64','amd64']){
  const c=e['actual-native-interruption-'+arch+'.json'];assert(c.ok&&c.matched_original_pidfd_signal&&c.recovery_metadata_only);assert.equal(c.original_proof_sha256,pins[arch].proof);assert.equal(c.original_closure_sha256,pins[arch].closure);assert.equal(c.arch,arch);assert.equal(c.signal,'SIGKILL');assert.equal(c.original_scan_posts,1);assert.equal(c.original_recovery_posts,1);assert.equal(c.recovery_signal_requested,false);assert.equal(c.state,'failed');assert.equal(c.closure_kind,'interrupted');
  assert(c.terminal_verified&&c.report_unavailable&&c.admission_sealed&&c.result_absent);assert(c.worker_exited&&c.scope_empty&&c.both_leases_free&&c.database_exact);assert.equal(c.close_audits,1);assert.equal(c.result_audits,0);assert(c.actual_ui_no_host_report_export&&c.old_history_and_root_receipts_preserved&&c.original_apps_sites_accounts_and_fixtures_preserved);assert.deepEqual(c.manager_asset,manager);assert.deepEqual(c.policy,policy);assert.equal(c.app_manifest_sha256,(await json(index)).disk14_manifest_sha256_unchanged);assert.equal(c.application_installs_updates,0);assert.equal(c.files_deleted,0);
 }
});

test('native QA milestones remain separate from Main delivery, unknown original cause and all50 commercial acceptance',async()=>{
 const {r}=await evidence();for(const k of ['historical_candidate_unmodified','source_ci_merged','normal_program_only_signed_upgrade_both','actual_large_amd_scan_passed','same_program_interruption_recovery_both'])assert.equal(r[k],true,k);
 for(const k of ['installed_failure_diagnostic_capture_verified','original_failure_cause_proven','original_failure_fixed','large_arm_scan_verified','main_delivered','main_absent_apps_installed','all_os_verified','physical_host_verified','extended_soak_complete','mobile_devices_verified','commercial_all50'])assert.equal(r[k],false,k);
 assert(r.remaining.length>=4);assert(r.remaining.some(x=>x.includes('Permission revocation')));assert(r.remaining.some(x=>x.includes('all other50')));
});
