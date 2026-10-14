// Source/evidence integrity; native/installed observations were performed
// separately and are not manufactured or rerun by these metadata assertions.
import test from 'node:test';
import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import {createHash} from 'node:crypto';
const read=p=>readFile(new URL('../'+p,import.meta.url));
const sha=b=>createHash('sha256').update(b).digest('hex');
test('historical secret lifetime fix retains exact signed BFCR inputs and immutable BFAW and failed BFCL identities',async()=>{
 const r=JSON.parse(await read('registry/platform-maintenance-secret-release.json'));
 const current=JSON.parse(await read('registry/reviewed-sources/0.1.0-dev.proapps24maintsecretbfcr/source-sha256.json'));
 assert.equal(sha(await read('registry/reviewed-sources/0.1.0-dev.proapps24maintsecretbfcr/source-sha256.json')),'faa56c16d142eb5a10a25e728ede59cdeecea43e601a6710265237cf2219b9cc');
 assert.equal(sha(await read('registry/reviewed-sources/0.1.0-dev.proapps24maintsecretbfcr/release-source-inputs.json')),'97c10c489ccca6bee828f4e147fd0c1b7fa76ea305333ea44c9fedb16411f628');
 const oldRaw=await read('registry/reviewed-sources/0.1.0-dev.proapps24maintuibfaw/source-sha256.json'),old=JSON.parse(oldRaw);
 assert.equal(sha(oldRaw),'17400c7188cbe3e9b9506d17279a9430ec687a462fe5899d04acef91fe0e5517');
 assert.equal(sha(await read('registry/reviewed-sources/0.1.0-dev.proapps24maintuibfaw/release-source-inputs.json')),'678ac3a5b0b8ce68f5d7c6fbba543b128e3a28dd75208f98a4477c5598d5e7a3');
 assert.equal(current.release.frozen_inputs_sha256,r.source_inputs_sha256);assert.equal(current.release.archive_sha256,r.normal_original_key_archives.amd64);assert.equal(current.release.archive,'panel-'+r.program+'-linux-amd64.tar.gz');assert.equal(Object.keys(current.files).length,1309);assert.deepEqual(current.test_overrides??{},{});
 assert.deepEqual(Object.keys(current.files).filter(k=>old.files[k]!==current.files[k]).sort(),['packaging/build-release.sh','scripts/test-platform-maintenance-secrets.mjs','web/src/PlatformMaintenance.vue']);assert.deepEqual(Object.keys(old.files).filter(k=>!(k in current.files)),[]);
 assert.deepEqual(r.only_source_changes,['packaging/build-release.sh','scripts/test-platform-maintenance-secrets.mjs','web/src/PlatformMaintenance.vue']);assert.equal(r.source_overrides,0);assert.equal(r.app_version_unchanged,'1.3.0');assert.equal(r.key_replaced,false);
 assert.equal(r.original_program_public_key_sha256,'4ccfcc861d56a41e3ba7f7ace7e2432c815f366c58448d783df92c6632f01339');assert.equal(r.retained_failed_cohort.original_failure_rewritten,false);assert.equal(r.retained_failed_cohort.normal_archives_produced,false);assert.equal(r.historical_24bfce_acceptance_rewritten,false);
 const code=(await read('panel-integration-geography/web/src/PlatformMaintenance.vue')).toString();
 for(const needle of ['function hideSecret()','function displaySecret(','clearTimeout(secretTimer)','if(secretGrantID===id)hideSecret()','current.revoked','current.legacy_unbound','current.expires_at*1000<=Date.now()','current.installation_id!==props.installationId','current.owner_id!==props.access?.user_id','hideSecret();error.value='])assert(code.includes(needle),needle);
 assert(!code.includes('localStorage')&&!code.includes('sessionStorage'));
 const build=(await read('panel-integration-geography/packaging/build-release.sh')).toString();assert(build.includes('node --test scripts/test-platform-maintenance-secrets.mjs'));assert(build.includes('npm run build) 2>&1 | tee'));assert(!build.includes('npm run build >/dev/null'));
 const ci=(await read('.github/workflows/verify.yml')).toString();assert(ci.indexOf('npm ci --prefix panel-integration-geography/web --ignore-scripts')<ci.indexOf('node --test panel-integration-geography/scripts/test-platform-maintenance-secrets.mjs'));
});
test('new original program transaction and installed external-revocation UI acceptance remain separate from old native commands and full commercial qualification',async()=>{
 const r=JSON.parse(await read('registry/platform-maintenance-secret-release.json'));
 for(const [name,pin]of Object.entries(r.actual_program_upgrade.program_artifacts)){
  const raw=await read('registry/reviewed-maintenance/24bfcr/'+name),p=JSON.parse(raw);assert.equal(sha(raw),pin);assert.equal(p.ok,true);assert.equal(p.version,r.program);assert.equal(p.source_inputs_sha256,r.source_inputs_sha256);assert.equal(p.archive_sha256,r.normal_original_key_archives.arm64);assert.equal(p.sites,82);assert.equal(p.app_records,20);assert.equal(p.protected_files_unchanged,708);assert.equal(p.protected_table_projections_unchanged,94);assert.equal(p.preserved_native_operations,1);assert.equal(p.application_installs_updates,0);assert.equal(p.native_commands,0);assert.equal(p.nginx_master_pid,'981');
  if(name==='program-run.json')assert.equal(p.journal_sha256,r.actual_program_upgrade.journal_sha256);
 }
 assert.deepEqual([r.verification.compiled_actual_setup_tests,r.verification.failures,r.verification.skips,r.verification.isolated_actual_vue_checks],[16,0,0,9]);
 const ui=r.actual_installed_ui;assert.equal(ui.passed,true);assert.equal(ui.checks,4);assert.equal(ui.grant_revoked,true);assert.equal(ui.live_inventory_retains_secret,true);assert.equal(ui.external_normal_csrf_revocation_then_read_refresh_hides_secret,true);assert.equal(ui.unexpected_page_errors,0);assert.equal(ui.elapsed5min_expiry_verified,false);
 assert.equal(ui.exact_loaded_manager_sha256,'c4bc034b1faadc66e7f866b59f492bc5ae207b081c496dc3cbfa63282c790034');
 for(const key of ['commercial_all50','platform_ops_commercial','main_delivered'])assert.equal(r[key],false,key);
 assert.equal(r.behavior.mutation_on_refresh,false);assert.equal(r.behavior.regenerate_token_on_refresh,false);assert.equal(r.behavior.secret_persisted_in_browser,false);
 assert(r.remaining.some(s=>s.includes('not installed new-UI proof')));assert(r.remaining.some(s=>s.includes('not repeated')||s.includes('no repeated')));
 const original=JSON.parse(await read('registry/reviewed-maintenance/24bfce/index.json'));assert.equal(original.installed_ui.display_gap_fix_installed_at_this_snapshot,false);assert.equal(original.native_commands,4);
});
