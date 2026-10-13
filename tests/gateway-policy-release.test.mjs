import test from 'node:test';
import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import {createHash} from 'node:crypto';
const read=p=>readFile(new URL('../'+p,import.meta.url),'utf8');
test('ordinary upgrade gateway policy is frozen, CI-checked and scoped actual acceptance retains original failure',async()=>{
 const inputs=JSON.parse(await read('panel-integration/release-source-inputs.json')),index=JSON.parse(await read('panel-integration/source-sha256.json'));
 assert.equal(inputs.frozen_inputs_sha256,'5411b3087db37b56677b8906865896802ec772390a7179f54af50415c5677457');
 assert.equal(inputs.archive_sha256,'1b48dab44be6513c434203544ce5048aa1cab88031fed17cf4bd1c7216af1d0b');
 for(const file of ['packaging/install.sh','packaging/test_install_gateway_policy.py']){
  const digest=createHash('sha256').update(await read('panel-integration/'+file)).digest('hex');
  assert.equal(inputs.files[file],digest);assert.equal(index.files[file],digest);
 }
 const installer=await read('panel-integration/packaging/install.sh');
 assert(installer.includes('if ((FRESH));then systemctl enable nginx;fi'));
 assert(installer.includes('restart_release_services || FAILED=1'));
 const previous=installer.slice(installer.indexOf('restart_previous_services(){'),installer.indexOf('\nsystemctl daemon-reload'));
 assert(previous.includes('systemctl restart panel-terminal panel-terminal-root panel-executor panel'));
 assert(!previous.includes('systemctl restart panel-terminal panel-terminal-root panel-executor panel nginx'));
 const workflow=await read('.github/workflows/verify.yml');
 assert(workflow.includes("-p 'test_install_gateway_policy.py'"));assert(workflow.includes('--experimental-strip-types --test panel-integration/scripts/test-outbound-source-view.mjs'));
 const c=JSON.parse(await read('registry/functional-contracts.json')),r=c.previous_gateway_release,old=c.previous_source_release;
 assert.equal(r.release,'0.1.0-dev.proapps24gatewaybefa');assert.equal(r.normal_build_python_tests,56);assert.equal(r.exported_normal_source_files,1202);
 assert.equal(r.actual_signed_ordinary_upgrade_passed,true);assert.equal(r.actual_ordinary_upgrade_baseline_saved_before_mutation,true);assert.equal(r.actual_ordinary_upgrade_original_sql_tables_compared,18);
 assert.equal(r.actual_ordinary_upgrade_nginx_master_and_service_state_preserved,true);assert.equal(r.actual_signed_ordinary_upgrade_proof_sha256,'360f9da90744a62b6381cb57bd18370ea4a76d4b228469cc1dc3b692a1abab10');
 assert.equal(old.actual_signed_upgrade_verification_passed,false);assert.equal(old.immediate_failed_upgrade_full_baseline_saved,false);assert.equal(old.retained_failed_upgrade_proof_sha256,'786a5d42e6e57cc3e8bb61d41bc7ca2a721bb5e16e7c665690963b0efa19db1d');
 assert.equal(old.read_only_upgrade_forensics_proof_sha256,'2102c512648295196ebf4403d8362930880d4f22ac1dae9bd930a60c8cb02ee5');assert.equal(old.actual_normal_executor_companion_passes,634);
 assert.equal(c.commercial_feature_parity_complete,false);assert.equal(r.all_50_commercial,false);assert.equal(r.main_release_delivered,false);
});
