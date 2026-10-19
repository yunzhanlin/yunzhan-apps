import {preAnalyticsWorkflowRead} from './pre-analytics-workflow.mjs';
import test from 'node:test';import assert from 'node:assert/strict';import fs from 'node:fs';import path from'node:path';import{fileURLToPath}from'node:url';import{createHash}from'node:crypto';
// Escaped systemd filenames contain literal backslashes; URL resolution would
// incorrectly interpret those bytes as path separators. Hash the real path.
const root=fileURLToPath(new URL('../',import.meta.url)),read=p=>preAnalyticsWorkflowRead(p,fs.readFileSync(path.join(root,p))),sha=b=>createHash('sha256').update(b).digest('hex');
test('file-management and ordinary development dispatch export is exact immutable normal source, never all50 acceptance',()=>{
 const index=JSON.parse(read('panel-integration-file-manager/source-sha256.json')),release=JSON.parse(read('panel-integration-file-manager/release-source-inputs.json')),record=JSON.parse(read('registry/file-manager-foundation-release.json'));
 assert.equal(record.version,'0.1.0-dev.proapps24devdispatchbgmu');assert.equal(record.frozen_inputs_sha256,'5d879e399b73ed741c39ac8551c8a2f0b2acd2e67e1eeb52aec954ec1b6fc864');
 assert.equal(release.frozen_inputs_sha256,record.frozen_inputs_sha256);assert.equal(index.release.frozen_inputs_sha256,record.frozen_inputs_sha256);assert.equal(release.archive_sha256,record.normal_original_key_archives.amd64);assert.deepEqual(index.files,release.files);assert.deepEqual(index.test_overrides,{});assert.equal(Object.keys(index.files).length,1503);
 for(const[file,digest]of Object.entries(index.files)){assert.equal(sha(read('panel-integration-file-manager/'+file)),digest,file);assert(!file.split('/').some(part=>['node_modules','.local','.git'].includes(part)),file);}
 assert.equal(record.commercial_all50,false);assert.equal(record.physical_mobile_acceptance,false);assert.equal(record.external_WebDAV_or_mail_provider_acceptance,false);assert.equal(record.actual_power_loss_acceptance,false);
 assert.equal(record.local_complete_go_regression.passed,2564);assert.equal(record.local_complete_go_regression.explicit_skips,11);
 for(const arch of['arm64','amd64']){assert.equal(record.Root_Linux_source_fixtures[arch].passed,119);assert.equal(record.Root_Linux_source_fixtures[arch].failed,0);assert.equal(record.Root_Linux_source_fixtures[arch].skipped,0);assert.match(record.Root_Linux_source_fixtures[arch].events_sha256,/^[a-f0-9]{64}$/);}
 assert.equal(record.native_rollback_or_reboot_claim_from_source_fixtures,false);assert.equal(record.original_failed_QA_receipts_relabelled,false);
});
test('actual exported Vue scope reset and original installed data boundaries are retained',()=>{
 const component=read('panel-integration-file-manager/web/src/FileManager.vue').toString(),install=read('panel-integration-file-manager/packaging/install.sh').toString(),test=read('panel-integration-file-manager/scripts/test-file-manager-scope.mjs').toString();
 for(const value of['fileDialogCurrent','resetSharedFileDialogs','canUseSharedInfrastructure','fileDialogEpoch','当前账户暂无已授权的可管理网站'])assert(component.includes(value),value);
 for(const value of['late completion','replacement account','closing clears entered password','same-scope'])assert(test.includes(value),value);
 assert(install.includes('exec python3 "$HERE/development-upgrade.py" "$DEVELOPMENT_ACTION" "$HERE"'));
 assert(install.indexOf('DEVELOPMENT_MARKER=')<install.indexOf('existing host configuration blocks first install'));
 assert(install.includes('[[ ! -e "$MARKER" && ! -L "$MARKER" && ! -e "$CURRENT" && ! -L "$CURRENT" ]]'));
 const record=JSON.parse(read('registry/file-manager-foundation-release.json'));
 assert.equal(record.actual_Main_delivery.ok,true);assert.equal(record.actual_Main_delivery.original_sites,58);assert.equal(record.actual_Main_delivery.original_modules,4);assert.equal(record.actual_Main_delivery.original_business_projections,97);assert.equal(record.actual_Main_delivery.exact_new_empty_tables,4);assert.equal(record.actual_Main_delivery.application_operations,0);
});
test('all historical CI bytes and original assertions remain before appended exact-source gates',()=>{
 const workflow=read('.github/workflows/verify.yml'),marker=Buffer.from('      - name: File manager and development dispatch complete Root Linux contracts (source only)'),at=workflow.indexOf(marker);assert(at>0);assert.equal(sha(workflow.subarray(0,at)),'97b9d24d9536efcf92331c8e1ad26e99a49416c6085f26d65df53ff03076bd12');
 const appended=workflow.subarray(at).toString();for(const gate of['sudo "$(command -v go)" test -p 1 ./... -count=1','test_program_queue_diagnostics test_production_upgrade test_development_upgrade_safety test_install_development_dispatch test_install_dependency_policy test_install_gateway_policy','scripts/test-file-manager-scope.mjs','scripts/web-entry-budget.mjs'])assert(appended.includes(gate),gate);
});
