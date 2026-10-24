import test from'node:test';import assert from'node:assert/strict';import fs from'node:fs';import path from'node:path';import{createHash}from'node:crypto';import{spawnSync}from'node:child_process';import{fileURLToPath}from'node:url';
import{correctHTTPSFixture,httpsFixtureMember,originalHTTPSFixtureSHA,correctedHTTPSFixtureSHA,reviewedHTTPSFixtureScopes,extendReviewedHTTPSFixtureOverlay}from'../tools/run-https-fixture-ci.mjs';
import{originalReviewedHTTPSFixtureWorkflow,originalHTTPSWorkflow,originalHTTPSWholeCommand,reviewedHTTPSWholeCommand,originalReviewedHTTPSFixtureTest}from'./reviewed-https-fixture-workflow.mjs';
import{hardeningManifestFixtureOverlay}from'../tools/run-hardening-ci.mjs';import{intrusionFeatureFixtureOverlay}from'../tools/run-intrusion-ci.mjs';
const repo=fileURLToPath(new URL('../',import.meta.url)),sha=b=>createHash('sha256').update(b).digest('hex'),raw=fs.readFileSync(repo+'panel-integration-memcached-retirement-handler/'+httpsFixtureMember);

test('Root CI admission receives only the two explicit nonsecret GitHub markers and original sudo failures remain failures',()=>{
 const r=JSON.parse(fs.readFileSync(repo+'registry/https-fixture-sudo-ci.json'));
 assert.equal(r.previous_head,'8e68688e8c7bb553c65805337a463cad4542905c');
 assert(r.original_failures_preserved.every(v=>v.conclusion==='failure'));
 assert(r.native_sudo_proof.read_only&&r.native_sudo_proof.remote_files_written===0&&r.native_sudo_proof.programme_or_application_mutations===0);
 assert.deepEqual(r.native_sudo_proof.architectures.map(v=>v.arch).sort(),['amd64','arm64']);
 for(const proof of r.native_sudo_proof.architectures){
  assert.deepEqual(proof.original_plain_sudo,{uid:0,GITHUB_ACTIONS:null,GITHUB_REPOSITORY:null});
  assert.deepEqual(proof.explicit_allowlist,{uid:0,GITHUB_ACTIONS:'true',GITHUB_REPOSITORY:'yunzhanlin/yunzhan-apps'});
 }
 assert.deepEqual(r.correction.allowlist,['GITHUB_ACTIONS','GITHUB_REPOSITORY']);
 assert.equal(reviewedHTTPSWholeCommand,'sudo --preserve-env=GITHUB_ACTIONS,GITHUB_REPOSITORY "$(command -v node)" "$GITHUB_WORKSPACE/tools/run-https-fixture-ci.mjs" "$(command -v go)" test -p 1 ./...');
 const driver=fs.readFileSync(repo+'tools/run-https-fixture-ci.mjs','utf8');
 assert(driver.includes("assert(process.getuid()===0&&process.platform==='linux'&&process.env.GITHUB_ACTIONS==='true'&&process.env.GITHUB_REPOSITORY==='yunzhanlin/yunzhan-apps')"));
 for(const k of['old_failures_relabelled','old_jobs_retried','fresh_CI_acceptance','programme_signed','programme_installed','Main19100_mutated','all50_commercial'])assert.equal(r[k],false);
});
test('actual both-architecture Root fixture results preserve original CI and collector failures and do not claim installation',()=>{
 const r=JSON.parse(fs.readFileSync(repo+'registry/https-fixture-ci.json'));assert.equal(r.original_CI_failure.job,120962618075);assert.equal(r.original_CI_failure.conclusion,'failure');assert(r.original_CI_failure.actual_original_port_not_logged&&r.original_CI_failure.not_retried_or_relabelled);assert.equal(r.member,httpsFixtureMember);assert.equal(r.original_test_sha256,originalHTTPSFixtureSHA);assert.equal(r.corrected_test_sha256,correctedHTTPSFixtureSHA);
 for(const a of Object.values(r.actual_Root_models)){assert.equal(a.original_red_colliding_subcases_failed,3);assert.equal(a.green_top_level,6);assert.equal(a.green_including_subtests,13);assert.equal(a.green_failures,0);assert.equal(a.green_skips,0);}
 const arm=r.actual_Root_models.arm64;assert.equal(arm.original_aggregate_ok,false);assert.equal(arm.original_false_relabelled,false);assert(arm.independent_preservation_review.ok&&arm.independent_preservation_review.all_original103_business_and_hosts_preserved);assert.equal(arm.independent_preservation_review.Go_tests_reexecuted,0);assert(arm.independent_preservation_review.elapsed_seconds<arm.independent_preservation_review.bound_seconds);assert.equal(r.actual_Root_models.amd64.retained_original_false.ok,false);assert(r.actual_Root_models.amd64.all_original103_business_and_hosts_preserved);
 assert.equal(r.immutable_source_indexes_and_members_changed,0);assert.equal(r.production_source_overrides,0);for(const k of['fresh_CI_acceptance','programme_signed','programme_upgraded','Main19100_mutated','all50_commercial'])assert.equal(r[k],false);assert.equal(r.applications_installed_or_deleted,0);
});
function temporary(t){const parent=repo+'.local';fs.mkdirSync(parent,{recursive:true});const dir=fs.mkdtempSync(parent+'/https-fixture-unit-');fs.chmodSync(dir,0o700);t.after(()=>fs.rmSync(dir,{recursive:true}));return dir;}
test('one exact HTTPS test-only correction adds collision regression and keeps every original TLS and guard assertion byte',()=>{
 assert.equal(sha(raw),originalHTTPSFixtureSHA);const corrected=correctHTTPSFixture(raw);assert.equal(sha(corrected),correctedHTTPSFixtureSHA);
 const text=corrected.toString(),at=text.indexOf('\nfunc lbHTTPSFixtureAvoidPortCollision'),hook='\n\tlbHTTPSFixtureAvoidPortCollision(t, &in)';assert(at>0);const base=text.slice(0,at);assert.equal(base.split(hook).length,2);assert.equal(sha(base.replace(hook,'')),originalHTTPSFixtureSHA);
 for(const s of['tls.VersionTLS12','tls.VersionTLS11','wrong hostname','different CA','expired TLS','otherRequests.Load() != 0','configBefore','TestLoadBalanceIndependentCheckPortTargetsAreClosed'])assert(base.includes(s),s);
 for(const s of['42791, 41001, 41002, 41003','unchanged production collision admission changed','*in.HealthCheck != policy','fixture correction changed fixed node IP','fixture still violates unchanged HTTPS/forwarding port isolation'])assert(text.slice(at).includes(s),s);
});
test('changed assertions, unknown source and nonfixture bytes never enter the reviewed replacement',()=>{
 for(const value of[Buffer.concat([raw,Buffer.from('\n// changed assertion')]),Buffer.from(raw.toString().replace('otherRequests.Load() != 0','false')),fs.readFileSync(repo+'panel-integration-memcached-retirement-handler/internal/executor/app_load_balance_linux.go')])assert.throws(()=>correctHTTPSFixture(value));
});
test('all56 immutable source scopes retain original indexed test bytes without any test or production source write',()=>{
 assert.equal(Object.keys(reviewedHTTPSFixtureScopes).length,56);
 for(const[scope,expected]of Object.entries(reviewedHTTPSFixtureScopes)){const raw=fs.readFileSync(repo+scope+'/source-sha256.json');assert.equal(sha(raw),expected.index_sha256);const index=JSON.parse(raw);assert.equal(index.release.frozen_inputs_sha256,expected.inputs);assert.equal(Object.keys(index.files).length,expected.files);assert(!Object.hasOwn(index.test_overrides??{},httpsFixtureMember));assert.equal(index.files[httpsFixtureMember],originalHTTPSFixtureSHA);assert.equal(sha(fs.readFileSync(repo+scope+'/'+httpsFixtureMember)),originalHTTPSFixtureSHA);}
});
function originalWhole(bytes){const restored=originalReviewedHTTPSFixtureWorkflow(bytes);assert.equal(restored.length,originalHTTPSWorkflow.bytes);assert.equal(sha(restored),originalHTTPSWorkflow.sha256);return restored;}
test('all34 workflow jobs restore byte-exactly after only37 explicit whole-test fixture invocations, with no argument or deadline loss',()=>{
 const bytes=fs.readFileSync(repo+'.github/workflows/verify.yml'),text=bytes.toString();assert.equal(text.split(reviewedHTTPSWholeCommand).length-1,37);assert.equal(text.split(originalHTTPSWholeCommand).length-1,0);const restored=originalWhole(bytes);assert.equal(restored.toString().split(originalHTTPSWholeCommand).length-1,37);
 assert.equal(originalReviewedHTTPSFixtureWorkflow(restored),restored);assert(!text.includes('continue-on-error'));assert(!text.includes('GOFLAGS')&&!text.includes('GOENV'));
});
test('workflow restoration cannot hide a removed test, altered budget, weaker vet or added skip',()=>{
 const raw=fs.readFileSync(repo+'.github/workflows/verify.yml','utf8');
 for(const text of[raw.replace(reviewedHTTPSWholeCommand,'true'),raw.replace('timeout-minutes: 25','timeout-minutes: 99'),raw.replace('go vet ./...','true'),raw.replace(reviewedHTTPSWholeCommand,reviewedHTTPSWholeCommand+' -run=TestNone')])assert.throws(()=>originalWhole(Buffer.from(text)));
});
test('six historical reader adapters reconstruct the entire prior test and reject any extra assertion change',()=>{
 const names=['disk-host-diagnostic-candidate','disk-host-reason-candidate','disk-host-reason-installed-acceptance','disk-host-runtime-fix','platform-fleet-candidate','platform-health-view-candidate'];
 for(const name of names){const p='tests/'+name+'.test.mjs',bytes=fs.readFileSync(repo+p),original=originalReviewedHTTPSFixtureTest(p,bytes);assert(!original.includes('originalReviewedHTTPSFixtureWorkflow'));assert.throws(()=>originalReviewedHTTPSFixtureTest(p,Buffer.concat([bytes,Buffer.from('\n// changed assertion')])));assert.equal(originalReviewedHTTPSFixtureTest(p,original),original);}
});
test('the two old reviewed test overlays compose with HTTPS while retaining their exact prior member and all immutable sources',t=>{
 for(const[scope,member,correct]of[['panel-integration-intrusion','internal/appcatalog/intrusion_journal_features_test.go',intrusionFeatureFixtureOverlay],['panel-integration-hardening','internal/executor/software_manifest_record_linux_test.go',hardeningManifestFixtureOverlay]]){
  const dir=temporary(t),source=repo+scope,prior=source+'/'+member,replacement=dir+'/prior_fixture_test.go',overlay=dir+'/overlay.json';const old=fs.readFileSync(prior),oldTLS=fs.readFileSync(source+'/'+httpsFixtureMember);
  fs.writeFileSync(replacement,correct(old),{flag:'wx',mode:0o600});fs.writeFileSync(overlay,JSON.stringify({Replace:{[prior]:replacement}}),{flag:'wx',mode:0o600});
  extendReviewedHTTPSFixtureOverlay(source+'/',dir,overlay);const value=JSON.parse(fs.readFileSync(overlay));assert.deepEqual(Object.keys(value.Replace),[prior,source+'/'+httpsFixtureMember]);assert.equal(value.Replace[prior],replacement);assert.equal(sha(fs.readFileSync(value.Replace[source+'/'+httpsFixtureMember])),correctedHTTPSFixtureSHA);assert(fs.readFileSync(prior).equals(old)&&fs.readFileSync(source+'/'+httpsFixtureMember).equals(oldTLS));
 }
});
test('overlay composition refuses foreign production members and changed or aliased prior fixtures before creating a new replacement',t=>{
 const source=repo+'panel-integration-intrusion',member=source+'/internal/appcatalog/intrusion_journal_features_test.go';
 for(const kind of['foreign','changed','symlink']){
  const dir=temporary(t),replacement=dir+'/prior_fixture_test.go',overlay=dir+'/overlay.json';if(kind==='symlink')fs.symlinkSync(member,replacement);else fs.writeFileSync(replacement,kind==='changed'?'changed':intrusionFeatureFixtureOverlay(fs.readFileSync(member)),{flag:'wx',mode:0o600});
  fs.writeFileSync(overlay,JSON.stringify({Replace:{[kind==='foreign'?source+'/internal/core/store.go':member]:replacement}}),{flag:'wx',mode:0o600});assert.throws(()=>extendReviewedHTTPSFixtureOverlay(source,dir,overlay));assert(!fs.existsSync(dir+'/reviewed-load-balance-https-fixture_test.go'));
 }
});
test('the CLI never accepts a reduced, filtered or foreign-overlay full-suite argument list',()=>{
 for(const args of[['test','./internal/executor'],['test','-p','1','./...','-run=TestNone'],['test','-overlay=foreign.json','-p','1','./...']]){const result=spawnSync(process.execPath,[repo+'tools/run-https-fixture-ci.mjs','/usr/bin/false',...args],{cwd:repo,encoding:'utf8'});assert.notEqual(result.status,0);}
});
