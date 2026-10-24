import{originalReviewedHTTPSFixtureWorkflow}from'./reviewed-https-fixture-workflow.mjs';
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import {createHash} from 'node:crypto';
import {fileURLToPath} from 'node:url';
const root=fileURLToPath(new URL('../',import.meta.url)),scope='panel-integration-memcached-review/',prior='panel-integration-memcached-unix/';
const read=n=>fs.readFileSync(root+n),json=n=>JSON.parse(read(n)),sha=b=>createHash('sha256').update(b).digest('hex');
const delta={"changed":["internal/core/memcached_unix_control.go","internal/core/memcached_unix_control_http.go","internal/core/runtime_bundles.go","internal/core/runtimes.go","internal/executor/docker_mutation_linux.go","internal/executor/docker_mutation_linux_test.go","internal/executor/memcached_unix_control_close_linux.go","internal/executor/memcached_unix_control_journal_linux.go","internal/executor/memcached_unix_control_linux.go","scripts/test-memcached-unix-ui-fixture.mjs","scripts/test-memcached-unix-ui.mjs","scripts/test-memcached-unix-workspace.mjs","web/src/MemcachedUnixManager.vue","web/src/memcachedUnix.ts"],"added":["internal/core/memcached_unix_control_observation_test.go","internal/core/memcached_unix_control_review.go","internal/core/memcached_unix_control_review_http.go","internal/core/memcached_unix_control_review_test.go","internal/core/runtime_audit_timestamp_test.go","internal/executor/memcached_unix_control_observation_linux.go","internal/executor/memcached_unix_control_observation_linux_test.go","internal/executor/memcached_unix_control_review_linux.go","internal/executor/memcached_unix_control_review_linux_test.go"],"removed":[]};
test('recorded real Root models and genuine builds are not signed programme, native application or commercial50 acceptance',()=>{
 const r=json('registry/memcached-review-core.json');assert.equal(r.frozen_inputs_sha256,'2477f8c1450679ff5711cb887cdfee2b485e8833eb64a0014c5369192710a8f7');assert.equal(r.exported_files,1907);assert.equal(r.source_overlays,0);
 for(const arch of ['amd64','arm64']){const m=r.actual_Root_models[arch];assert.equal(m.top_level,109);assert.equal(m.including_subtests,709);assert.equal(m.skips,0);assert.equal(m.failures,0);assert(m.all_original102_business_schema_rows_and20modules_preserved&&m.all_original_containers_NSS_and_installed_programme_lifetimes_preserved);assert(!m.default_account_created&&!m.default_application_installed);assert.match(m.proof_sha256,/^[a-f0-9]{64}$/);assert(r.normal_programme_builds[arch].portable_build_completed);}
 for(const n of ['signed','normal_upgrade_accepted','Main19100_mutated','all50_commercial'])assert.equal(r[n],false,n);
 assert.equal(r.legacy_validator_fixture.production_overrides,0);assert.equal(r.legacy_validator_fixture.original_CI.exact_original_CI_cause_retrospectively_proven,false);assert.equal(r.ui.real_native_or_public_API_acceptance,false);assert.equal(r.application_manifests_changed,0);
});
test('F46 frozen review source preserves its F45 parent, all1446 Go inputs and exact1907 archive-bound members',()=>{
 const raw=read(scope+'source-sha256.json'),index=JSON.parse(raw),old=json(prior+'source-sha256.json');
 assert.equal(sha(raw),'92f45bca09edc338dad7b1abb27b0c9bda9a1ddfcb7bf5f478ef06caca1b3d63');
 assert.equal(sha(read(scope+'release-source-inputs.json')),'1b6249d00594e0e61f144a8f03e7085bc040313b4612f6abb131b2ac0ef08366');
 assert.equal(index.release.frozen_inputs_sha256,'2477f8c1450679ff5711cb887cdfee2b485e8833eb64a0014c5369192710a8f7');
 assert.equal(index.release.archive_sha256,'07f3e2c9dc2321f35bf8945b6aae3c04af525c3c1de63f476c95b50cd2450435');
 assert.equal(index.release.archive,'panel-0.1.0-dev.proapps24memreviewblaa-linux-amd64.tar.gz');
 assert.deepEqual(index.test_overrides,{});assert.equal(Object.keys(index.files).length,1907);assert.equal(Object.keys(index.files).filter(n=>n.endsWith('.go')).length,1446);
 assert.deepEqual(json(scope+'release-source-inputs.json'),{...index.release,files:index.files});
 assert.deepEqual(Object.keys(old.files).filter(n=>old.files[n]!==index.files[n]),delta.changed);
 assert.deepEqual(Object.keys(index.files).filter(n=>!old.files[n]),delta.added);assert(!Object.keys(old.files).some(n=>!index.files[n]));
 for(const[n,h]of Object.entries(index.files)){const f=root+scope+n,s=fs.lstatSync(f);assert(path.posix.normalize(n)===n&&!path.isAbsolute(n)&&!n.split('/').some(x=>['..','.git','.local','node_modules'].includes(x)));assert(s.isFile()&&!s.isSymbolicLink()&&s.nlink===1);assert.equal(sha(read(scope+n)),h,n);}
 assert.equal(index.files['web/src/FileManager.vue'],old.files['web/src/FileManager.vue']);
 assert.equal(sha(read('dist/catalog-v1.json')),'bc0dcdbcd0bcd5e75c889471a9e26168c951f943f772e0400d328af8d3e5f84f');
});
test('real producer timestamp fix retains the exact strict SELECT-only historical validator',()=>{
 const now=json(scope+'source-sha256.json'),old=json(prior+'source-sha256.json'),name='internal/core/runtime_failed_upgrade.go';
 assert.equal(now.files[name],old.files[name]);
 const jobs=read(scope+'internal/core/runtimes.go').toString(),bundle=read(scope+'internal/core/runtime_bundles.go').toString(),regression=read(scope+'internal/core/runtime_audit_timestamp_test.go').toString();
 for(const text of ['key, stamp, stamp)', 'actor, release, stamp)', 'string(b), stamp, j.ID)', 'j.TargetID, state, stamp)'])assert(jobs.includes(text),text);
 for(const text of ['jobKey, stamp, stamp)', 'actor, id, stamp)', 'string(encoded), stamp)'])assert(bundle.includes(text),text);
 for(const text of ['runtimeStampBoundaryDriver','stamp.Add(time.Second)','original failure must remain valid across slow SQL writes','ValidateRuntimeFailedInstall','both real producer write paths were not delayed'])assert(regression.includes(text),text);
 assert(!regression.includes('UPDATE audit_logs'));
});
test('independent review appends original-result-bound evidence without a native restart or identity adoption',()=>{
 const rootSource=read(scope+'internal/executor/memcached_unix_control_review_linux.go').toString(),native=rootSource.split('func (s *Service)')[0],journal=read(scope+'internal/executor/memcached_unix_control_observation_linux.go').toString(),sql=read(scope+'internal/core/memcached_unix_control_review.go').toString();
 for(const text of ['store.open(op.RequestID)','original.Issued == nil','engineStore.existingOnly = true','reader.unixControlReview','reader.unixOperation','memcachedUnixWorkspaceState','memcachedUnixReadyAt','again != state','lease.observe(result)'])assert(native.includes(text),text);
 assert(!/memcachedUpdateDockerPost|exec\.Command|http\.MethodPost|\.prepare\(/.test(native));
 for(const text of ['OriginalResultSHA256','original.Issued == nil','original.Result.State != "unknown"','"observation.json"','before.Result','value.Result.State != "observed"'])assert(journal.includes(text),text);
 assert(!/Remove\(|RemoveAll\(|"result.json"/.test(journal));
 for(const text of ['MemcachedUnixControlReviewBinding','memcachedUpdateAuthority(ctx, tx, reviewer','row.Operation != op','app.memcached.unix.review','row.Result != result'])assert(sql.includes(text),text);
});
test('actual Vue recovery distinguishes historical observation from original success and clears revoked or unknown replies',()=>{
 const ui=read(scope+'web/src/MemcachedUnixManager.vue').toString(),models=read(scope+'scripts/test-memcached-unix-workspace.mjs').toString(),browser=read(scope+'scripts/test-memcached-unix-ui.mjs').toString();
 for(const text of ['previewReview','commitReview','currentReviewRow','acknowledge_original_unknown','原命令结果仍未知','这是历史记录，不代表当前健康','复核回复未知，不自动重发'])assert(ui.includes(text),text);
 for(const text of ['double review confirmation sends one closed acknowledgement','permission revoked while confirming review or close','late cross-actor review preview is discarded'])assert(models.includes(text),text);
 assert(browser.includes('mobileButton.y+mobileButton.height<=mobileFooter.y'));assert(!/localStorage|sessionStorage|console\.log/.test(ui));
});
test('current independent Root gate requires all109 models and709 subcases, while preserving every original31 workflow job',()=>{
 const raw=originalReviewedHTTPSFixtureWorkflow(read('.github/workflows/verify.yml')),at=raw.indexOf('\n  memcached-unix-models-amd64:\n');assert.equal(at,102422);assert.equal(sha(raw.subarray(0,at)),'42c8126b32067a6bafbbcb5054bde803fecf9a548e7865fbb62785b39d493d61');
 const gate=raw.subarray(at).toString(),ci=read('tools/run-memcached-review-models-ci.mjs').toString();
 for(const text of ['panel-integration-memcached-review','tools/run-memcached-review-models-ci.mjs','tools/run-memcached-review-packaging-ci.py','tests/memcached-review-source.test.mjs'])assert(gate.includes(text),text);
 for(const text of ['total===109&&subtests===709','2477f8c1450679ff5711cb887cdfee2b485e8833eb64a0014c5369192710a8f7','TestRuntimeAuditTimestampSurvivesSQLSecondBoundary','TestMemcachedUnixControlReviewNeverCreatesOrRepairsTheOriginalDockerLock','actual_default_install_or_account_creation:false','all50_commercial:false'])assert(ci.includes(text),text);
 assert(!gate.includes('continue-on-error'));assert(!gate.includes('--overlay'));assert(!gate.includes('reset-failed'));
});
