import {test} from 'node:test';
import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import {createHash} from 'node:crypto';
const read=p=>readFile(new URL('../'+p,import.meta.url),'utf8'),sha=b=>createHash('sha256').update(b).digest('hex');

test('2.5 changes only statistics and retains immutable2.4.1 packages and their historical review',async()=>{
 const catalog=JSON.parse(await read('dist/catalog-v1.json')),app=catalog.apps.find(a=>a.id==='website-statistics-v2');
 assert.equal(sha(JSON.stringify(catalog.apps.filter(a=>a.id!=='website-statistics-v2').sort((a,b)=>a.id.localeCompare(b.id)))),'bffecb66de76955218323de30d9eee1c7312ba4ac27089e788d6f5b3b6df5a89');
 assert.equal(app.version,'2.6.0');assert.equal(app.sha256,sha(await read('dist/apps/website-statistics-v2/2.6.0/manifest.json')));
 assert.equal(sha(await read('dist/apps/website-statistics-v2/2.5.0/manifest.json')),'7a2d358fbb5f5a3bf0718b72ccc7401ae83df4d10596da837d1ed259a2ce2d13');
 const latest=JSON.parse(await read('dist/apps/website-statistics-v2/2.5.0/manifest.json'));
 assert.deepEqual(latest.required_panel_features,['statistics-cursor-retirement-v1','statistics-request-identity-v1']);
 assert.equal(sha(await read('dist/apps/website-statistics-v2/2.4.1/manifest.json')),'8b0bc77a7ddba94e1a29ea434c080b6c40c212d1edc592b904f757a3aa74f74e');
 assert.equal(sha(await read('dist/apps/website-statistics-v2/2.4.0/manifest.json')),'45a02dd14bd30421d238d32a1453656faca5f9282991eafe3f67056d64322124');
 const c=JSON.parse(await read('registry/functional-contracts.json')),r=c.reviewed_statistics_version_release,f=JSON.parse(await read('panel-integration/release-source-inputs.json')),i=JSON.parse(await read('panel-integration/source-sha256.json'));
 // Historical native proofs remain bound to the old immutable release;
 // current exported source must match its own signed input index instead.
 assert.equal(r.release,'0.1.0-dev.proapps24statsversionbelq');assert.equal(r.frozen_inputs_sha256,'918458c33fde22e77952d50b9a976bf124321b4106c4e9ec366b67edf4be24d0');
 assert.equal(r.frozen_source_files,16875);assert.equal(Object.keys(i.files).length,1250);assert.equal(Object.keys(f.files).length,1209);assert.deepEqual(i.test_overrides??{},{});
 assert.equal(f.frozen_inputs_sha256,i.release.frozen_inputs_sha256);assert.equal(f.archive_sha256,i.release.archive_sha256);
 const n=r.actual_normal_native_fixtures;assert.equal(n.proof_sha256,'c6d01d7efbd561289ceb23f3f6b9bb255e0496392f898e0bf58cd1f72600dee8');assert.equal(n.passed,true);assert.equal(n.executor_pass,666);assert.equal(n.executor_skip,124);assert.equal(n.executor_fail,0);assert.equal(n.python_count,93);assert.equal(n.python_skips,0);assert.equal(n.startup_pass,10);assert.equal(n.startup_skip,1);assert.equal(n.installed_state_preserved,true);assert.equal(n.candidate_installed,false);assert.equal(n.main_changed,false);
 assert.equal(n.source_inputs_sha256,r.frozen_inputs_sha256);assert.equal(n.normal_archive_sha256,r.signed_normal_release.arm64.archive);assert.equal(n.normal_executor_companion_sha256,r.signed_normal_release.arm64.companion);
 for(const p of ['internal/executor/app_statistics_history_linux.go','internal/executor/app_statistics_history_linux_test.go','internal/appcatalog/catalog.go','internal/appcatalog/panel_features.go','internal/appcatalog/panel_features_test.go','web/src/AppModuleReport.vue']){const hash=sha(await read('panel-integration/'+p));assert.equal(i.files[p],hash);assert.equal(f.files[p],hash);}
 const code=await read('panel-integration/internal/executor/app_statistics_history_linux.go');
 const versionSource=await read('panel-integration/internal/core/app_modules.go');assert.match(versionSource,/case "website-statistics-v2":\s+version = "2\.5\.0"/);
 assert((await read('panel-integration/internal/core/app_statistics_release_test.go')).includes('TestStatisticsCursorRetirementReleaseVersionMatchesActualUpdateHandler'));
 assert.equal(r.actual_signed_program_upgrade.proof_sha256,'d876149d39dc54c40f11f59ff032af8105e3774f1a71d45977d1928b72e82346');assert.equal(r.actual_signed_program_upgrade.passed,true);assert.equal(r.actual_signed_program_upgrade.original_statistics_240_preserved,true);assert.equal(r.actual_signed_program_upgrade.main_changed,false);
 for(const s of ['ExpiredStreams','statisticsHistoryStreams','tx.Commit()','blocked=0','offset=size','retireStatisticsStreams'])assert(code.includes(s),s);
 assert.equal(r.all_50_commercial,false);assert.equal(r.main_changed,false);assert.equal(c.commercial_feature_parity_complete,false);
});
