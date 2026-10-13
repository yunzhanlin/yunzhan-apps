import test from 'node:test';
import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import {createHash} from 'node:crypto';
const read=p=>readFile(new URL('../'+p,import.meta.url),'utf8');
const sha=s=>createHash('sha256').update(s).digest('hex');
test('job archival source and actual acceptance scope are bound to a new immutable original-key program',async()=>{
 const current=JSON.parse(await read('panel-integration-geography/source-sha256.json')),old=JSON.parse(await read('registry/reviewed-sources/0.1.0-dev.proapps24wafpolicybetu/source-sha256.json')),record=JSON.parse(await read('registry/geodata-job-archive-release.json'));
 assert.equal(old.release.frozen_inputs_sha256,'f0977771ba0e9d457eeae17d80ce68d9958410910cb5de27d34b817975e6ddd5');
 assert.equal(record.frozen_inputs_sha256,current.release.frozen_inputs_sha256);assert.equal(record.normal_original_key_archives.amd64,current.release.archive_sha256);
 assert.deepEqual(Object.keys(current.files).filter(p=>old.files[p]!==current.files[p]),record.only_source_changes);for(const p of Object.keys(old.files))assert(Object.hasOwn(current.files,p),p);
 assert.deepEqual(current.test_overrides??{},{});assert.equal(record.main_delivered,false);assert.equal(record.commercial_all50,false);assert.equal(record.bounds.automatic_deletion,false);assert.equal(record.bounds.archive_jobs,512);
 assert.equal(record.actual_normal_browser.intercepted_or_synthetic_api,false);assert.equal(record.actual_normal_browser.archive_posts,1);assert.equal(record.actual_normal_http_and_original_job.new_jobs_or_downloads,false);assert.equal(record.actual_normal_http_and_original_job.selected_data_changed,false);
 const core=await read('panel-integration-geography/internal/core/statistics_geodata_archive.go');for(const gate of ['DecodeStatisticsGeoArchive','statistics.geodata.archive.request','statistics.geodata.archive.complete','原地域任务与执行器终态不同','Cache-Control','succeeded'])assert(core.includes(gate),gate);
 const native=await read('panel-integration-geography/internal/executor/app_statistics_geodata_archive_linux.go');for(const gate of ['unix.RENAME_NOREPLACE','statisticsGeoJobSameFiles','statisticsGeoInstanceLease(true)','store.checkpoint("after-rename")','512'])assert(native.includes(gate),gate);
 assert(!native.includes('RemoveAll(')&&!native.includes('os.Remove('));assert((await read('panel-integration-geography/internal/executor/program_upgrade_geodata_linux.go')).includes('statistics-geodata-job-archive'));
 assert((await read('panel-integration-geography/web/src/StatisticsGeoJobRecords.vue')).includes('核对原任务归档交接'));
 assert.equal(sha(await read('dist/apps/website-statistics-v2/2.6.0/manifest.json')),'17d8a5fb7f48a2e448103580c77067b249281d413f3182c3f7d1e2291ac54d70');
});
