// Integrity and scope assertions about separately captured evidence, not a new
// native/installed acceptance run and never a replacement for the original log.
import test from 'node:test';
import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import {createHash} from 'node:crypto';
const read=p=>readFile(new URL('../'+p,import.meta.url));
const sha=b=>createHash('sha256').update(b).digest('hex');
test('historical disk source export binds exact frozen BFFR inputs while preserving original signed BFDV source authority',async()=>{
 const r=JSON.parse(await read('registry/disk-inode-release.json'));
 const i=JSON.parse(await read('registry/reviewed-sources/0.1.0-dev.proapps24diskinodebffr/source-sha256.json'));
 const f=JSON.parse(await read('registry/reviewed-sources/0.1.0-dev.proapps24diskinodebffr/release-source-inputs.json'));
 const oldRaw=await read('registry/reviewed-sources/0.1.0-dev.proapps24geoauthbfdv/source-sha256.json'),old=JSON.parse(oldRaw);
 assert.equal(sha(oldRaw),'2c7ab96cec0d532387b06c169c4a4d1f256c17571351ca8f2684a54899117ccc');
 assert.equal(sha(await read('registry/reviewed-sources/0.1.0-dev.proapps24geoauthbfdv/release-source-inputs.json')),'832971985c43377f0e561eaa73aff199e77213d4d9a57d01c95b5090de089c5b');
 assert.equal(i.release.frozen_inputs_sha256,r.source_inputs_sha256);assert.equal(i.release.archive_sha256,r.normal_original_key_archives.amd64);assert.equal(i.release.archive,'panel-'+r.program+'-linux-amd64.tar.gz');
 assert.equal(f.frozen_inputs_sha256,r.source_inputs_sha256);assert.equal(f.archive_sha256,r.normal_original_key_archives.amd64);
 assert.deepEqual(Object.keys(i.files).filter(k=>i.files[k]!==old.files[k]).sort(),r.only_source_changes);assert.deepEqual(Object.keys(old.files).filter(k=>!(k in i.files)),[]);
 assert.equal(r.source_overrides,0);assert.deepEqual(i.test_overrides??{},{});
 for(const name of r.only_source_changes){assert.equal(i.files[name],f.files[name],name);assert.equal(sha(await read('panel-integration-geography/'+name)),f.files[name],name);}
 const scanner=(await read('panel-integration-geography/internal/executor/app_disk_usage_linux.go')).toString();
 for(const text of ['diskUsageEntriesMax = 100000','diskUsageDepthMax = 128','diskUsageReadBatch = 64','unix.O_NOFOLLOW','unix.AT_SYMLINK_NOFOLLOW','st.Blocks * 512','st.Dev != expected.Dev || st.Ino != expected.Ino','snapshot_consistent','filesystem_inodes_available','classification_limited'])assert(scanner.includes(text),text);
 assert(!scanner.includes('os.Remove')&&!scanner.includes('exec.Command')&&!scanner.includes('ReadFile('));
 const build=(await read('panel-integration-geography/packaging/build-release.sh')).toString();assert(build.includes('node --test scripts/test-disk-usage.mjs'));
 const ci=(await read('.github/workflows/verify.yml')).toString();assert(ci.includes("go test -race ./internal/executor -run '^Test(DiskUsage|ModuleDisk)' -count=1 -v"));assert(ci.includes('node --test panel-integration-geography/scripts/test-disk-usage.mjs'));
});
test('disk original native and browser observations retain failures and do not certify installation or commercial qualification',async()=>{
 const r=JSON.parse(await read('registry/disk-inode-release.json')),proofs={};
 for(const [name,pin]of Object.entries(r.evidence_sha256)){const bytes=await read('registry/reviewed-disk-inode/24bffr/'+name);assert.equal(sha(bytes),pin,name);proofs[name]=JSON.parse(bytes);}
 for(const name of ['native-arm64.json','feature-arm64.json']){
  const wrap=proofs[name],p=wrap.proof;assert.equal(p.ok,true);assert.equal(p.actual_exit,0);assert.notEqual(p.effective_uid,0);assert.equal(p.filesystem,'tmpfs');assert.equal(p.source_inputs_sha256,r.source_inputs_sha256);assert.equal(p.program_archive_sha256,r.normal_original_key_archives.arm64);
  assert(!wrap.test_summary.some(s=>s.startsWith('--- SKIP:')||s.startsWith('--- FAIL:')));
 }
 const native=proofs['native-arm64.json'];assert.equal(native.proof.binary_sha256,'bed504dfe6f40e529a401a16329ea75a9735efa3a65bdb40a5b8f4af32260978');assert.equal(native.test_summary.filter(s=>s.startsWith('--- PASS:')).length,13);
 assert(native.test_summary.some(s=>s.includes('files=100003 visited_entries=100000 returned_top=100')));
 const ui=proofs['isolated-ui.json'],i=JSON.parse(await read('panel-integration-geography/source-sha256.json'));assert.equal(ui.ok,true);assert.equal(ui.source_inputs_sha256,r.source_inputs_sha256);assert.equal(ui.checks.length,7);assert.deepEqual(ui.errors,[]);assert.deepEqual(ui.failures,[]);assert.deepEqual(ui.geometry.window_errors,[]);assert.equal(ui.geometry.viewport,390);assert.equal(ui.geometry.document_width,390);
 for(const [name,pin]of Object.entries(ui.sources))assert.equal(i.files[name],pin,name);
 assert.equal(proofs['retained-first-ui.json'].ok,false);assert.equal(proofs['retained-diagnostic-ui.json'].ok,false);
 assert(proofs['retained-diagnostic-ui.json'].geometry.window_errors.some(s=>s.includes('ResizeObserver loop')));
 assert.equal(r.feature_gate.candidate_stage,'integration');assert.equal(r.feature_gate.published_version_unchanged,'1.2.0');
 assert.equal(sha(await read('dist/apps/disk-analysis/1.2.0/manifest.json')),r.feature_gate.published_manifest_sha256);
 for(const name of ['main_delivered','disk_analysis_commercial','commercial_all50','catalog_and_all50_packages_changed'])assert.equal(r[name],false,name);
 assert.equal(r.application_installs_updates,0);assert(r.remaining.length>=5);
});
