import {readFile} from 'node:fs/promises';
import assert from 'node:assert/strict';
import test from 'node:test';
const read=p=>readFile(new URL('../'+p,import.meta.url),'utf8');
test('terminal archive is a real bounded no-overwrite operation, not remote deletion',async()=>{
 const source=await read('panel-integration/internal/executor/app_sync_remote_archive_linux.go');
 assert.match(source,/remoteArchiveMaxJobs = 2048/);assert.match(source,/remoteArchiveMaxBytes int64 = 16 << 20/);
 assert.match(source,/unix\.Renameat2/);assert.match(source,/unix\.RENAME_NOREPLACE/);
 assert.match(source,/in\.ExpectedSHA != remoteJobSHA\(j\)/);assert.match(source,/ARCHIVE REMOTE /);assert.match(source,/cp\.Pending != nil/);
 for(const name of ['succeeded','conflicts','failed','recovered'])assert(source.includes('"'+name+'"'));
 assert.doesNotMatch(source,/dialRemote|\.Remove\(|\.RemoveAll\(/);
});
test('archived IDs remain private full-byte identities with native regression cases',async()=>{
 const jobs=await read('panel-integration/internal/executor/app_sync_remote_jobs_linux.go');
 assert.match(jobs,/job_archived/);assert.match(jobs,/job_sha256/);assert.match(jobs,/archiveExists/);
 const readSource=await read('panel-integration/internal/executor/app_sync_remote_linux.go');assert.match(readSource,/RecordSHA = core\.Hash/);
 const fixtures=await read('panel-integration/internal/executor/app_sync_remote_archive_linux_test.go');
 for(const name of ['KeepsReplayAndFreesQueueSlot','RejectsUnknownWorkAndUnsafeNamespaces','BoundsAndReadOnlyPagination','TrueProcessExitPreservesIdentity'])assert(fixtures.includes('TestRemoteSyncArchive'+name));
 const contracts=JSON.parse(await read('registry/functional-contracts.json'));assert.equal(contracts.commercial_feature_parity_complete,false);
 const app=contracts.apps.find(a=>a.id==='files-sync');assert(app.scenarios.some(s=>s.includes('终态任务私有归档')));assert(app.gaps.some(s=>s.includes('远端事务')&&s.includes('有限容量')));assert(app.scenarios.some(s=>s.includes('远端计划')));
});
