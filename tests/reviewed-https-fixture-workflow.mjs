// Restore only the explicitly reviewed CI-only HTTPS fixture invocation.
// Existing historical hashes remain authoritative for every other byte.
import assert from'node:assert/strict';
import{createHash}from'node:crypto';
export const originalHTTPSWholeCommand='sudo "$(command -v go)" test -p 1 ./...';
export const reviewedHTTPSWholeCommand='sudo --preserve-env=GITHUB_ACTIONS,GITHUB_REPOSITORY "$(command -v node)" "$GITHUB_WORKSPACE/tools/run-https-fixture-ci.mjs" "$(command -v go)" test -p 1 ./...';
export const originalHTTPSWorkflow={head:'1061104bc6d6896ff6f711dfa379b47bebd40429',bytes:107862,sha256:'520481e456a2b926927d193614bd8090f79b174f3ad579d2948c6490eb6be0c8',complete_invocations:37};
export function originalReviewedHTTPSFixtureWorkflow(bytes){
 const text=bytes.toString(),count=text.split(reviewedHTTPSWholeCommand).length-1;
 if(!count)return bytes;
 assert(count>=1&&count<=originalHTTPSWorkflow.complete_invocations,'Only the reviewed full-source fixture invocations may be restored');
 const restored=text.replaceAll(reviewedHTTPSWholeCommand,()=>originalHTTPSWholeCommand);
 return Buffer.isBuffer(bytes)?Buffer.from(restored):restored;
}

const reviewedHistoricalHTTPSReaders={"tests/disk-host-diagnostic-candidate.test.mjs":{"before":"7bf7cf14af76a2887620615cf31349d0ab1580d6a1a358a38c7aafafb41b9f5e","after":"f39877b6d2cc23e7683967557e14fa50bf0077ef916faeaaeca097499ae6fe98","edits":[{"from":"originalReviewedHTTPSFixtureWorkflow(await read('.github/workflows/verify.yml'))","to":"await read('.github/workflows/verify.yml')","count":1}]},"tests/disk-host-reason-candidate.test.mjs":{"before":"334012223896dab5dafb3d7c575fef068bba69a90f8dc4b2ab7318705e966605","after":"fce3e4493d46732396734b03d2ec1fdadc04ce60821bc0f9d5cf81c69de76655","edits":[{"from":"originalReviewedHTTPSFixtureWorkflow(await read('.github/workflows/verify.yml'))","to":"await read('.github/workflows/verify.yml')","count":1}]},"tests/disk-host-reason-installed-acceptance.test.mjs":{"before":"ead6139ddde7b03225380f1426a9cdee4abaca02421c3a1f9ef881579814e2b7","after":"2e737d7279268f5415ed5b44360083c0e0e95d5f873cf2efc788d6abe8b69fdc","edits":[{"from":"originalReviewedHTTPSFixtureWorkflow(await read('.github/workflows/verify.yml'))","to":"await read('.github/workflows/verify.yml')","count":1}]},"tests/disk-host-runtime-fix.test.mjs":{"before":"3e564a6bc15b6b130279953482cafab7c9e7b7831ecb0884f1ac774c2034b2db","after":"c79ac882db9d576202f617e5d8e14a007669700e73879757c7fe48337c3c392a","edits":[{"from":"originalReviewedHTTPSFixtureWorkflow(await read('.github/workflows/verify.yml'))","to":"await read('.github/workflows/verify.yml')","count":1}]},"tests/platform-fleet-candidate.test.mjs":{"before":"fa7217314cad00418edd2263156917d0b69e20f424c6bf8eae8637ded1cdf271","after":"aee47b3014396123923793f5753d4b5bebd97d9d2d4a0a1125477fd333ce3244","edits":[{"from":"originalReviewedHTTPSFixtureWorkflow(await read('.github/workflows/verify.yml'))","to":"await read('.github/workflows/verify.yml')","count":1}]},"tests/platform-health-view-candidate.test.mjs":{"before":"500b3319a2796fec2e26c70336fef0c446f9c94a609942956190cc5845ffeb19","after":"9d412ed9eaef6b1dbaefec634d7d4d7cf58ee1263ad931862039ee03dff3e667","edits":[{"from":"originalReviewedHTTPSFixtureWorkflow(await read('.github/workflows/verify.yml'))","to":"await read('.github/workflows/verify.yml')","count":1}]}};
export function originalReviewedHTTPSFixtureTest(path,bytes){
 const plan=reviewedHistoricalHTTPSReaders[path];if(!plan)return bytes;
 const digest=b=>createHash('sha256').update(b).digest('hex');if(digest(bytes)===plan.before)return bytes;
 assert.equal(digest(bytes),plan.after,'Only the exact reviewed workflow reader import and calls may be removed');
 const added="import{originalReviewedHTTPSFixtureWorkflow}from'./reviewed-https-fixture-workflow.mjs';\\n".replace('\\n','\n');
 let text=bytes.toString();assert.equal(text.split(added).length,2);text=text.replace(added,'');
 for(const{from,to,count}of plan.edits){assert.equal(text.split(from).length-1,count);text=text.replaceAll(from,()=>to);}
 assert.equal(digest(text),plan.before,'Every original historical assertion byte remains exact');return Buffer.from(text);
}
