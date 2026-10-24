import{originalReviewedHTTPSFixtureWorkflow}from'./reviewed-https-fixture-workflow.mjs';
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
import {createHash} from 'node:crypto';
const root=fileURLToPath(new URL('../',import.meta.url)),scope='panel-integration-php-bounded/',read=n=>fs.readFileSync(root+n),json=n=>JSON.parse(read(n)),sha=b=>createHash('sha256').update(b).digest('hex');
test('bounded PHP admission is exactly1778 ordinary frozen source files,1328 Go files and no overrides',()=>{
 const index=json(scope+'source-sha256.json');assert.equal(sha(read(scope+'source-sha256.json')),'95e9dea6cea66a71a38627296efc20af3d58a8a6d6012911c5267e6dae953184');assert.equal(index.release.frozen_inputs_sha256,'12bd315dbff814fe9a24af1229d6a0ed3be2bb0b1fc9cafe50546fc5ce7bd9c7');assert.equal(index.release.archive_sha256,'003610a118922b83969345ef414e45400c43891a4b1a3c2cdc3135f572ba500b');assert.equal(Object.keys(index.files).length,1778);assert.equal(Object.keys(index.files).filter(n=>n.endsWith('.go')).length,1328);assert.deepEqual(index.test_overrides,{});assert.deepEqual(json(scope+'release-source-inputs.json').files,index.files);
 for(const[n,h]of Object.entries(index.files)){assert.equal(path.posix.normalize(n),n);assert(!path.isAbsolute(n)&&!n.split('/').some(c=>['..','.git','.local','node_modules'].includes(c)));const s=fs.lstatSync(root+scope+n);assert(s.isFile()&&!s.isSymbolicLink()&&s.nlink===1);assert.equal(sha(read(scope+n)),h,n);}
});
test('admission changes only2 Go handlers plus its new tests; all bounded-memory,collector,OOM,retry and installer sources remain exact',()=>{
 const current=json(scope+'source-sha256.json'),old=json('panel-integration-runtime-memory/source-sha256.json');assert(Object.keys(old.files).every(n=>Object.hasOwn(current.files,n)));assert.deepEqual(Object.keys(current.files).filter(n=>!(n in old.files)).sort(),['internal/appcatalog/php_bounded_features_test.go']);assert.deepEqual(Object.keys(current.files).filter(n=>n in old.files&&current.files[n]!==old.files[n]).sort(),['internal/appcatalog/panel_features.go','internal/appcatalog/php_security_features.go']);
 for(const[n,h]of Object.entries(old.files))if(!['internal/appcatalog/panel_features.go','internal/appcatalog/php_security_features.go'].includes(n))assert.equal(current.files[n],h,n);
});
test('four compat2 packages require both independently available Linux handlers,without silently promoting historical compat1',()=>{
 const src=read(scope+'internal/appcatalog/php_security_features.go').toString(),tests=read(scope+'internal/appcatalog/php_bounded_features_test.go').toString();
 for(const s of ['PHPBoundedNativeBuildFeature = "php-bounded-native-build-v1"','case version + "-compat1":','case version + "-compat2":','len(m.RequiredPanelFeatures) != 2 || !security || !bounded','available == nil || !available(feature)','required = append(required, PHPBoundedNativeBuildFeature)'])assert(src.includes(s),s);
 for(const s of ['TestPHPBoundedBuildManifestBytesBindOfflineNetworkAndCachedVerification','FetchManifest','verifyManifestData','SHA-256','stripped handler borrowed signed original bytes','rehash replaced required bounded builder'])assert(tests.includes(s),s);
});
test('additional26th gate retains every byte of previous25-job workflow and all ordinary production deadlines',()=>{
 const workflow=originalReviewedHTTPSFixtureWorkflow(read('.github/workflows/verify.yml')),at=workflow.indexOf('\n  php-bounded-native-amd64:\n');assert(at>0);assert.equal(sha(workflow.subarray(0,at)),'da9365ee70442710017474652ad14ee186c03f8ad87620e5e8cf4f5011590269');const gate=workflow.subarray(at).toString();for(const s of ['panel-integration-php-bounded','tools/check-php-bounded-schema.mjs','go vet ./...','TestPublishedRepositoryCurrentSignedManifestABI','-race','jsonschema==4.25.1'])assert(gate.includes(s),s);for(const s of ['continue-on-error','-overlay=','reset-failed','killall','pkill'])assert(!gate.includes(s),s);
 assert(read(scope+'internal/executor/program_upgrade_queues_linux.go').toString().includes('5*time.Second'));
});
