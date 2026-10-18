import test from 'node:test';import assert from 'node:assert/strict';import fs from 'node:fs';import path from 'node:path';import {fileURLToPath} from 'node:url';import {createHash} from 'node:crypto';
const root=fileURLToPath(new URL('..',import.meta.url)),read=p=>fs.readFileSync(path.join(root,p)),sha=b=>createHash('sha256').update(b).digest('hex'),meta=JSON.parse(read('registry/mobile-native-session-release.json')),scope=meta.source_scope;
test('native 1.3.1 is an independent exact 24-file frozen client without program or app signature claims',()=>{
 const raw=read(scope+'/source-sha256.json'),index=JSON.parse(raw),input=JSON.parse(read(scope+'/SOURCE_INPUTS.json'));assert.equal(sha(raw),meta.source_index_sha256);assert.equal(sha(JSON.stringify(index.files)),meta.source_inputs_sha256);assert.equal(index.source_inputs_sha256,meta.source_inputs_sha256);assert.equal(input.inputs_sha256,meta.source_inputs_sha256);assert.deepEqual(input.files,index.files);assert.deepEqual(index.test_overrides,{});assert.equal(Object.keys(index.files).length,24);
 for(const [p,expected] of Object.entries(index.files)){assert(p.startsWith('mobile/')&&path.posix.normalize(p)===p&&!p.split('/').some(x=>['..','build','.local','.gradle','.build','local.properties'].includes(x)));assert.equal(read(scope+'/'+p).length,expected.bytes);assert.equal(sha(read(scope+'/'+p)),expected.sha256,p);}
 assert.equal(meta.server_application_version_unchanged,'1.3.0');assert.equal(meta.source_overrides,0);assert.equal(meta.program_or_server_application_operation,false);assert.equal(meta.private_key_access_or_rotation,false);
});
test('actual platform adapters bind original picker authentication and foreground delivery to the state gates',()=>{
 const android=read(scope+'/mobile/android/app/src/main/java/icu/yunzhan/panel/PanelActivity.java').toString(),ios=read(scope+'/mobile/ios/YunzhanMobile.swift').toString();
 for(const phrase of ['session.beginSelection()','ticket.requestCode','session.awaitingSelection(request)','session.receiveSelection(request','session.takeSelection()','authentication != signal','session.finishAuthentication(ticket, true)','session.end()','session.foreground(false)'])assert(android.includes(phrase),phrase);
 for(const phrase of ['controller === picker','callbacks.beginSelection()','callbacks.receiveSelection(ticket','callbacks.takeSelection()','self.authAttempt == attempt','self.callbacks.finishAuthentication(attempt','callbacks.end()','callbacks.cover(background: background)'])assert(ios.includes(phrase),phrase);
 assert(!android.includes('startActivityForResult(pick, 42)'));assert(!ios.includes('upload?(safe'));
 assert(read(scope+'/mobile/ios/Package.swift').toString().includes('"SessionCallbacks.swift"'));assert(read(scope+'/mobile/ios/YunzhanMobile.xcodeproj/project.pbxproj').toString().includes('path = SessionCallbacks.swift'));
});
test('real Android Swift lint and unsigned device builds are gates, never device publisher or all50 completion',()=>{
 const workflow=read('.github/workflows/mobile.yml').toString();for(const phrase of ['test assembleRelease assembleDebug lint','gradle-version: \'8.13\'','run: swift test','-destination generic/platform=iOS','CODE_SIGNING_ALLOWED=NO','if-no-files-found: error'])assert(workflow.includes(phrase),phrase);
 assert.deepEqual(meta.android_tests,{debug:10,release:10,failed:0,skipped:0});assert.deepEqual(meta.swift_tests,{passed:9,failed:0});assert.equal(meta.android_lint_issues,0);for(const value of Object.values(meta.not_proven))assert.equal(value,true);assert.equal(meta.commercial_all50,false);
 const apk=read(scope+'/mobile/android/app/build.gradle').toString();assert(apk.includes("versionName '1.3.1'"));assert(apk.includes('versionCode 131'));
});
