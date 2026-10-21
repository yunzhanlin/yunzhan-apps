import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import {fileURLToPath} from 'node:url';
import {createHash} from 'node:crypto';
import {originalNginxRuntimeWorkflow,beforeNginxRuntime} from './pre-nginx-runtime-release.mjs';
import {oldWAFRepositoryRoot} from '../tools/verify-waf-health-handler-boundary.mjs';
import {verifyOldNginxRuntimeRefusal} from '../tools/verify-nginx-runtime-handler-boundary.mjs';
const root=fileURLToPath(new URL('..',import.meta.url)),read=n=>fs.readFileSync(new URL('../'+n,import.meta.url)),sha=b=>createHash('sha256').update(b).digest('hex');
test('only five named historical positive roots and one historical WAF negative argument change; all sixteen original jobs survive',()=>{
 const raw=read('.github/workflows/verify.yml'),old=originalNginxRuntimeWorkflow(raw);
 const previous=read('registry/reviewed-catalogs/before-nginx-runtime-workflow24bjbl/verify-pr70.yml');
 assert.equal(sha(previous),'b230a6bf4f6b990461ded7d0270d8fea1603807551dec6e205f1ec9dac47253f');assert(old.subarray(0,previous.length).equals(previous));
 const line='-published-app-registry-root "$GITHUB_WORKSPACE/'+beforeNginxRuntime.slice(0,-1)+'"';assert.equal(raw.toString().split(line).length-1,5);
 for(const change of [raw.toString().replace(line,'-published-app-registry-root "/tmp/fake"'),raw.toString().replace('timeout 240s sudo python3','timeout 999s sudo python3'),raw.toString().replace('sudo "$(command -v go)" test -p 1 ./... -count=1','true')])assert.throws(()=>originalNginxRuntimeWorkflow(Buffer.from(change)));
 for(const scope of ['runtime-package','runtime-health'])assert(raw.toString().includes('working-directory: panel-integration-'+scope+'\n        run: sudo "$(command -v go)" test -json ./internal/appcatalog -run \'^TestPublishedRepositoryCurrentSignedManifestABI$\' -count=1 -args -published-app-registry-root "$GITHUB_WORKSPACE"'));
 const added=raw.toString().indexOf('\n  nginx-runtime-signed-native-amd64:\n');assert(added>0);const following=raw.toString().slice(added+4).search(/\n  [a-z][a-z0-9-]+:\n/);const gate=raw.toString().slice(added,following<0?undefined:added+4+following);
 for(const command of ['runs-on: ubuntu-24.04','timeout-minutes: 20','npm run verify:signature','tests/nginx-runtime-history.test.mjs','cd panel-integration-runtime-package','cd ../panel-integration-runtime-health','node tools/verify-nginx-runtime-handler-boundary.mjs','node tools/verify-waf-health-handler-boundary.mjs --repo-root '+beforeNginxRuntime.slice(0,-1)])assert(gate.includes(command),command);
 assert.equal(gate.split("-run '^TestPublishedRepositoryCurrentSignedManifestABI$'").length-1,2);assert(!gate.includes('continue-on-error'));assert(!gate.includes('-overlay='));
});
test('the old WAF negative runner admits only its exact original-key signed predecessor, not arbitrary paths or inline flags',()=>{
 assert.equal(oldWAFRepositoryRoot([],root),root);const target=beforeNginxRuntime.slice(0,-1);assert.equal(oldWAFRepositoryRoot(['--repo-root',target],root),root+target);
 for(const args of [['--repo-root'],['--repo-root','.'],['--repo-root','/tmp/fake'],['--repo-root',target+'/../fake'],['--repo-root',target,'--skip-signature'],['--repo-root='+target]])assert.throws(()=>oldWAFRepositoryRoot(args,root));
});
test('Nginx-only actual compiled refusal cannot accept a skipped, partial, catalog-wide, wrong-error, signaled or all-green result',()=>{
 const ids=JSON.parse(read(beforeNginxRuntime+'dist/catalog-v1.json')).apps.map(a=>a.id),prefix='TestPublishedRepositoryCurrentSignedManifestABI';
 const events=[...ids.filter(id=>id!=='nginx').map(id=>({Action:'pass',Test:prefix+'/'+id})),{Action:'output',Test:prefix+'/nginx',Output:'actual compiled handler rejects current signed manifest 应用面板处理器要求无效'},{Action:'fail',Test:prefix+'/nginx'},{Action:'fail',Test:prefix},{Action:'fail'}];
 const result={status:1,stdout:events.map(e=>JSON.stringify(e)).join('\n')};assert.equal(verifyOldNginxRuntimeRefusal(result,ids).other49_passed,49);
 for(const changed of [{...result,status:0},{...result,error:new Error('spawn')},{...result,signal:'SIGTERM'},{...result,stdout:result.stdout.replace('应用面板处理器要求无效','unknown')},{...result,stdout:result.stdout.replace('"Action":"pass"','"Action":"skip"')},{...result,stdout:events.slice(1).map(e=>JSON.stringify(e)).join('\n')}])assert.throws(()=>verifyOldNginxRuntimeRefusal(changed,ids));
});
