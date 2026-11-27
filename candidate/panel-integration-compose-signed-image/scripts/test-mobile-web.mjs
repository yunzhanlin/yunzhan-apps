import test from 'node:test';import assert from 'node:assert/strict';import {readFileSync}from'node:fs';import ts from'../web/node_modules/typescript/lib/typescript.js';
const source=readFileSync(new URL('../web/src/mobileWeb.ts',import.meta.url),'utf8');const compiled=ts.transpileModule(source,{compilerOptions:{target:ts.ScriptTarget.ES2022,module:ts.ModuleKind.ESNext}}).outputText;const web=await import('data:text/javascript;base64,'+Buffer.from(compiled).toString('base64'));
test('copy and open retain only the same origin and the real safety entry, without credentials or temporary tokens',()=>{
 assert.equal(web.mobileWebURL('https://panel.example:28888/?tmp_token=private#secret'),'https://panel.example:28888/');
 assert.equal(web.mobileWebURL('https://panel.example/0123456789abcdef0123456789abcdef/?tmp_token=private'),'https://panel.example/0123456789abcdef0123456789abcdef/');
 assert.equal(web.mobileWebURL('http://127.0.0.1:19100/'),'http://127.0.0.1:19100/');
 for(const url of['javascript:alert(1)','file:///private/data','https://user:password@panel.example/','not a URL'])assert.equal(web.mobileWebURL(url),undefined);
 for(const url of['http://127.0.0.1:19100/','http://127.9.8.7/','http://[::1]/','https://test.localhost/'])assert(web.mobileWebIsLoopback(url));assert(!web.mobileWebIsLoopback('https://localhost.example/'));
});
test('install is explicit, single use, cancellation safe, and an older outcome cannot discard a newer browser prompt',async()=>{
 const target=new EventTarget();web.trackMobileWebInstall(target);let calls=0,updates=0;const unwatch=web.watchMobileWebInstall(()=>updates++);
 let finish;const first=new Event('beforeinstallprompt',{cancelable:true});first.userChoice=new Promise(r=>finish=r);first.prompt=async()=>{calls++;};target.dispatchEvent(first);assert(first.defaultPrevented);assert(web.mobileWebInstallAvailable());assert.equal(calls,0);
 const waiting=web.requestMobileWebInstall();assert.equal(await web.requestMobileWebInstall(),'unavailable');assert.equal(calls,1);
 const next=new Event('beforeinstallprompt',{cancelable:true});next.prompt=async()=>{calls++;};next.userChoice=Promise.resolve({outcome:'dismissed'});target.dispatchEvent(next);finish({outcome:'accepted'});assert.equal(await waiting,'accepted');assert(web.mobileWebInstallAvailable());assert.equal(await web.requestMobileWebInstall(),'dismissed');assert.equal(calls,2);assert(!web.mobileWebInstallAvailable());
 target.dispatchEvent(next);target.dispatchEvent(new Event('appinstalled'));assert(!web.mobileWebInstallAvailable());const n=updates;unwatch();target.dispatchEvent(next);assert.equal(updates,n);
});

const {beforeMobileWebBuild}=await import('./release-build-baseline.mjs');
test('normal builds cannot omit duplicate alter or move the web gate; unrelated build edits remain visible',()=>{
 const text=readFileSync(new URL('../packaging/build-release.sh',import.meta.url),'utf8');const previous='(cd "$BUILD_ROOT" && /opt/homebrew/bin/node --test scripts/test-mobile-delivery-links.mjs) 2>&1 | tee -a "$STAGE/$NAME/BUILD_CHECKS.txt"\n';const addition='(cd "$BUILD_ROOT" && /opt/homebrew/bin/node --test scripts/test-mobile-web.mjs) 2>&1 | tee -a "$STAGE/$NAME/BUILD_CHECKS.txt"\n';
 assert(beforeMobileWebBuild(text).includes(previous));for(const bad of[text.replace(addition,''),text.replace(addition,addition+addition),text.replace(addition,addition.replace('--test','--check')),text.replace(previous+addition,addition+previous)])assert.throws(()=>beforeMobileWebBuild(bad));assert.notEqual(beforeMobileWebBuild(text.replace('go vet ./...','unreviewed-command ./...')),beforeMobileWebBuild(text));
});
