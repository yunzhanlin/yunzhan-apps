import {test} from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import ts from '../web/node_modules/typescript/lib/typescript.js';
const read=relative=>readFileSync(new URL('../'+relative,import.meta.url),'utf8');
const emitted=ts.transpileModule(read('web/src/registryFreshness.ts'),{compilerOptions:{target:ts.ScriptTarget.ES2022,module:ts.ModuleKind.ESNext}}).outputText;
const {RegistryFreshness}=await import('data:text/javascript;base64,'+Buffer.from(emitted).toString('base64'));
const commit='a'.repeat(40), checked='2026-10-10T10:00:00Z';
const snapshot=(source={},version='1.8.1',status='healthy')=>({catalog:{schema_version:1,repository:'public-signed-fixture',apps:[{id:'load-balance',version}]},status:[status],source:{source:'verified-cache',stale:false,fetched_at:checked,...source}});
const fresh=()=>snapshot({source:'github',checked_at:checked,resolved_commit:commit});
test('catalog freshness is a bounded Git reference followed by immutable signed reads',()=>{
 const github=read('internal/appcatalog/github_catalog.go'),catalog=read('internal/appcatalog/catalog.go');
 assert.match(github,/https:\/\/api\.github\.com\/repos\/yunzhanlin\/yunzhan-apps\/git\/ref\/heads\/main/);
 assert.match(github,/c\.BaseURL != DefaultBaseURL/);assert.match(github,/readResponse\(req, 16<<10\)/);
 assert.match(github,/reference\.Ref != "refs\/heads\/main"/);assert.match(github,/reference\.Object\.Type != "commit"/);
 assert.match(github,/\^\[0-9a-f\]\{40\}\$/);assert.match(github,/uniqueGitHubReference\(raw\)/);
 assert.match(github,/githubCatalogCommitBase\+commit\+"\/"\+relative/);
 assert.doesNotMatch(github,/Authorization|\.URL\.Query\(|\.Set\("check"/);
 assert.match(catalog,/transport\.CheckRedirect =/);assert.match(catalog,/http\.ErrUseLastResponse/);
 assert.match(catalog,/c\.resolveCatalogCommit\(ctx\)/);assert.match(catalog,/c\.verifyCatalog\(raw, signature\)/);
 assert.match(catalog,/catalogProgress\(previous, catalog\)/);assert.match(catalog,/Stale: true/);
 assert.match(catalog,/ResolvedCommit: commit/);
});
test('store shows actual checked time and successful resolved commit without unlocking stale updates',()=>{
 const view=read('web/src/App.vue');
 assert.match(view,/registryLastCheck\.checked_at/);
 assert.match(view,/!appRegistry\.source\.stale && registryLastCheck\?\.resolved_commit/);
 assert.match(view,/最近成功定位提交/);assert.match(view,/registryLastCheck\.resolved_commit\.slice\(0, 12\)/);
 assert.match(view,/未能确认仓库最新版本，当前显示已验签缓存/);
 assert.match(view,/registryInstalling\.includes\(app\.id\) \|\| appRegistry\.source\.stale/);
 assert.match(read('packaging/build-release.sh'),/test-registry-freshness\.mjs/);
 assert.match(view,/registryFreshness\.reset\(\)/);assert.match(view,/applyRegistryRead\(ticket, await api<AppRegistry>/);
 assert.match(view,/if \(d && registryTicket\) applyRegistryRead\(registryTicket, d\)/);
 assert.doesNotMatch(view,/appRegistry\.value = await api<AppRegistry>/);
});
test('actual receipt survives repeated cache polls without inventing a new check',()=>{
 const state=new RegistryFreshness();assert.equal(state.lastSuccessfulCheck(),undefined);
 state.complete(state.begin('check'),fresh());
 for(let i=0;i<12;i++){
  const response=state.complete(state.begin('poll'),snapshot({},'1.8.1','row-'+i));
  assert.equal(response.source.checked_at,undefined);assert.equal(response.source.resolved_commit,undefined);
  assert.deepEqual(response.status,['row-'+i]);assert.deepEqual(state.lastSuccessfulCheck(),{checked_at:checked,resolved_commit:commit});
 }
});
test('polls begun before or during an interactive check cannot replace its result',()=>{
 for(const order of ['before','during']){
  const state=new RegistryFreshness();let poll,check;
  if(order==='before'){poll=state.begin('poll');check=state.begin('check');}else{check=state.begin('check');poll=state.begin('poll');}
  assert.equal(state.complete(poll,snapshot()),undefined);assert(state.complete(check,fresh()));
  assert.equal(state.complete(poll,snapshot({},'OLD')),undefined);
  assert.deepEqual(state.lastSuccessfulCheck(),{checked_at:checked,resolved_commit:commit});
 }
});
test('failed real check remains stale and locked across cache polls until a genuine success',()=>{
 const state=new RegistryFreshness();let previous=state.complete(state.begin('check'),fresh());
 const ticket=state.begin('check');previous=state.failure(ticket,previous,'GitHub quota exhausted');
 assert(previous.source.stale);assert.equal(state.lastSuccessfulCheck(),undefined);
 for(let i=0;i<8;i++){
  previous=state.complete(state.begin('poll'),snapshot({},'1.8.1','fresh-installed-row-'+i));
  assert(previous.source.stale);assert.equal(previous.source.error,'GitHub quota exhausted');
  assert.equal(previous.source.checked_at,undefined);assert.equal(state.lastSuccessfulCheck(),undefined);
  assert.deepEqual(previous.status,['fresh-installed-row-'+i]);
 }
 previous=state.complete(state.begin('check'),fresh());assert(!previous.source.stale);assert.equal(state.lastSuccessfulCheck().resolved_commit,commit);
});
test('server-marked stale cache also survives polling; successful fresh background fetch can recover',()=>{
 const state=new RegistryFreshness();state.complete(state.begin('check'),fresh());
 state.complete(state.begin('check'),snapshot({stale:true,error:'signature invalid',checked_at:checked}));
 assert(state.complete(state.begin('poll'),snapshot()).source.stale);assert.equal(state.lastSuccessfulCheck(),undefined);
 const recovered=state.complete(state.begin('poll'),fresh());assert(!recovered.source.stale);assert.equal(state.lastSuccessfulCheck().resolved_commit,commit);
});
test('newer check wins in either completion order; older success cannot hide newer failure',()=>{
 for(const newerFirst of [true,false]){
  const state=new RegistryFreshness(),older=state.begin('check'),newer=state.begin('check');
  if(newerFirst)assert(state.failure(newer,snapshot(),'new failure').source.stale);
  assert.equal(state.complete(older,fresh()),undefined);assert(!state.isCurrentCheck(older));
  if(!newerFirst)assert(state.failure(newer,snapshot(),'new failure').source.stale);
  assert.equal(state.lastSuccessfulCheck(),undefined);assert(state.complete(state.begin('poll'),snapshot()).source.stale);
 }
});
test('account reset discards old receipts, results and errors without blocking the next account',()=>{
 const state=new RegistryFreshness();state.complete(state.begin('check'),fresh());
 const oldPoll=state.begin('poll'),oldCheck=state.begin('check');state.reset();
 assert.equal(state.lastSuccessfulCheck(),undefined);assert.equal(state.complete(oldPoll,fresh()),undefined);
 assert.equal(state.failure(oldCheck,snapshot(),'old account error'),undefined);assert(!state.isCurrentCheck(oldCheck));
 const cached=state.complete(state.begin('poll'),snapshot());assert(cached&&!cached.source.stale);assert.equal(state.lastSuccessfulCheck(),undefined);
 assert(state.complete(state.begin('check'),fresh()));
});
test('catalog identity changes clear the old commit and out-of-order polls cannot restore it',()=>{
 const state=new RegistryFreshness();state.complete(state.begin('check'),fresh());
 const older=state.begin('poll'),newer=state.begin('poll');assert(state.complete(newer,snapshot({},'new-version')));
 assert.equal(state.lastSuccessfulCheck(),undefined);assert.equal(state.complete(older,snapshot()),undefined);
});
test('custom sources, malformed receipts and oversized identity never invent GitHub commit evidence',()=>{
 for(const source of [{source:'github',checked_at:checked},{source:'github',checked_at:'invalid',resolved_commit:commit},{source:'github',checked_at:checked,resolved_commit:'BAD'},{}]){
  const state=new RegistryFreshness();state.complete(state.begin('check'),snapshot(source));
  if(source.checked_at===checked&&source.resolved_commit===undefined)assert.deepEqual(state.lastSuccessfulCheck(),{checked_at:checked,resolved_commit:undefined});
  else assert.equal(state.lastSuccessfulCheck(),undefined);
 }
 const state=new RegistryFreshness(),large=fresh();large.catalog.apps[0].padding='x'.repeat((1<<20)+1);
 state.complete(state.begin('check'),large);assert.equal(state.lastSuccessfulCheck(),undefined);
});
test('returned receipt is a defensive copy and state never persists credentials or trusts a cache as fresh',()=>{
 const state=new RegistryFreshness();state.complete(state.begin('check'),fresh());
 const receipt=state.lastSuccessfulCheck();receipt.resolved_commit='b'.repeat(40);assert.equal(state.lastSuccessfulCheck().resolved_commit,commit);
 assert.doesNotMatch(read('web/src/registryFreshness.ts'),/localStorage|sessionStorage|Authorization|fetch\(/);
});
