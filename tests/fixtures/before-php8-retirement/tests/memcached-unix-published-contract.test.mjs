import test from'node:test';import assert from'node:assert/strict';import fs from'node:fs';import path from'node:path';import{fileURLToPath}from'node:url';import{createHash,createPublicKey,verify}from'node:crypto';
import{validateManifest}from'../tools/lib.mjs';import{memcachedUnixCases}from'../tools/memcached-unix-fixtures.mjs';
import{memcachedUnixErrors}from'../tools/memcached-unix-contract.mjs';
import{exactReviewedPreMemcachedRepository,predecessorScope}from'../tools/reviewed-pre-memcached-repository.mjs';
import{historicalPHPBoundedCases}from'./reviewed-memcached-unix-inputs.mjs';import{phpBoundedCases}from'../tools/php-bounded-fixtures.mjs';
import{originalReviewedMemcachedUnixTest,reviewedMemcachedUnixReaders}from'./reviewed-memcached-unix-test-frames.mjs';
import{prepareFiveAppHistoricalWorkflow,originalReviewedFiveAppHistoricalWorkflow,original34WorkflowSHA,original34RootCalls,currentF48ABICommand,originalF47NegativeCommand,currentUnixSchemaCommand}from'./reviewed-five-app-workflow.mjs';
const root=fileURLToPath(new URL('../',import.meta.url)),read=n=>fs.readFileSync(path.join(root,n)),json=n=>JSON.parse(read(n)),sha=b=>createHash('sha256').update(b).digest('hex'),oldScope=predecessorScope+'/',sourceScope='registry/reviewed-distributors/before-memcached-unix24blfi/',expectedChanges=['memcached','php-82','php-83','php-84','php-85'];
test('actual original-key current50 changes exactly five packages, retains other45 and every previous signed endpoint',()=>{
 const raw=read('dist/catalog-v1.json'),catalog=JSON.parse(raw),old=json(oldScope+'dist/catalog-v1.json'),pub=read('signatures/catalog-v1.pub.pem'),bundle=json('signatures/catalog-v1.bundle.json');
 assert.equal(sha(pub),'659ea4edcecaf23a586e2ff371616fde5f6ee7c219fb70fa978816e2b10acf75');assert.equal(bundle.catalog,raw.toString());assert(verify(null,raw,createPublicKey(pub),Buffer.from(bundle.signature,'base64')));
 assert.equal(catalog.apps.length,50);assert.equal(new Set(catalog.apps.map(a=>a.id)).size,50);
 assert.deepEqual(catalog.apps.filter(a=>JSON.stringify(a)!==JSON.stringify(old.apps.find(b=>b.id===a.id))).map(a=>a.id).sort(),expectedChanges);
 for(const a of old.apps)assert.equal(sha(read('dist/apps/'+a.id+'/'+a.version+'/manifest.json')),a.sha256,a.id);
 for(const a of catalog.apps){const m=json('dist/apps/'+a.id+'/'+a.version+'/manifest.json');assert.equal(sha(read('dist/apps/'+a.id+'/'+a.version+'/manifest.json')),a.sha256);assert.deepEqual(validateManifest(m),[],a.id);}
});
test('current Unix and PHP manifests declare real independent compiled handlers without promising commercial acceptance',()=>{
 const apps=json('registry/apps.json').apps,mem=apps.find(a=>a.id==='memcached');assert.equal(mem.version,'1.6.45-compat4');assert.equal(mem.stage,'ready');
 assert.deepEqual([...mem.required_panel_features].sort(),['compose-memcached-digest-v1','compose-memcached-retirement-v1','compose-memcached-unix-v1']);assert.deepEqual(memcachedUnixErrors(mem),[]);
 for(const id of expectedChanges.filter(id=>id!=='memcached')){const m=apps.find(a=>a.id===id);assert(m.version.endsWith('-compat2'));assert.deepEqual(m.required_panel_features,['php-security-20261021-v1','php-bounded-native-build-v1']);}
});
test('all80 current50 historical and malformed Unix fixtures keep exact JS contract acceptance',()=>{
 const cases=memcachedUnixCases(root);assert.equal(cases.length,80);assert.equal(cases.filter(c=>c.valid).length,54);assert.equal(cases.filter(c=>!c.valid).length,26);
 for(const c of cases)assert.equal(validateManifest(c.manifest).length===0,c.valid,c.name);
});
test('new schema adds only the two Unix capabilities one closed branch and three scoped guards; all older schema semantics remain exact',()=>{
 const before=json(sourceScope+'schema/app.schema.json'),schema=json('schema/app.schema.json'),reversed=structuredClone(schema),flags=['compose-memcached-unix-v1','compose-memcached-retirement-v1'];
 assert.equal(schema.allOf.length,before.allOf.length+3);
 const branches=schema.allOf[0].then.oneOf.filter(c=>c.properties?.id?.const==='memcached'&&c.properties?.version?.const==='1.6.45-compat4');assert.equal(branches.length,1);assert.deepEqual(branches[0].properties.stage.enum,['integration','ready']);
 reversed.properties.required_panel_features.items.enum=reversed.properties.required_panel_features.items.enum.filter(v=>!flags.includes(v));
 reversed.allOf[0].then.oneOf=reversed.allOf[0].then.oneOf.filter(c=>!(c.properties?.id?.const==='memcached'&&c.properties?.version?.const==='1.6.45-compat4'));
 reversed.allOf.splice(before.allOf.length);assert.deepEqual(reversed,before);
 const tail=schema.allOf.slice(before.allOf.length);assert.equal(tail[0].if.properties.id.const,'memcached');assert.equal(tail[0].if.properties.version.const,'1.6.45-compat4');assert.deepEqual(tail[1].if.anyOf.map(c=>c.properties.required_panel_features.contains.const),flags);assert.deepEqual(tail[2].then.properties.version.enum,['1.6.45-compat1','1.6.45-compat2','1.6.45-compat4']);
});
test('real merged distributor sources and complete34-job predecessor retain their exact original bytes',()=>{
 const pins={"schema/app.schema.json":"c0d4934cb2432645e4fcca13682d11580393e302479842001fbc5787c932f081","tools/lib.mjs":"9ac031b7c1b4b418dd86b5df4bfa9104bedd7a9a53d8498ceaeade3491bdb9c8","tools/php-security-contract.mjs":"55ce07ed892c64332a00168a9d7e3f2d0c2ff3025486c763ff5b961c7d9ec8e9","tools/php-bounded-contract.mjs":"47eb004565c61a453c7df63e1a38f4097a4cda38ead43c218074653846755c62",".github/workflows/verify.yml":"beb05395b72dd5891329f3b8a15a09d8d3b75aa65ca3f506fe3e73c1aa77642d"};for(const[name,digest]of Object.entries(pins))assert.equal(sha(read(sourceScope+name)),digest,name);
 assert.equal(exactReviewedPreMemcachedRepository(['--repo-root',predecessorScope],root),path.join(path.resolve(root),predecessorScope)+'/');
 for(const args of[['--repo-root','/tmp'],['--repo-root',predecessorScope+'/'],['--source',predecessorScope],['--repo-root',predecessorScope,'--allow']])assert.throws(()=>exactReviewedPreMemcachedRepository(args,root));
});
test('eleven historical readers restore every original assertion byte and refuse undeclared edits',()=>{
 assert.equal(Object.keys(reviewedMemcachedUnixReaders).length,11);
 for(const[name,record]of Object.entries(reviewedMemcachedUnixReaders)){const raw=read(name),old=originalReviewedMemcachedUnixTest(name,raw);assert.equal(sha(old),record.before);assert.throws(()=>originalReviewedMemcachedUnixTest(name,Buffer.concat([raw,Buffer.from('\n// changed assertion')])));assert.strictEqual(originalReviewedMemcachedUnixTest(name,old),old);}
});
test('historical PHP selection replaces only its exact signed50 input while all original positive and236 negative cases stay unchanged',()=>{
 const now=phpBoundedCases(root),old=historicalPHPBoundedCases(root);assert.equal(old.length,now.length);assert.equal(old.filter(c=>!c.valid).length,236);
 assert.deepEqual(old.filter(c=>!c.name.startsWith('current50:')),now.filter(c=>!c.name.startsWith('current50:')));
 assert.equal(old.filter(c=>c.name.startsWith('current50:')).length,50);
});
test('all34 workflow jobs and all original commands and bounds are byte-identical after only declared catalog and extra closed ABI/schema gates are restored',()=>{
 const prior=read(sourceScope+'.github/workflows/verify.yml'),current=read('.github/workflows/verify.yml');assert.equal(sha(prior),original34WorkflowSHA);assert(prepareFiveAppHistoricalWorkflow(prior).equals(current));
 assert(originalReviewedFiveAppHistoricalWorkflow(current).equals(prior));assert.equal(originalReviewedFiveAppHistoricalWorkflow(current.toString()),prior.toString());
 const text=current.toString();assert.equal(text.slice(text.indexOf('\njobs:\n')).match(/^  [a-z0-9-]+:$/gm).length,34);assert.equal(original34RootCalls.length,8);assert.equal(new Set(original34RootCalls.map(c=>c.job)).size,7);
 for(const cmd of[currentF48ABICommand,originalF47NegativeCommand,currentUnixSchemaCommand])assert.equal(text.split(cmd).length,2);
 for(const bad of[text.replace('go vet ./...','true'),text.replace('timeout 900s','timeout 901s'),text.replace(currentUnixSchemaCommand,'true'),text.replace(originalF47NegativeCommand,'true'),text.replace('test -p 1 ./...','test -p 1 ./... -run TestNone')])assert.throws(()=>originalReviewedFiveAppHistoricalWorkflow(Buffer.from(bad)));
});
