import test from'node:test';import assert from'node:assert/strict';import{readFileSync}from'node:fs';import ts from'../web/node_modules/typescript/lib/typescript.js';
const read=n=>readFileSync(new URL('../'+n,import.meta.url),'utf8'),compile=s=>ts.transpileModule(s,{compilerOptions:{target:ts.ScriptTarget.ES2022,module:ts.ModuleKind.ESNext}}).outputText;
const helper=read('web/src/mobileDelivery.ts'),component=read('web/src/AppModuleReport.vue');
const{mobileArtifactURL}=await import('data:text/javascript;base64,'+Buffer.from(compile(helper)).toString('base64'));
const backend=read('internal/core/app_mobile.go'),release=backend.match(/const release = "([^"]+)"/)[1];
const current=[...backend.matchAll(/"filename": "([^"]+)", "url": release \+ "[^"]+", "sha256": "([a-f0-9]{64})"/g)].map(m=>({filename:m[1],url:release+m[1],sha256:m[2]}));assert.equal(current.length,3);
const legacy=[
 ['yunzhan-mobile-1.3.0-android.apk','45dd8bc7048ad0df15805dc1887f509b8905390eace6a223c552c9425fc74db2'],
 ['yunzhan-mobile-1.3.0-ios-unsigned.tar.gz','272d6ffbf0b636b121311f6565f3203ae4f460852d023db3882523507071c219'],
 ['yunzhan-mobile-1.3.0-source.tar.gz','797f47e79e8ef799c813fc9a6c2c9ce2f56e8cb159c8896defbcfed1b61e865d'],
].map(([filename,sha256])=>({filename,sha256,url:'https://github.com/yunzhanlin/yunzhan-apps/releases/download/v0.1.0-dev.proapps11/'+filename}));
test('actual current compiled Go producer emits exactly the three supported1.3.2 delivery links',()=>{
 assert(release.endsWith('/mobile-v1.3.2/'));for(const row of current)assert.equal(mobileArtifactURL('1.3.2',row),row.url);
});
test('every genuine legacy1.3.0 endpoint keeps its exact original cohort and digest',()=>{for(const row of legacy)assert.equal(mobileArtifactURL('1.3.0',row),row.url);});
test('cross-version mixed filename digest or report identity never becomes an allowed download',()=>{
 for(const row of current){for(const version of['1.3.0','1.3.1','1.3.3','1.3.2 ','v1.3.2','__proto__','constructor',null,{},[]])assert.equal(mobileArtifactURL(version,row),undefined);for(const old of legacy){assert.equal(mobileArtifactURL('1.3.2',{...row,sha256:old.sha256}),undefined);assert.equal(mobileArtifactURL('1.3.2',{...row,filename:old.filename}),undefined);assert.equal(mobileArtifactURL('1.3.0',row),undefined);}}
});
test('aliases query fragments encoded separators credentials traversal and external origins are not normalized',()=>{
 const row=current[0];for(const url of[
  row.url+'?download=1',row.url+'#file',row.url.replace('https:','http:'),row.url.replace('github.com','github.com.evil.invalid'),row.url.replace('github.com','evil.invalid'),row.url.replace('github.com/','github.com@evil.invalid/'),row.url.replace('/releases/','//releases/'),row.url.replace('/download/','/download/../download/'),row.url.replace('/download/','%2fdownload/'),row.url.replace('yunzhanlin','Yunzhanlin'),row.url.replace('https:','HTTPS:'),'javascript:alert(1)','data:text/html,unsafe','file:///etc/passwd','//github.com/path',
 ])assert.equal(mobileArtifactURL('1.3.2',{...row,url}),undefined,url);
});
test('malformed inherited accessor and proxy records cannot produce a URL or execute a getter',()=>{
 const row=current[0];for(const input of[null,undefined,[],{},row.url,Object.create(row),{...row,filename:undefined},{...row,url:null},{...row,sha256:row.sha256.toUpperCase()},{...row,sha256:'0'.repeat(64)}])assert.equal(mobileArtifactURL('1.3.2',input),undefined);
 let reads=0;const accessor={...row};Object.defineProperty(accessor,'url',{get(){reads++;return row.url;}});assert.equal(mobileArtifactURL('1.3.2',accessor),undefined);assert.equal(reads,0);
 assert.equal(mobileArtifactURL('1.3.2',new Proxy(row,{getOwnPropertyDescriptor(){throw Error('not JSON');}})),undefined);
 const before=JSON.stringify(row);mobileArtifactURL('1.3.2',row);assert.equal(JSON.stringify(row),before);
});
test('the actual Vue report wrapper binds its own report version and all link fields, with visible refusal',()=>{
 const start=component.indexOf('function mobileDownloadURL('),end=component.indexOf('</script>',start);assert(start>0&&end>start);
 const f=new Function('props','mobileArtifactURL',compile(component.slice(start,end))+';return mobileDownloadURL;')({report:{version:'1.3.2'}},mobileArtifactURL);
 for(const row of current)assert.equal(f(row),row.url);assert.equal(f({...current[0],sha256:'0'.repeat(64)}),undefined);
 assert(component.includes('v-if="mobileDownloadURL(item)" :href="mobileDownloadURL(item)"'));assert(component.includes('target="_blank" rel="noopener noreferrer"'));assert(component.includes(':aria-label="`下载${item.name}`"'));assert(component.includes('交付物与报告版本或内置发布清单不一致'));assert(!helper.includes('fetch(')&&!helper.includes('localStorage')&&!helper.includes('window.location'));
});
test('ordinary programme builds cannot omit the new real-delivery regression',()=>{assert.match(read('packaging/build-release.sh'),/node --test scripts\/test-mobile-delivery-links\.mjs/);});
test('the official8.2.4 security backport is exact in package lock and installed build inputs; dev remains loopback only',()=>{
 const pkg=JSON.parse(read('web/package.json')),lock=JSON.parse(read('web/package-lock.json')),installed=JSON.parse(read('web/node_modules/vite/package.json'));
 assert.equal(pkg.devDependencies.vite,'8.2.4');assert.equal(lock.packages[''].devDependencies.vite,'8.2.4');assert.equal(installed.version,'8.2.4');
 const entry=lock.packages['node_modules/vite'];assert.equal(entry.version,'8.2.4');assert.equal(entry.resolved,'https://registry.npmjs.org/vite/-/vite-8.2.4.tgz');
 assert.equal(entry.integrity,'sha512-lfauXnrf2x0p+UoA+wXh0dgFWnUjCyG6Js95KBkgaCwUU9k0DAHI4W6Q0WCx+h+5g+Alce1y4Zi2QjjK0UvGBw==');
 assert.equal(pkg.scripts.dev,'vite --host 127.0.0.1');assert(!pkg.scripts.build.includes('--host'));
});
