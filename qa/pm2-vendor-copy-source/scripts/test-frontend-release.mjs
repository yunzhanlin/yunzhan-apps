// Actual compiled watcher/transport, including controlled loopback HTTP. This
// is not installed two-release browser or real pending-task acceptance.
import test from 'node:test';import assert from 'node:assert/strict';import fs from 'node:fs';import http from 'node:http';import ts from '../web/node_modules/typescript/lib/typescript.js';
const read=p=>fs.readFileSync(new URL('../'+p,import.meta.url),'utf8');
const compile=s=>ts.transpileModule(s,{compilerOptions:{target:ts.ScriptTarget.ES2022,module:ts.ModuleKind.ESNext}}).outputText;
const {FrontendReleaseWatch,frontendEntry,assertFrontendMutationCurrent,frontendReleaseBytes,frontendReleaseTimeout,frontendReleaseInterval}=await import('data:text/javascript;base64,'+Buffer.from(compile(read('web/src/frontendRelease.ts'))).toString('base64'));
const base='http://127.0.0.1:19100/',before=base+'assets/index-beforeAA.js',html=entry=>`<!doctype html><html><head><script type="module" crossorigin src="./assets/index-${entry}.js"></script></head><body><div id="app"></div></body></html>`;
const response=(body=html('afterBBB'),url=base,headers={'Content-Type':'text/html'})=>{const r=new Response(body,{headers});Object.defineProperty(r,'url',{value:url});return r;};
const defer=()=>{let resolve;const promise=new Promise(r=>resolve=r);return{promise,resolve};};
test('entry identity accepts only a bounded single same-origin hashed module without executing markup',()=>{
 assert.equal(frontendEntry(html('beforeAA'),base),before);assert.equal(frontendEntry(html('beforeAA'),'https://panel.example/private/'),'https://panel.example/private/assets/index-beforeAA.js');
 for(const bad of [html('beforeAA')+html('afterBBB'),'<script type="module">doNotRun()</script>',html('beforeAA').replace('./assets/','https://foreign.invalid/assets/'),html('beforeAA').replace('.js"','.js?old=1"'),html('beforeAA').replace('.js"','.js#fragment"'),html('beforeAA').replace('src=','data-src='),'x'.repeat(frontendReleaseBytes+1),'<script src="./assets/index-beforeAA.js"></script>'])assert.equal(frontendEntry(bad,base),undefined,bad.slice(0,100));
 assert.equal(frontendReleaseBytes,16384);assert.equal(frontendReleaseTimeout,3000);assert.equal(frontendReleaseInterval,60000);
});
test('same original release stays usable; update is latched and never reloads or performs a mutation',async()=>{
 const states=[],calls=[];let now=0,body=html('beforeAA');const watch=new FrontendReleaseWatch({indexURL:base,loadedEntry:before,now:()=>now,publish:v=>states.push(v),fetch:async(...args)=>{calls.push(args);return response(body);}});
 try{await watch.check();assert.deepEqual(states,[{kind:'current'}]);now+=59999;await watch.check();assert.equal(calls.length,1);now++;body=html('afterBBB');await watch.check();assert.deepEqual(states.at(-1),{kind:'updated'});now+=60000;await watch.check();assert.equal(calls.length,2);for(const[url,options]of calls){assert.equal(url,base);assert.equal(options.method,'GET');assert.equal(options.cache,'no-store');assert.equal(options.redirect,'error');assert(options.signal instanceof AbortSignal);assert(!Object.hasOwn(options,'body'));}}finally{watch.dispose();}
});
test('single-flight and disposal cannot publish an old read or turn a close into another request',async()=>{
 const pending=defer(),states=[],calls=[];const watch=new FrontendReleaseWatch({indexURL:base,loadedEntry:before,publish:v=>states.push(v),fetch:(...args)=>{calls.push(args);return pending.promise;}});
 const a=watch.check(),b=watch.check();assert.equal(a,b);watch.dispose();assert(calls[0][1].signal.aborted);pending.resolve(response());await a;await watch.check();assert.equal(calls.length,1);assert.deepEqual(states,[]);
});
test('unknown document, private transport errors and bad body lengths do not fabricate a release',async()=>{
 for(const fixture of [()=>Promise.reject(Error('private transport payload must not be published')),async()=>response(html('afterBBB'),base,{'Content-Type':'application/json'}),async()=>response(html('afterBBB'),'https://foreign.invalid/'),async()=>response(html('afterBBB'),base,{'Content-Type':'text/html','Content-Length':String(frontendReleaseBytes+1)}),async()=>response(html('afterBBB'),base,{'Content-Type':'text/html','Content-Length':'-1'}),async()=>response('x'.repeat(frontendReleaseBytes+1))]){const states=[],watch=new FrontendReleaseWatch({indexURL:base,loadedEntry:before,publish:v=>states.push(v),fetch:fixture});try{await watch.check();assert.deepEqual(states,[{kind:'unknown'}]);}finally{watch.dispose();}}
});
test('actual loopback transport refuses redirects and incomplete streams within the unchanged 3-second budget',async t=>{
 const paths=[],server=http.createServer((req,res)=>{paths.push(req.url);if(req.url==='/redirect'){res.writeHead(302,{Location:'/'});res.end();}else if(req.url==='/stall'){res.writeHead(200,{'Content-Type':'text/html'});res.flushHeaders();}else{res.writeHead(200,{'Content-Type':'text/html'});res.end(html('afterBBB'));}});
 await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));t.after(()=>{server.closeAllConnections();server.close();});const origin='http://127.0.0.1:'+server.address().port;
 for(const route of ['/','/redirect','/stall']){const states=[],watch=new FrontendReleaseWatch({indexURL:origin+route,loadedEntry:origin+'/assets/index-beforeAA.js',publish:v=>states.push(v)});try{await watch.check();assert.deepEqual(states,[{kind:route==='/'?'updated':'unknown'}]);}finally{watch.dispose();}}assert.deepEqual(paths,['/','/redirect','/stall']);
});
test('only a known update blocks new writes; original task reads and explicit logout remain available',()=>{
 for(const kind of ['idle','current','unknown'])assert.doesNotThrow(()=>assertFrontendMutationCurrent({kind},'POST','/docker/projects'));
 for(const method of ['POST','PUT','PATCH','DELETE'])assert.throws(()=>assertFrontendMutationCurrent({kind:'updated'},method,'/docker/projects'),/不会自动重发/);
 for(const[method,path]of [['GET','/docker/jobs/'+'a'.repeat(32)],['GET','/jobs/'+'b'.repeat(32)],['POST','/logout'],['HEAD','/']])assert.doesNotThrow(()=>assertFrontendMutationCurrent({kind:'updated'},method,path));
});
test('actual shared API blocks before creating a ticket or fetching, without dropping old pending identities',async()=>{
 const app=read('web/src/App.vue'),code=compile(app.slice(app.indexOf('async function api<T>('),app.indexOf('const overviewReadGate ='))),calls=[],saved=new Map([['original','retained']]);
 const b={assertFrontendMutationCurrent,frontendReleaseStatus:{value:{kind:'updated'}},csrf:{value:'fixture-session'},accessEpoch:7,registryRequestIdentity:{begin:()=>assert.fail('no new ticket')},apiURL:path=>'/api'+path,randomId:()=>assert.fail('no new id'),user:{value:'fixture'},accessPlan:{value:{}},accountChanging:{value:false},clearAccessData:()=>assert.fail('no account change'),fetch:async(...args)=>{calls.push(args);return{ok:true,status:200,json:async()=>({retained:true})};}};
 const api=new Function(...Object.keys(b),code+';return api;')(...Object.values(b));await assert.rejects(api('/app-registry/website-analytics/update','POST',{}),/请先刷新/);await assert.rejects(api('/docker/projects','POST',{}),/请先刷新/);assert.equal(calls.length,0);await api('/docker/jobs/'+'a'.repeat(32));assert.equal(calls.length,1);assert.equal(saved.get('original'),'retained');
 assert(app.includes('frontendReleaseWatch.dispose()'));assert(app.includes('frontendReleaseWatch.check()'));assert(app.includes('data-testid="frontend-release-notice"'));assert(app.includes('function reloadFrontend() { window.location.reload(); }'));assert(!read('web/src/frontendRelease.ts').includes('location.reload'));
});
