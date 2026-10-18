// Export only this new immutable program scope after the ORIGINAL normal
// release verifier proves its detached signature. Historical scopes stay exact.
import fs from 'node:fs';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
import {execFileSync} from 'node:child_process';
import {createHash} from 'node:crypto';
const root=fileURLToPath(new URL('..',import.meta.url));
const output=path.join(root,'panel-integration-memcached-revision');
const sha=b=>createHash('sha256').update(b).digest('hex');
const args=process.argv.slice(2);
if(args.length!==8||args[0]!=='--panel-root'||args[2]!=='--release'||args[4]!=='--public-key'||args[6]!=='--openssl')throw Error('usage: export-memcached-revision-source.mjs --panel-root FROZEN --release NORMAL_AMD64_ARCHIVE --public-key ORIGINAL_PROGRAM_PUBLIC_KEY --openssl OPENSSL');
const [source,archive,key,openssl]=[args[1],args[3],args[5],args[7]];
for(const p of [source,archive,key,openssl])if(!path.isAbsolute(p)||path.normalize(p)!==p||fs.realpathSync(p)!==p)throw Error('ordinary explicit canonical absolute inputs required');
const name=path.basename(archive);
if(name!=='panel-0.1.0-dev.proapps24memrevisionbgex-linux-amd64.tar.gz')throw Error('only the new normal revision archive is supported');
const original=fs.lstatSync(archive),publicInfo=fs.lstatSync(key);
if(!original.isFile()||original.nlink!==1||original.size<1||original.size>500*1024*1024)throw Error('archive identity/budget invalid');
if(!publicInfo.isFile()||publicInfo.nlink!==1||publicInfo.size<1||publicInfo.size>16384||sha(fs.readFileSync(key))!=='4ccfcc861d56a41e3ba7f7ace7e2432c815f366c58448d783df92c6632f01339')throw Error('original program PUBLIC trust key required');
const verifier=path.join(source,'packaging/signed-release.py');
if(sha(fs.readFileSync(verifier))!=='fe128e82b4e11345b320cd782134768bfe1a4df14947c425d7494873a7a7b7b5')throw Error('normal release verifier drift');
if(fs.existsSync(output))throw Error('source scope already exists; never overwrite, resume or repair it');
const archiveSHA=sha(fs.readFileSync(archive));
const verified=execFileSync('/usr/bin/python3',['-B',verifier,'--openssl',openssl,'verify',archive,'--public-key',key],{encoding:'utf8',timeout:45000,stdio:['ignore','pipe','pipe']});
if(!verified.includes(archiveSHA))throw Error('normal original-key signature verification did not bind this archive');
const inputs=JSON.parse(execFileSync('/usr/bin/tar',['-xOf',archive,name.replace(/\.tar\.gz$/,'')+'/SOURCE_INPUTS.json'],{maxBuffer:16*1024*1024}));
const frozen=JSON.parse(fs.readFileSync(path.join(source,'SOURCE_INPUTS.json')));
if(inputs.format!==1||inputs.inputs_sha256!=='874d92562e8f39b4b9eabe1b83e13cc2ff5fcaca39d900034a9a86977d72c97a'||inputs.inputs_sha256!==frozen.inputs_sha256||JSON.stringify(inputs.files)!==JSON.stringify(frozen.files)||Object.keys(inputs.files).length!==17098)throw Error('original signed source/input identity differs');
const selected=Object.entries(inputs.files).filter(([p])=>!p.startsWith('web/node_modules/')).sort(([a],[b])=>a.localeCompare(b));
if(selected.length!==1455)throw Error('new exact source export inventory differs');
for(const p of ['internal/core/app_registry.go','internal/core/app_registry_memcached_revision_test.go','internal/core/memcached_update_close.go','internal/core/memcached_update_close_test.go','internal/core/memcached_update_producer.go','internal/executor/docker_app_update_worker_linux.go','web/src/App.vue','web/src/MemcachedAppUpdate.vue','web/src/memcachedUpdateIdentity.ts','scripts/test-memcached-update-identity.mjs'])if(!inputs.files[p]?.sha256)throw Error('required real update/revision source missing: '+p);
const files={};
for(const [p,expected] of selected){
 if(path.posix.normalize(p)!==p||path.isAbsolute(p)||p.split('/').some(v=>!v||['..','.git','.local','node_modules'].includes(v))||typeof expected.sha256!=='string'||!/^[a-f0-9]{64}$/.test(expected.sha256)||expected.bytes<0||expected.bytes>2*1024*1024)throw Error('unexportable source member: '+p);
 const file=path.join(source,p),s=fs.lstatSync(file);
 if(!s.isFile()||s.isSymbolicLink()||fs.realpathSync(file)!==file||s.size!==expected.bytes||sha(fs.readFileSync(file))!==expected.sha256)throw Error('frozen source drift: '+p);
 files[p]=expected.sha256;
}
const after=fs.lstatSync(archive);
if(after.dev!==original.dev||after.ino!==original.ino||after.size!==original.size||after.mtimeMs!==original.mtimeMs||sha(fs.readFileSync(archive))!==archiveSHA)throw Error('archive changed during verified preflight');
fs.mkdirSync(output,{mode:0o755});
for(const [p,expected] of selected){
 const raw=fs.readFileSync(path.join(source,p));if(sha(raw)!==expected.sha256)throw Error('source changed after preflight: '+p);
 const target=path.join(output,p);fs.mkdirSync(path.dirname(target),{recursive:true,mode:0o755});fs.writeFileSync(target,raw,{flag:'wx',mode:expected.mode&0o111?0o755:0o644});
}
const release={archive:name,archive_sha256:archiveSHA,frozen_inputs_sha256:inputs.inputs_sha256};
for(const [leaf,body] of [['release-source-inputs.json',{...release,files}],['source-sha256.json',{format:1,release,files,test_overrides:{}}]])fs.writeFileSync(path.join(output,leaf),JSON.stringify(body,null,2)+'\n',{flag:'wx',mode:0o644});
for(const [p,digest] of Object.entries(files))if(sha(fs.readFileSync(path.join(output,p)))!==digest)throw Error('published source drift: '+p);
console.log(JSON.stringify({source_export:path.basename(output),files:selected.length,...release,test_overrides:0,normal_original_key_signature_verified:true}));
