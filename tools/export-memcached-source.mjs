// A new immutable source scope. Never rewrite historical integration exports.
// The normal publisher independently verifies the signed archive before this
// mechanical export; every exported byte must match that archive's input index.
import fs from'node:fs';import path from'node:path';import{fileURLToPath}from'node:url';import{execFileSync}from'node:child_process';import{createHash}from'node:crypto';
const root=fileURLToPath(new URL('..',import.meta.url)),output=path.join(root,'panel-integration-memcached-update');
const sha=b=>createHash('sha256').update(b).digest('hex');
const args=process.argv.slice(2);if(args.length!==4||args[0]!=='--panel-root'||args[2]!=='--release')throw Error('usage: export-memcached-source.mjs --panel-root FROZEN_SOURCE --release NORMAL_AMD64_ARCHIVE');
const source=args[1],archive=args[3];for(const p of[source,archive])if(!path.isAbsolute(p)||path.normalize(p)!==p||fs.realpathSync(p)!==p)throw Error('explicit ordinary absolute inputs required');
const name=path.basename(archive);if(!/^panel-[a-z0-9.-]+-linux-amd64\.tar\.gz$/.test(name))throw Error('normal immutable AMD64 release required');
const original=fs.lstatSync(archive);if(!original.isFile()||original.isSymbolicLink()||original.nlink!==1||original.size<1||original.size>500*1024*1024)throw Error('archive identity/budget invalid');
if(fs.existsSync(output))throw Error('source scope already exists; never overwrite or repair it');
const archiveSHA=sha(fs.readFileSync(archive));
const inputs=JSON.parse(execFileSync('/usr/bin/tar',['-xOf',archive,name.replace(/\.tar\.gz$/,'')+'/SOURCE_INPUTS.json'],{maxBuffer:16*1024*1024}));
const frozen=JSON.parse(fs.readFileSync(path.join(source,'SOURCE_INPUTS.json')));if(inputs.format!==1||inputs.inputs_sha256!==frozen.inputs_sha256||JSON.stringify(inputs.files)!==JSON.stringify(frozen.files)||!inputs.files||Object.keys(inputs.files).length>20000)throw Error('source/archive frozen-input binding differs');
const selected=Object.entries(inputs.files).filter(([p])=>!p.startsWith('web/node_modules/')).sort(([a],[b])=>a.localeCompare(b));
for(const p of['go.mod','internal/executor/docker_app_update_worker_linux.go','internal/core/memcached_update_producer.go','internal/core/memcached_update_transaction.go','internal/appcatalog/memcached_release_envelope.go','web/src/MemcachedAppUpdate.vue','web/src/memcachedUpdateIdentity.ts','scripts/test-memcached-update-identity.mjs'])if(!inputs.files[p]?.sha256)throw Error('required original-update source missing: '+p);
if(selected.length<8||selected.length>5000)throw Error('source export inventory exceeds fixed scope');
const files={};
for(const[p,expected]of selected){
 if(path.posix.normalize(p)!==p||path.isAbsolute(p)||p.split('/').some(v=>!v||['..','.git','.local','node_modules'].includes(v))||typeof expected.sha256!=='string'||!/^[a-f0-9]{64}$/.test(expected.sha256)||expected.bytes<0||expected.bytes>2*1024*1024)throw Error('unexportable frozen source member: '+p);
 const file=path.join(source,p),info=fs.lstatSync(file);if(!info.isFile()||info.isSymbolicLink()||fs.realpathSync(file)!==file||info.size!==expected.bytes||sha(fs.readFileSync(file))!==expected.sha256)throw Error('frozen source drift: '+p);
 files[p]=expected.sha256;
}
const after=fs.lstatSync(archive);if(after.dev!==original.dev||after.ino!==original.ino||after.size!==original.size||after.mtimeMs!==original.mtimeMs||sha(fs.readFileSync(archive))!==archiveSHA)throw Error('archive changed during export preflight');
// Exclusive new directory and files. Any interrupted export is visibly partial
// and remains an error on reopening, never permission to overwrite old bytes.
fs.mkdirSync(output,{mode:0o755});
for(const[p,expected]of selected){
 const file=path.join(source,p),raw=fs.readFileSync(file);if(sha(raw)!==expected.sha256)throw Error('source changed after preflight: '+p);
 const target=path.join(output,p);fs.mkdirSync(path.dirname(target),{recursive:true,mode:0o755});fs.writeFileSync(target,raw,{flag:'wx',mode:expected.mode&0o111?0o755:0o644});
}
const release={archive:name,archive_sha256:archiveSHA,frozen_inputs_sha256:inputs.inputs_sha256};
fs.writeFileSync(path.join(output,'release-source-inputs.json'),JSON.stringify({...release,files},null,2)+'\n',{flag:'wx',mode:0o644});
fs.writeFileSync(path.join(output,'source-sha256.json'),JSON.stringify({format:1,release,files,test_overrides:{}},null,2)+'\n',{flag:'wx',mode:0o644});
for(const[p,expected]of Object.entries(files))if(sha(fs.readFileSync(path.join(output,p)))!==expected)throw Error('published source mismatch: '+p);
console.log(JSON.stringify({source_export:path.basename(output),files:Object.keys(files).length,...release,test_overrides:0}));
