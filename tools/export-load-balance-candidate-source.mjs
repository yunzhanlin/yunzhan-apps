// One fixed source-only candidate export, bound to a NORMAL AMD64 archive.
// Stable frozen distributors and their original exporter remain untouched.
import fs from 'node:fs';import path from 'node:path';import assert from 'node:assert/strict';
import {fileURLToPath} from 'node:url';import {execFileSync} from 'node:child_process';
import {createHash} from 'node:crypto';
const root=fileURLToPath(new URL('../',import.meta.url)),args=process.argv.slice(2);
assert(args.length===4&&args[0]==='--panel-root'&&args[2]==='--release','only exact source and normal release archive are accepted');
const panel=path.resolve(args[1]),archive=path.resolve(args[3]);assert.equal(fs.realpathSync(panel),panel);assert.equal(fs.realpathSync(archive),archive);
const basename=path.basename(archive);assert(/^panel-[0-9a-z.-]*candidate[0-9a-z.-]*-linux-amd64\.tar\.gz$/.test(basename));
const sha=b=>createHash('sha256').update(b).digest('hex'),prefix=basename.replace(/\.tar\.gz$/,'');
const input=JSON.parse(execFileSync('/usr/bin/tar',['-xOf',archive,prefix+'/SOURCE_INPUTS.json'],{maxBuffer:16<<20}));
assert(input.format===1&&sha(JSON.stringify(input.files))===input.inputs_sha256);
const output=path.join(root,'candidate/panel-integration-load-balance');assert(!fs.existsSync(output),'inspect original export; never overwrite a source cohort');
const build=fs.readFileSync(panel+'/packaging/build-release.sh','utf8');assert.equal(sha(build),input.files['packaging/build-release.sh'].sha256);
const scripts=new Set(['scripts/env.sh','scripts/upgrade-running-development.sh']),pending=[...build.matchAll(/\bnode(?:\s+--[a-z-]+)*\s+((?:scripts\/[a-z0-9-]+\.mjs)(?:\s+scripts\/[a-z0-9-]+\.mjs)*)/g)].flatMap(v=>v[1].split(/\s+/));
assert(pending.includes('scripts/test-load-balance-stream.mjs')&&pending.includes('scripts/test-load-balance-stream-account-entry.mjs'));
while(pending.length){
 const name=pending.shift();if(scripts.has(name))continue;
 const bytes=fs.readFileSync(panel+'/'+name);assert.equal(sha(bytes),input.files[name]?.sha256,name);scripts.add(name);
 for(const match of bytes.toString().matchAll(/from\s*['"]\.\/([a-z0-9-]+\.mjs)['"]/g))pending.push('scripts/'+match[1]);
}
const allowed=name=>['go.mod','go.sum','dev/provision-app.sh'].includes(name)||scripts.has(name)||/^(?:cmd|internal|packaging|web\/src|web\/public)\//.test(name)||/^dev\/[A-Za-z0-9_@.\\-]+\.(?:service|timer|mount|conf)$/.test(name)||/^web\/(?:index.html|package.json|package-lock.json|tsconfig.json|tsconfig.node.json|vite.config.ts)$/.test(name)||/^mobile\//.test(name)&&!/(?:^|\/)(?:build|\.build|\.gradle|\.swiftpm|xcuserdata|\.DS_Store)(?:\/|$)/.test(name)&&!name.endsWith('local.properties');
const selected=Object.keys(input.files).filter(allowed).sort(),payload=[];
for(const name of selected){
 assert(path.posix.normalize(name)===name&&!name.split('/').includes('..'));
 const source=panel+'/'+name,s=fs.lstatSync(source),expected=input.files[name];
 assert(s.isFile()&&!s.isSymbolicLink()&&s.nlink===1&&s.size<=2<<20&&!expected.link,name);
 const bytes=fs.readFileSync(source);assert(bytes.length===expected.bytes&&sha(bytes)===expected.sha256&&(s.mode&4095)===expected.mode,name);
 payload.push([name,bytes]);
}
assert(selected.includes('scripts/upgrade-running-development.sh')&&selected.includes('dev/provision-app.sh')&&selected.includes('internal/appcatalog/official_channel.go')&&selected.includes('scripts/release-build-baseline.mjs')&&selected.includes('scripts/load-balance-stream-fixture.mjs'));
fs.mkdirSync(output,{recursive:true,mode:0o755});const files={};
for(const[name,bytes]of payload){const target=path.join(output,name);fs.mkdirSync(path.dirname(target),{recursive:true,mode:0o755});fs.writeFileSync(target,bytes,{flag:'wx',mode:input.files[name].mode});files[name]=sha(bytes);}
const release={archive:basename,archive_sha256:sha(fs.readFileSync(archive)),frozen_inputs_sha256:input.inputs_sha256};
for(const[name,value]of [['source-sha256.json',{schema_version:1,release,files}],['release-source-inputs.json',{schema_version:1,...release,files}]])fs.writeFileSync(path.join(output,name),JSON.stringify(value,null,2)+'\n',{flag:'wx',mode:0o644});
console.log(JSON.stringify({ok:true,files:selected.length,output,source_inputs_sha256:input.inputs_sha256,no_binaries_or_private_keys:true,installation_or_all50_acceptance:false}));
