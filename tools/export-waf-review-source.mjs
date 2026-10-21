// Exclusive independent export from the normal signed release. No historical
// source, receipt or signature is modified. Publisher verification is separate.
import fs from 'node:fs';
import path from 'node:path';
import assert from 'node:assert/strict';
import {fileURLToPath} from 'node:url';
import {execFileSync} from 'node:child_process';
import {createHash} from 'node:crypto';
const root=fileURLToPath(new URL('..',import.meta.url)),output=path.join(root,'panel-integration-waf-review'),sha=b=>createHash('sha256').update(b).digest('hex');
const args=process.argv.slice(2);assert(args.length===4&&args[0]==='--panel-root'&&args[2]==='--release','explicit frozen source and normal AMD64 release required');
const source=args[1],archive=args[3];
for(const p of [source,archive])assert(path.isAbsolute(p)&&path.normalize(p)===p&&fs.realpathSync(p)===p);
assert(!fs.existsSync(output),'Never overwrite or repair an existing export');
const identity=fs.lstatSync(archive),name=path.basename(archive);assert(identity.isFile()&&!identity.isSymbolicLink()&&identity.nlink===1&&identity.size>0&&identity.size<500*1024*1024);
assert.equal(name,'panel-0.1.0-dev.proapps24wafreviewbjcj-linux-amd64.tar.gz');
const archiveSHA=sha(fs.readFileSync(archive));assert.equal(archiveSHA,'da8f834b9dad08a6dc8759dab28923737b5e806feb829dea00b0217c0ad75854');
const inputs=JSON.parse(execFileSync('/usr/bin/tar',['-xOf',archive,name.replace(/\.tar\.gz$/,'')+'/SOURCE_INPUTS.json'],{maxBuffer:16*1024*1024}));
assert.deepEqual(inputs,JSON.parse(fs.readFileSync(path.join(source,'SOURCE_INPUTS.json'))));assert.equal(inputs.format,1);assert.equal(inputs.inputs_sha256,'057ba6e3ad56cb050718cde7b2a4ef8a4c7016e5e4526e75c3baecc76c061c0a');assert.equal(Object.keys(inputs.files).length,17436);
const selected=Object.entries(inputs.files).filter(([p])=>!p.startsWith('web/node_modules/')).sort(([a],[b])=>a.localeCompare(b));assert.equal(selected.length,1733);
const files={},prior=JSON.parse(fs.readFileSync(path.join(root,'panel-integration-runtime-health/source-sha256.json')));assert.equal(prior.release.frozen_inputs_sha256,'fcaf4c10d038b82eaf6d021c002de0e558845f0f31eeb8eef70c4ac823050c1f');
for(const [p,item]of selected){
 assert(path.posix.normalize(p)===p&&!path.isAbsolute(p)&&!p.split('/').some(v=>!v||['..','.git','.local','node_modules'].includes(v)));assert(/^[a-f0-9]{64}$/.test(item.sha256)&&item.bytes>=0&&item.bytes<=2*1024*1024);
 const file=path.join(source,p),s=fs.lstatSync(file);assert(s.isFile()&&!s.isSymbolicLink()&&fs.realpathSync(file)===file&&s.size===item.bytes);assert.equal(sha(fs.readFileSync(file)),item.sha256,p);files[p]=item.sha256;
}
assert(Object.keys(prior.files).every(p=>Object.hasOwn(files,p)));
assert.deepEqual(Object.keys(files).filter(p=>!Object.hasOwn(prior.files,p)).sort(),['internal/core/app_registry_waf_admission.go','internal/core/app_registry_waf_admission_test.go']);
assert.deepEqual(Object.keys(files).filter(p=>Object.hasOwn(prior.files,p)&&prior.files[p]!==files[p]).sort(),['internal/core/app_registry.go','scripts/test-runtime-package-labels.mjs','web/src/App.vue','web/src/registryUpdateLabel.ts']);
const after=fs.lstatSync(archive);for(const p of ['dev','ino','size','mtimeMs'])assert.equal(after[p],identity[p]);assert.equal(sha(fs.readFileSync(archive)),archiveSHA);
fs.mkdirSync(output,{mode:0o755});
for(const [p,item]of selected){const raw=fs.readFileSync(path.join(source,p));assert.equal(sha(raw),item.sha256);const target=path.join(output,p);fs.mkdirSync(path.dirname(target),{recursive:true,mode:0o755});fs.writeFileSync(target,raw,{flag:'wx',mode:item.mode&0o111?0o755:0o644});}
const release={archive:name,archive_sha256:archiveSHA,frozen_inputs_sha256:inputs.inputs_sha256};
for(const [name,value]of [['release-source-inputs.json',{...release,files}],['source-sha256.json',{format:1,release,files,test_overrides:{}}]])fs.writeFileSync(path.join(output,name),JSON.stringify(value,null,2)+'\n',{flag:'wx',mode:0o644});
for(const [p,h]of Object.entries(files))assert.equal(sha(fs.readFileSync(path.join(output,p))),h,p);
console.log(JSON.stringify({source_export:path.basename(output),files:selected.length,...release,source_overrides:0}));
