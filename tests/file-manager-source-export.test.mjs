import test from'node:test';import assert from'node:assert/strict';import fs from'node:fs';import os from'node:os';import path from'node:path';import{createHash}from'node:crypto';import{spawnSync,execFileSync}from'node:child_process';
const tool=fs.readFileSync(new URL('../tools/export-file-manager-source.mjs',import.meta.url)),sha=b=>createHash('sha256').update(b).digest('hex');
function fixture(t){
 const temporary=fs.realpathSync(os.tmpdir()),root=fs.mkdtempSync(path.join(temporary,'yunzhan-file-manager-export-fixture-'));t.after(()=>{assert.equal(path.dirname(root),temporary);assert(path.basename(root).startsWith('yunzhan-file-manager-export-fixture-'));fs.rmSync(root,{recursive:true})});
 const repo=path.join(root,'repo'),source=path.join(root,'source'),payload=path.join(root,'payload'),name='panel-0.1.0-dev.fixture-linux-amd64';fs.mkdirSync(path.join(repo,'tools'),{recursive:true});fs.mkdirSync(source);fs.mkdirSync(path.join(payload,name),{recursive:true});fs.writeFileSync(path.join(repo,'tools/export-file-manager-source.mjs'),tool);
 const paths=['go.mod','internal/core/files.go','internal/core/file_shares.go','internal/core/smtp.go','internal/executor/files_cloud_linux.go','web/src/FileManager.vue','packaging/install.sh','scripts/test-file-manager-scope.mjs','web/node_modules/never-export.js'],files={};
 for(const p of paths){const raw=Buffer.from('synthetic framing fixture '+p+'\n');fs.mkdirSync(path.dirname(path.join(source,p)),{recursive:true});fs.writeFileSync(path.join(source,p),raw);files[p]={sha256:sha(raw),bytes:raw.length,mode:0o644}}
 const index={format:1,inputs_sha256:'a'.repeat(64),files},archive=path.join(root,name+'.tar.gz');
 const pack=()=>{const raw=JSON.stringify(index);fs.writeFileSync(path.join(source,'SOURCE_INPUTS.json'),raw);fs.writeFileSync(path.join(payload,name,'SOURCE_INPUTS.json'),raw);execFileSync('/usr/bin/tar',['czf',archive,'-C',payload,name])};pack();
 return{root,repo,source,archive,index,pack,output:path.join(repo,'panel-integration-file-manager'),run:()=>spawnSync(process.execPath,['tools/export-file-manager-source.mjs','--panel-root',source,'--release',archive],{cwd:repo,encoding:'utf8',timeout:15000})};
}
test('mechanical source export binds exact archive inputs, excludes dependencies, never overwrites and makes no signing claim',t=>{
 const f=fixture(t),r=f.run();assert.equal(r.status,0,r.stderr);const result=JSON.parse(r.stdout);assert.equal(result.files,8);assert.equal(result.archive_sha256,sha(fs.readFileSync(f.archive)));assert(!fs.existsSync(path.join(f.output,'web/node_modules')));const bound=JSON.parse(fs.readFileSync(path.join(f.output,'source-sha256.json')));assert.deepEqual(bound.test_overrides,{});assert.equal(bound.release.frozen_inputs_sha256,f.index.inputs_sha256);
 for(const[p,pin]of Object.entries(bound.files))assert.equal(sha(fs.readFileSync(path.join(f.output,p))),pin);const before=fs.readFileSync(path.join(f.output,'source-sha256.json'));assert.notEqual(f.run().status,0);assert.deepEqual(fs.readFileSync(path.join(f.output,'source-sha256.json')),before);
});
for(const scenario of['changed-source','symlink-source','missing-handler','traversal-index','oversized-source','different-index','hardlinked-archive','existing-output'])test('source exporter refuses '+scenario+' without publishing or repairing',t=>{
 const f=fixture(t);switch(scenario){
 case'changed-source':fs.writeFileSync(path.join(f.source,'go.mod'),'changed');break;
 case'symlink-source':fs.renameSync(path.join(f.source,'go.mod'),path.join(f.source,'old'));fs.symlinkSync('old',path.join(f.source,'go.mod'));break;
 case'missing-handler':delete f.index.files['internal/core/file_shares.go'];f.pack();break;
 case'traversal-index':f.index.files['../escape']={sha256:'f'.repeat(64),bytes:1,mode:0o644};f.pack();break;
 case'oversized-source':f.index.files['go.mod'].bytes=(2<<20)+1;f.pack();break;
 case'different-index':{const bad=structuredClone(f.index);bad.inputs_sha256='b'.repeat(64);fs.writeFileSync(path.join(f.source,'SOURCE_INPUTS.json'),JSON.stringify(bad));break}
 case'hardlinked-archive':fs.linkSync(f.archive,path.join(f.root,'other-archive'));break;
 case'existing-output':fs.mkdirSync(f.output);fs.writeFileSync(path.join(f.output,'original'),'retained');break;
 }
 const r=f.run();assert.notEqual(r.status,0);const expected={'changed-source':'frozen source drift','symlink-source':'frozen source drift','missing-handler':'required file-manager source missing','traversal-index':'unexportable frozen source member','oversized-source':'unexportable frozen source member','different-index':'source/archive frozen-input binding differs','hardlinked-archive':'archive identity/budget invalid','existing-output':'source scope already exists'};assert(r.stderr.includes(expected[scenario]),r.stderr);if(scenario==='existing-output')assert.equal(fs.readFileSync(path.join(f.output,'original'),'utf8'),'retained');else assert(!fs.existsSync(f.output));
});
