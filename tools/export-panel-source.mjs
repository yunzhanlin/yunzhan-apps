import { readdir,readFile,mkdir,writeFile,lstat } from 'node:fs/promises';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
import {execFileSync} from 'node:child_process';
import {sha256,pretty} from './lib.mjs';
const root=fileURLToPath(new URL('..',import.meta.url));
const sourceArg=process.argv.indexOf('--panel-root');
const panel=sourceArg>=0?path.resolve(process.argv[sourceArg+1]):path.resolve(root,'../panel');
const output=path.join(root,'panel-integration');
const releaseArg=process.argv.indexOf('--release');
let releaseInputs,releaseInfo;
if(releaseArg>=0){
 const archive=path.resolve(process.argv[releaseArg+1]);
 const basename=path.basename(archive);if(!/^panel-[A-Za-z0-9._-]+-linux-amd64\.tar\.gz$/.test(basename))throw Error('Unexpected release archive name');
 releaseInputs=JSON.parse(execFileSync('tar',['-xOzf',archive,basename.replace(/\.tar\.gz$/,'')+'/SOURCE_INPUTS.json'],{maxBuffer:16*1024*1024}));
 releaseInfo={archive:basename,archive_sha256:sha256(await readFile(archive)),frozen_inputs_sha256:releaseInputs.inputs_sha256};
}
const qaOnly=relative=>relative.startsWith('scripts/test')||['scripts/panel_client.py','scripts/cache-app-qa-images.mjs','scripts/check-app-registry-compat-browser.mjs'].includes(relative);
// Explicit source allowlist: no release binaries, QA state, credentials or signing keys.
const entries=['go.mod','go.sum','cmd','internal','dev','packaging','web/src','web/public','web/index.html','web/package.json','web/package-lock.json','web/tsconfig.json','web/tsconfig.node.json','web/vite.config.ts','scripts/env.sh','scripts/test-app-modules.py','scripts/test-app-native.py','scripts/test-app-compose-matrix.py','scripts/test-app-modules-extended.py','scripts/test-app-module-lifecycle.py','scripts/test-app-base-refresh.py','scripts/test-app-security-refresh.py','scripts/test-app-memcached-refresh.py','scripts/test-app-registry-compose.py','scripts/test-app-registry-phpmyadmin.py','scripts/test-app-store-50-browser.mjs','scripts/test-app-reboot.py','scripts/test-app-registry-fifty.py','scripts/cache-app-qa-images.mjs','scripts/test_app_registry_common.py','scripts/panel_client.py'];
const hashes={};
async function copy(relative){
 const input=path.join(panel,relative),st=await lstat(input);
 if(st.isSymbolicLink())throw Error('source symlink rejected: '+relative);
 if(st.isDirectory()){for(const name of (await readdir(input)).sort())await copy(path.join(relative,name));return;}
 if(!st.isFile()||st.size>2*1024*1024)throw Error('unexpected source file: '+relative);
 let data=await readFile(input);
 if(releaseInputs&&!qaOnly(relative)){
  const expected=releaseInputs.files[relative]?.sha256;
  if(!expected){console.log('excluded post-release source:',relative);return;}
  if(sha256(data)!==expected){
   let previous;try{previous=await readFile(path.join(output,relative));}catch(error){if(error.code!=='ENOENT')throw error;}
   if(previous&&sha256(previous)===expected)data=previous;
   else{
    const committed=execFileSync('git',['show','HEAD:panel-integration/'+relative],{cwd:root,maxBuffer:2*1024*1024});
    if(sha256(committed)!==expected)throw Error('No verified release source available: '+relative);
    data=committed;
   }
   console.log('preserved frozen release source:',relative);
  }
 }
 await mkdir(path.dirname(path.join(output,relative)),{recursive:true});await writeFile(path.join(output,relative),data);hashes[relative]=sha256(data);
}
for(const entry of [...entries,'scripts/test_pma_sql_common.py','scripts/upgrade-running-development.sh','scripts/check-app-registry-compat-browser.mjs','scripts/test-app-functions.py','scripts/test-app-functions-browser.mjs','scripts/test-app-reliability.py','scripts/test-app-reliability-browser.mjs','scripts/test-app-legacy-write.py','scripts/test-app-store-updates.py','scripts/test-app-store-updates-browser.mjs','scripts/test-software-routing.mjs','scripts/test-software-routing-browser.mjs','scripts/test-software-routing-install-browser.mjs']){try{await copy(entry)}catch(e){if(e.code==='ENOENT'&&entry.includes('tsconfig'))continue;throw e;}}
await writeFile(path.join(output,'source-sha256.json'),pretty({schema_version:1,...(releaseInfo?{release:releaseInfo}:{}),files:hashes}));
if(releaseInputs)await writeFile(path.join(output,'release-source-inputs.json'),pretty({schema_version:1,...releaseInfo,files:Object.fromEntries(Object.keys(hashes).filter(relative=>!qaOnly(relative)).map(relative=>[relative,releaseInputs.files[relative].sha256]))}));
console.log('exported reviewed source files:',Object.keys(hashes).length);
