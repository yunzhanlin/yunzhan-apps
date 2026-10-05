import { readdir,readFile,mkdir,writeFile,lstat } from 'node:fs/promises';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
import {sha256,pretty} from './lib.mjs';
const root=fileURLToPath(new URL('..',import.meta.url));
const panel=path.resolve(root,'../panel');
const output=path.join(root,'panel-integration');
// Explicit source allowlist: no release binaries, QA state, credentials or signing keys.
const entries=['go.mod','go.sum','cmd','internal','dev','packaging','web/src','web/public','web/index.html','web/package.json','web/package-lock.json','web/tsconfig.json','web/tsconfig.node.json','web/vite.config.ts','scripts/env.sh','scripts/test-app-modules.py','scripts/test-app-native.py','scripts/test-app-compose-matrix.py','scripts/test-app-modules-extended.py','scripts/test-app-module-lifecycle.py','scripts/test-app-base-refresh.py','scripts/test-app-security-refresh.py','scripts/test-app-memcached-refresh.py','scripts/test-app-registry-compose.py','scripts/test-app-registry-phpmyadmin.py','scripts/test-app-store-50-browser.mjs','scripts/test-app-reboot.py','scripts/test-app-registry-fifty.py','scripts/cache-app-qa-images.mjs','scripts/test_app_registry_common.py','scripts/panel_client.py'];
const hashes={};
async function copy(relative){
 const input=path.join(panel,relative),st=await lstat(input);
 if(st.isSymbolicLink())throw Error('source symlink rejected: '+relative);
 if(st.isDirectory()){for(const name of (await readdir(input)).sort())await copy(path.join(relative,name));return;}
 if(!st.isFile()||st.size>2*1024*1024)throw Error('unexpected source file: '+relative);
 const data=await readFile(input);await mkdir(path.dirname(path.join(output,relative)),{recursive:true});await writeFile(path.join(output,relative),data);hashes[relative]=sha256(data);
}
for(const entry of [...entries,'scripts/test_pma_sql_common.py']){try{await copy(entry)}catch(e){if(e.code==='ENOENT'&&entry.includes('tsconfig'))continue;throw e;}}
await writeFile(path.join(output,'source-sha256.json'),pretty({schema_version:1,files:hashes}));
console.log('exported reviewed source files:',Object.keys(hashes).length);
