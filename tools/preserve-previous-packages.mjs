import fs from 'node:fs';import path from 'node:path';import {execFileSync} from 'node:child_process';
const revision=process.argv[2];if(!/^[a-f0-9]{40}$/.test(revision||''))throw Error('Exact reviewed revision required');
const root=path.resolve(import.meta.dirname,'..');let count=0;
for(const name of execFileSync('git',['ls-tree','-r','--name-only',revision,'dist/apps'],{cwd:root,encoding:'utf8'}).trim().split('\n')){
 if(!/^dist\/apps\/[a-z0-9-]+\/[a-zA-Z0-9.-]+\/manifest\.json(?:\.sha256)?$/.test(name))throw Error('Unexpected package path');
 const output=path.join(root,name);if(fs.existsSync(output))continue;
 fs.mkdirSync(path.dirname(output),{recursive:true});fs.writeFileSync(output,execFileSync('git',['show',revision+':'+name],{cwd:root}));count++;
}
console.log('Preserved historical package files:',count);
