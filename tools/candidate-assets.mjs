import {lstat,readdir,readFile,mkdir,writeFile,realpath} from 'node:fs/promises';
import path from 'node:path';

// Copy only the existing PUBLIC application/data trees into the candidate
// namespace. Preserve original signed data/licence bytes; never credentials,
// another source directory, links, special files, or changed immutable assets.
export async function candidateAssets(root) {
  root=path.resolve(root);if(await realpath(root)!==root)throw Error('candidate publisher root must be canonical');
  let files=0,total=0;
  async function parents(relative){
    let directory=root;
    for(const part of ['candidate',...path.posix.dirname(relative).split('/')]){
      directory=path.join(directory,part);
      try{await mkdir(directory,{mode:0o755});}catch(error){if(error.code!=='EEXIST')throw error;}
      const s=await lstat(directory);if(!s.isDirectory()||s.isSymbolicLink()||(s.mode&0o022)!==0)throw Error('candidate output parent is not an ordinary non-writable public directory');
    }
  }
  async function walk(relative,depth=0){
    if(depth>16)throw Error('candidate public asset nesting exceeded');
    const source=path.join(root,relative),s=await lstat(source);
    if(s.isSymbolicLink())throw Error('candidate public asset cannot be a link');
    if(s.isDirectory()){
      for(const name of (await readdir(source)).sort()){
        if(name==='.DS_Store'||name.startsWith('._'))continue;
        if(!/^[A-Za-z0-9._-]+$/.test(name)||name.startsWith('.')||/private|secret|password|credentials/i.test(name))throw Error('unexpected public asset name');
        await walk(relative+'/'+name,depth+1);
      }
      return;
    }
    if(!s.isFile()||s.nlink!==1||s.size>64*1024*1024||++files>8192||(total+=s.size)>256*1024*1024)throw Error('candidate public asset type or bound refused');
    const bytes=await readFile(source);if(bytes.length!==s.size)throw Error('public asset changed during read');
    const target=path.join(root,'candidate',relative);await parents(relative);
    try{const s=await lstat(target);if(!s.isFile()||s.isSymbolicLink()||s.nlink!==1)throw Error('candidate output asset is not ordinary');if(!(await readFile(target)).equals(bytes))throw Error('changed immutable candidate public asset');}
    catch(error){if(error.code!=='ENOENT')throw error;await writeFile(target,bytes,{flag:'wx',mode:0o644});}
  }
  await walk('dist/apps');await walk('data');return {files,bytes:total};
}
