import {lstat,readFile,mkdir,open,rename,unlink,realpath} from 'node:fs/promises';
import path from 'node:path';
import {randomUUID} from 'node:crypto';

// The schema is the current publisher ABI. Unlike versioned application/data
// assets, this fixed generated endpoint follows the authoritative root schema.
export async function candidateSchema(root){
  root=path.resolve(root);if(await realpath(root)!==root)throw Error('candidate schema root must be canonical');
  for(const relative of ['schema','candidate','candidate/schema']){
    const file=path.join(root,relative);
    if(relative!=='schema')try{await mkdir(file,{mode:0o755});}catch(e){if(e.code!=='EEXIST')throw e;}
    const s=await lstat(file);if(!s.isDirectory()||s.isSymbolicLink()||(s.mode&0o022)!==0)throw Error('candidate schema parent must be ordinary and non-writable');
  }
  const ordinary=s=>s.isFile()&&!s.isSymbolicLink()&&s.nlink===1&&(s.mode&0o022)===0&&s.size<=256*1024;
  const source=path.join(root,'schema/app.schema.json'),target=path.join(root,'candidate/schema/app.schema.json');
  const s=await lstat(source);if(!ordinary(s))throw Error('source schema must be an ordinary bounded file');
  const bytes=await readFile(source);if(bytes.length!==s.size)throw Error('source schema changed during read');
  const value=JSON.parse(bytes);if(value.$schema!=='https://json-schema.org/draft/2020-12/schema'||value.$id!=='https://github.com/yunzhanlin/yunzhan-apps/schema/app.schema.json'||!Array.isArray(value.allOf)||!Array.isArray(value.properties?.required_panel_features?.items?.enum))throw Error('source schema is not the fixed publisher ABI');
  try{const t=await lstat(target);if(!ordinary(t))throw Error('candidate schema output must be ordinary');if((await readFile(target)).equals(bytes))return {changed:false,bytes:bytes.length};}catch(e){if(e.code!=='ENOENT')throw e;}
  const temporary=path.join(root,'candidate/schema','.app.schema.'+randomUUID()+'.tmp');let created=false;
  try{
    const file=await open(temporary,'wx',0o644);created=true;
    try{await file.writeFile(bytes);await file.sync();}finally{await file.close();}
    await rename(temporary,target);created=false;
    const directory=await open(path.dirname(target),'r');try{await directory.sync();}finally{await directory.close();}
  }finally{if(created)await unlink(temporary);}
  return {changed:true,bytes:bytes.length};
}
