import {lstat,readFile,mkdir,open,rename,unlink,realpath} from 'node:fs/promises';
import path from 'node:path';
import {randomUUID} from 'node:crypto';

// The schema is the current forty publisher ABI. Unlike versioned application/data
// assets, this fixed generated endpoint follows the authoritative root schema.
export async function currentCandidateSchema(root){
  root=path.resolve(root);if(await realpath(root)!==root)throw Error('candidate schema root must be canonical');
  for(const relative of ['schema','candidate','candidate/schema']){
    const file=path.join(root,relative);
    if(relative!=='schema')try{await mkdir(file,{mode:0o755});}catch(e){if(e.code!=='EEXIST')throw e;}
    const s=await lstat(file);if(!s.isDirectory()||s.isSymbolicLink()||(s.mode&0o022)!==0)throw Error('candidate schema parent must be ordinary and non-writable');
  }
  const ordinary=s=>s.isFile()&&!s.isSymbolicLink()&&s.nlink===1&&(s.mode&0o022)===0&&s.size<=256*1024;
  const source=path.join(root,'schema/current-app.schema.json'),target=path.join(root,'candidate/schema/current-app.schema.json');
  const s=await lstat(source);if(!ordinary(s))throw Error('source schema must be an ordinary bounded file');
  const bytes=await readFile(source);if(bytes.length!==s.size)throw Error('source schema changed during read');
  const value=JSON.parse(bytes);if(value.$schema!=='https://json-schema.org/draft/2020-12/schema'||value.$id!=='https://github.com/yunzhanlin/yunzhan-apps/schema/current-app.schema.json'||!Array.isArray(value.oneOf)||value.oneOf.length!==42||value['x-yunzhan-contract-kind']!=='current40-retained-native132-133'||!Array.isArray(value.properties?.required_panel_features?.items?.enum))throw Error('source schema is not the fixed publisher ABI');
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

export async function assertCurrentContracts(root,apps){
 const source=path.join(path.resolve(root),'schema/current-app.schema.json'),st=await lstat(source);if(!st.isFile()||st.isSymbolicLink()||st.nlink!==1||st.mode&0o022||st.size>256*1024)throw Error('Current contract schema must be ordinary and bounded');const value=JSON.parse(await readFile(source,'utf8'));if(value['x-yunzhan-contract-kind']!=='current40-retained-native132-133'||value.oneOf?.length!==42)throw Error('Current contract schema identity is unknown');
 const canonical=v=>JSON.stringify(v,(_,x)=>x&&typeof x==='object'&&!Array.isArray(x)?Object.fromEntries(Object.entries(x).sort(([a],[b])=>a.localeCompare(b))):x);
 for(const app of apps){const matches=value.oneOf.filter(c=>c.properties?.id?.const===app.id&&c.properties?.version?.const===app.version);if(matches.length!==1)throw Error('Current package has no exact reviewed contract: '+app.id+'@'+app.version);const c=matches[0];for(const name of c.required)if(!Object.hasOwn(app,name))throw Error('Current contract field missing: '+app.id+':'+name);for(const[name,p]of Object.entries(c.properties))if(!Object.hasOwn(p,'const')||canonical(app[name])!==canonical(p.const))throw Error('Current contract identity changed: '+app.id+':'+name);for(const absent of c.not?.anyOf??[])if(absent.required.every(k=>Object.hasOwn(app,k)))throw Error('Foreign optional contract field: '+app.id);}
}
