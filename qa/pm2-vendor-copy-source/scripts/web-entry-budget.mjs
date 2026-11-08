import {readSync,openSync,closeSync,fstatSync,lstatSync,readdirSync,constants} from 'node:fs';
import {resolve,basename} from 'node:path';
import {createHash} from 'node:crypto';
import {pathToFileURL} from 'node:url';
import ts from '../web/node_modules/typescript/lib/typescript.js';
const limit=1_200_000;
const hash=b=>createHash('sha256').update(b).digest('hex');
export function webEntryBudget(directory) {
 const root=resolve(directory),assets=resolve(root,'assets');
 const read=(p,max)=>{
  let fd;
  try {
   fd=openSync(p,constants.O_RDONLY|constants.O_NOFOLLOW|constants.O_NONBLOCK);
   const before=fstatSync(fd);
   if(!before.isFile()||before.nlink!==1||before.size>max)throw new Error();
   const buffer=Buffer.alloc(max+1);let length=0;
   while(length<buffer.length){const n=readSync(fd,buffer,length,buffer.length-length,null);if(n===0)break;length+=n;}
   const after=fstatSync(fd),current=lstatSync(p);
   if(length>max||length!==before.size||current.isSymbolicLink()||
    ['dev','ino','size','mtimeMs','ctimeMs','uid','gid','nlink'].some(key=>before[key]!==after[key]||before[key]!==current[key]))throw new Error();
   return buffer.subarray(0,length);
  } catch { throw new Error('Build asset is not a stable bounded ordinary file'); }
  finally { if(fd!==undefined)closeSync(fd); }
 };
 const html=read(resolve(root,'index.html'),64<<10).toString('utf8');
 const attr=(tag,key)=>new RegExp('(?:^|\\s)'+key+'="([^"]*)"','i').exec(tag)?.[1];
 const asset=value=>{if(!/^\.\/assets\/[a-zA-Z0-9_-]+\.js$/.test(value||''))throw new Error('Entry points must be fixed local JavaScript assets');return resolve(root,value);};
 const scripts=[...html.matchAll(/<script\b[^>]*>/gi)].map(x=>x[0]).filter(x=>attr(x,'type')==='module');
 if(scripts.length!==1)throw new Error('Expected one module entry script');
 const entry=asset(attr(scripts[0],'src'));
 const pending=[entry,...[...html.matchAll(/<link\b[^>]*>/gi)].map(x=>x[0]).filter(x=>attr(x,'rel')==='modulepreload').map(x=>asset(attr(x,'href')))];
 const visited=new Map();
 while(pending.length) {
  const path=pending.pop();if(visited.has(path))continue;
  if(visited.size>=64)throw new Error('Eager entry graph exceeds 64 assets');
  const bytes=read(path,limit+1);
  if(bytes.length>limit)throw new Error('JavaScript asset exceeds the unchanged 1,200,000 byte budget');
  const tree=ts.createSourceFile(path,bytes.toString('utf8'),ts.ScriptTarget.ESNext,true,ts.ScriptKind.JS);
  if(tree.parseDiagnostics.length)throw new Error('Built JavaScript could not be parsed');
  visited.set(path,{name:basename(path),bytes:bytes.length,sha256:hash(bytes)});
  for(const node of tree.statements)if((ts.isImportDeclaration(node)||ts.isExportDeclaration(node))&&node.moduleSpecifier) {
   if(!ts.isStringLiteral(node.moduleSpecifier))throw new Error('Static import path is not fixed');
   const name=node.moduleSpecifier.text;
   if(!/^\.\/[a-zA-Z0-9_-]+\.js$/.test(name))throw new Error('Static import must stay within the local asset directory');
   pending.push(resolve(assets,name));
  }
 }
 const eager=[...visited.values()].sort((a,b)=>a.name.localeCompare(b.name));
 const total=eager.reduce((sum,x)=>sum+x.bytes,0);
 if(total>limit)throw new Error('Eager entry JavaScript exceeds the unchanged 1,200,000 byte budget');
 if(eager.some(x=>x.name.startsWith('AppModuleManager-')))throw new Error('Application manager is still eagerly loaded');
 const all=readdirSync(assets).filter(x=>x.endsWith('.js'));
 if(all.length>128)throw new Error('Built JavaScript asset inventory exceeds 128 entries');
 const deferred=all.filter(x=>/^AppModuleManager-[a-zA-Z0-9_-]+\.js$/.test(x));
 if(deferred.length!==1)throw new Error('Expected one actual deferred application manager chunk');
 for(const name of all)if(read(resolve(assets,name),limit+1).length>limit)throw new Error('A deferred JavaScript chunk exceeds the unchanged budget');
 const module=read(resolve(assets,deferred[0]),limit+1);
 return {passed:true,eager_limit_bytes:limit,entry:basename(entry),entry_bytes:visited.get(entry).bytes,eager_javascript_bytes:total,eager_assets:eager,deferred_application_manager:{name:deferred[0],bytes:module.length,sha256:hash(module)},index_sha256:hash(Buffer.from(html)),scope:'Actual build JavaScript graph and modulepreloads only; not browser network, CSS/font budget, accessibility, native installation, or all-50 commercial acceptance.'};
}
if(process.argv[1]&&import.meta.url===pathToFileURL(resolve(process.argv[1])).href) {
 if(process.argv.length!==3)throw new Error('Pass the exact freshly built web directory');
 console.log(JSON.stringify(webEntryBudget(process.argv[2])));
}
