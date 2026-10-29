// Offline publication of already original-key signed derived data. This tool
// never signs, downloads, installs, activates, or accepts a caller-selected key.
import {readFile,lstat,readdir,mkdir,writeFile,open,rename,realpath} from 'node:fs/promises';
import {fileURLToPath} from 'node:url';
import path from 'node:path';
import {pretty,sha256} from './lib.mjs';
import {verifyCountryDataManifest} from './country-data-contract.mjs';
const root=fileURLToPath(new URL('..',import.meta.url));
const args=process.argv.slice(2);if(args.length!==3)throw Error('usage: build-country-data-channel.mjs original-signed-manifest original-signature exclusively-generated-data-directory');
async function input(name,max){
  const before=await lstat(name);if(!before.isFile()||before.isSymbolicLink()||before.nlink!==1||before.size<1||before.size>max)throw Error('country publication input is linked, special or outside capacity');
  const bytes=await readFile(name),after=await lstat(name);
  if(before.dev!==after.dev||before.ino!==after.ino||before.size!==after.size||before.mtimeMs!==after.mtimeMs||bytes.length!==before.size)throw Error('country input changed during stable read');return bytes;
}
const raw=(await input(args[0],256*1024)).toString('utf8'),signature=(await input(args[1],128)).toString('utf8'),key=await input(path.join(root,'signatures/catalog-v1.pub.pem'),4096);
let verified=verifyCountryDataManifest(raw,signature,key);
const directory=path.resolve(args[2]),info=await lstat(directory);if(await realpath(directory)!==directory||!info.isDirectory()||info.isSymbolicLink())throw Error('country source directory must be canonical and ordinary');
const expected=verified.assets.map(a=>a.code+'.cidr'),known=new Set([...expected,'parent-manifest.json','parent-manifest.sig','parent-public.pem','NOTICE.txt','generation.json']);
for(const n of await readdir(directory))if(!known.has(n))throw Error('country source contains unknown members');
const memberBytes=new Map();for(const a of verified.assets){const bytes=await input(path.join(directory,a.code+'.cidr'),64*1048576);if(bytes.length!==a.bytes||sha256(bytes)!==a.sha256||!bytes.toString('utf8').startsWith(`# panel-country-networks-v1\n# parent-manifest-sha256: ${sha256(verified.manifest.parent_manifest)}\n# parent-database-sha256: ${verified.parent.sha256}\n`))throw Error('country source bytes or parent provenance differ');memberBytes.set(a.code+'.cidr',bytes);}
async function dir(relative){let p=root;for(const n of relative.split('/')){p=path.join(p,n);try{await mkdir(p,{mode:0o755});}catch(e){if(e.code!=='EEXIST')throw e;}const s=await lstat(p);if(!s.isDirectory()||s.isSymbolicLink()||(s.mode&0o022)!==0)throw Error('country output parent must be ordinary non-writable directory');}}
const relative='data/geodata/dbip-country-lite-v1',base=path.join(root,relative),catalogue=path.join(base,'catalog.signed.json');
let before;try{before=(await input(catalogue,512*1024)).toString('utf8');}catch(e){if(e.code!=='ENOENT')throw e;}
if(before){const previous=JSON.parse(before);if(Object.keys(previous).sort().join(',')!=='manifest,signature'||before!==pretty(previous))throw Error('country existing catalogue is not canonical');verified=verifyCountryDataManifest(raw,signature,key,new Date(),previous);}
const m=verified.manifest,release=relative+'/releases/'+m.release+'-r'+m.revision+'-'+verified.sha256;
await dir(release);
const notice=`IP Geolocation by DB-IP\nhttps://db-ip.com/\nLicense: CC BY 4.0\nhttps://creativecommons.org/licenses/by/4.0/\nDB-IP City Lite ${m.release}; derived canonical country CIDR shards, revision ${m.revision}.\nOriginal provider source: ${verified.parent.source}\nOriginal parent manifest SHA256: ${sha256(m.parent_manifest)}\nGenerator SHA256: ${m.generator_sha256}\nOnly explicitly selected countries are downloaded; publication does not activate WAF policy.\n`;
memberBytes.set('manifest.json',Buffer.from(raw));memberBytes.set('manifest.json.sig',Buffer.from(signature));memberBytes.set('NOTICE.txt',Buffer.from(notice));
for(const[n,bytes]of memberBytes){const target=path.join(root,release,n);try{if(!(await input(target,64*1048576)).equals(bytes))throw Error('changed immutable country release member');}catch(e){if(e.code!=='ENOENT')throw e;await writeFile(target,bytes,{flag:'wx',mode:0o644});}}
const body=pretty({manifest:raw,signature:signature.endsWith('\n')?signature.slice(0,-1):signature});
if(before===body){console.log(`identical original-key country data and all ${memberBytes.size} immutable members verified`);process.exit(0);}
const stage=path.join(base,'.catalog-'+verified.sha256+'.tmp');await writeFile(stage,body,{flag:'wx',mode:0o644});const fd=await open(stage,'r');try{await fd.sync();}finally{await fd.close();}
let current;try{current=(await input(catalogue,512*1024)).toString('utf8');}catch(e){if(e.code!=='ENOENT')throw e;}
if(current!==before)throw Error('country catalogue changed before original atomic publication; stage retained');
await rename(stage,catalogue);const opened=await open(base,'r');try{await opened.sync();}finally{await opened.close();}
console.log(JSON.stringify({ok:true,channel:m.channel,release:m.release,revision:m.revision,manifest_sha256:verified.sha256,assets:verified.assets.length,bytes:m.bytes,networks:m.networks,installation_or_activation:false}));
