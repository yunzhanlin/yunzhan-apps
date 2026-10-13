// Publish small original-key data authority only. No private key, MMDB bytes,
// arbitrary source, executable or visitor IP belongs in the data channel.
import {createPublicKey,verify} from 'node:crypto';
import {readFile,lstat,mkdir,writeFile,rename,open} from 'node:fs/promises';
import {fileURLToPath} from 'node:url';
import path from 'node:path';
import {sha256,pretty} from './lib.mjs';
const root=fileURLToPath(new URL('..',import.meta.url));
const [manifestPath,signaturePath]=process.argv.slice(2);
if(!manifestPath||!signaturePath||process.argv.length!==4)throw Error('usage: build-geodata-channel.mjs original-signed-manifest original-signature');
const publicKey=createPublicKey(await readFile(path.join(root,'signatures/catalog-v1.pub.pem')));
if(publicKey.export({type:'spki',format:'der'}).toString('base64')!=='MCowBQYDK2VwAyEAq/Lp03Rt0HZlhJF6fac3sFsb2Tq2Q75cFL+tpRNWNvc=')throw Error('original pinned application key required');
const domain=Buffer.from('yunzhan-geodata-city-v1\n');
function check(manifest,signature){
 if(Buffer.byteLength(manifest)>4096||signature.length>128||!verify(null,Buffer.concat([domain,Buffer.from(manifest)]),publicKey,Buffer.from(signature.trim(),'base64')))throw Error('data signature does not match original key and domain');
 const m=JSON.parse(manifest),expected=['format','channel','release','build_epoch','compressed_bytes','compressed_sha256','bytes','sha256','source','license','attribution_url'];
 const keys=[...manifest.matchAll(/"([^"\\]*)"\s*:/g)].map(v=>v[1]);
 if(keys.length!==expected.length||new Set(keys).size!==expected.length||keys.some(k=>!expected.includes(k))||Object.keys(m).length!==expected.length)throw Error('data manifest unknown, duplicate or noncanonical fields');
 if(m.format!==1||m.channel!=='dbip-city-lite-v1'||!/^20[2-9][0-9]-(0[1-9]|1[0-2])$/.test(m.release)||!Number.isSafeInteger(m.build_epoch)||m.build_epoch<1||!Number.isSafeInteger(m.compressed_bytes)||m.compressed_bytes<1||m.compressed_bytes>80*1048576||!Number.isSafeInteger(m.bytes)||m.bytes<1||m.bytes>160*1048576||!/^[a-f0-9]{64}$/.test(m.sha256)||!/^[a-f0-9]{64}$/.test(m.compressed_sha256)||m.source!==`https://download.db-ip.com/free/dbip-city-lite-${m.release}.mmdb.gz`||m.license!=='https://creativecommons.org/licenses/by/4.0/'||m.attribution_url!=='https://db-ip.com/')throw Error('data identity, size, source or attribution differs');
 const now=new Date(),month=new Date(m.release+'-01T00:00:00Z'),next=new Date(Date.UTC(month.getUTCFullYear(),month.getUTCMonth()+1,1)),built=m.build_epoch*1000;
 if(m.release>now.toISOString().slice(0,7)||built<month.getTime()-7*86400000||built>=next.getTime()+7*86400000||built>now.getTime()+3600000)throw Error('future or unrelated release epoch');
 return m;
}
async function input(p,max){const s=await lstat(p);if(!s.isFile()||s.isSymbolicLink()||s.nlink!==1||s.size<1||s.size>max)throw Error('input identity or size invalid');return await readFile(p,'utf8');}
const manifest=await input(manifestPath,4096),signature=await input(signaturePath,128),m=check(manifest,signature),digest=sha256(manifest);
async function directory(p){
 try{await mkdir(p);}catch(e){if(e.code!=='EEXIST')throw e;}
 const s=await lstat(p);if(!s.isDirectory()||s.isSymbolicLink())throw Error('data publication directory must not be a symlink or special file');
}
const base=path.join(root,'data/geodata/dbip-city-lite-v1');
for(const part of ['data','data/geodata','data/geodata/dbip-city-lite-v1'])await directory(path.join(root,part));
const catalogue=path.join(base,'catalog.signed.json');
let before,identical=false;try{before=await input(catalogue,8192);}catch(e){if(e.code!=='ENOENT')throw e;}
if(before){
 const old=JSON.parse(before);if(Object.keys(old).sort().join(',')!=='manifest,signature'||typeof old.manifest!=='string'||typeof old.signature!=='string'||before!==pretty(old))throw Error('existing data bundle cannot be verified');
 const prior=check(old.manifest,old.signature);
 if(m.release<prior.release||m.release===prior.release&&digest!==sha256(old.manifest))throw Error('data rollback or same-month replacement refused');
 if(m.release===prior.release)identical=true;
}
await directory(path.join(base,'releases'));
const immutable=path.join(base,'releases',m.release+'-'+digest);await directory(immutable);
for(const [name,value]of [['manifest.json',manifest],['manifest.json.sig',signature],['NOTICE.txt',`DB-IP City Lite ${m.release}\nIP Geolocation by DB-IP\nhttps://db-ip.com/\nLicense: CC BY 4.0\nhttps://creativecommons.org/licenses/by/4.0/\nSource: ${m.source}\nUnmodified provider database; downloaded only on explicit panel request.\n`]]){
 const target=path.join(immutable,name);let prior;try{prior=await input(target,4096);}catch(e){if(e.code!=='ENOENT')throw e;}
 if(prior!==undefined){if(prior!==value)throw Error('immutable data release differs');}else await writeFile(target,value,{flag:'wx'});
}
if(identical){console.log('identical signed data channel AND immutable release members verified');process.exit(0);}
const body=pretty({manifest,signature:signature.trim()}),stage=path.join(base,'.catalog-'+digest+'.tmp');
await writeFile(stage,body,{flag:'wx'});const fd=await open(stage,'r');try{await fd.sync();}finally{await fd.close();}
let current;try{current=await input(catalogue,8192);}catch(e){if(e.code!=='ENOENT')throw e;}
if(current!==before)throw Error('data catalogue changed before atomic publication; staged bytes retained');
await rename(stage,catalogue);const dir=await open(base,'r');try{await dir.sync();}finally{await dir.close();}
console.log(`original-key data authority ${m.release} ${digest}; no provider bytes or installation included`);
