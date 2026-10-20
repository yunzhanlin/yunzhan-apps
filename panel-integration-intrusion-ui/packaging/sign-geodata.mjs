#!/usr/bin/env node
// Data release helper: the same original app key, a distinct signing domain,
// and exclusive output. This never runs on an end user's panel.
import {createPrivateKey, createPublicKey, sign} from 'node:crypto';
import {lstatSync, readFileSync, writeFileSync} from 'node:fs';
const [manifestPath,keyPath] = process.argv.slice(2);
if(!manifestPath||!keyPath||process.argv.length!==4)throw new Error('usage: sign-geodata.mjs manifest.json original-app-private-key.pem');
const keyInfo=lstatSync(keyPath);
if(!keyInfo.isFile()||keyInfo.isSymbolicLink()||keyInfo.nlink!==1||keyInfo.uid!==process.getuid()||(keyInfo.mode&0o777)!==0o600||keyInfo.size>4096)throw new Error('unsafe signing key identity or mode');
const manifestInfo=lstatSync(manifestPath);
if(!manifestInfo.isFile()||manifestInfo.isSymbolicLink()||manifestInfo.size>4096)throw new Error('invalid manifest input');
const key=createPrivateKey(readFileSync(keyPath));
if(key.asymmetricKeyType!=='ed25519')throw new Error('Ed25519 key required');
const expected='MCowBQYDK2VwAyEAq/Lp03Rt0HZlhJF6fac3sFsb2Tq2Q75cFL+tpRNWNvc=';
if(createPublicKey(key).export({format:'der',type:'spki'}).toString('base64')!==expected)throw new Error('not the original pinned app key');
const raw=readFileSync(manifestPath);
const signature=sign(null,Buffer.concat([Buffer.from('yunzhan-geodata-city-v1\n'),raw]),key);
writeFileSync(manifestPath+'.sig',signature.toString('base64')+'\n',{flag:'wx',mode:0o600});
process.stdout.write('Signed geodata manifest with original pinned app key.\n');
