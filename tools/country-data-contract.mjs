import {createPublicKey,verify} from 'node:crypto';
import {pretty,sha256} from './lib.mjs';
const digest=/^[a-f0-9]{64}$/;
const licence='https://creativecommons.org/licenses/by/4.0/',attribution='https://db-ip.com/';
const exact=(v,fields)=>v&&typeof v==='object'&&!Array.isArray(v)&&Object.keys(v).sort().join(',')===[...fields].sort().join(',');
const integer=(v,max)=>Number.isSafeInteger(v)&&v>0&&v<=max;
export function verifyCountryDataManifest(raw,signature,keyBytes,now=new Date(),previous){
  if(typeof raw!=='string'||Buffer.byteLength(raw)<1||Buffer.byteLength(raw)>256*1024||typeof signature!=='string'||signature.length>128)throw Error('country manifest size or encoding invalid');
  const key=createPublicKey(keyBytes);
  if(key.export({type:'spki',format:'der'}).toString('base64')!=='MCowBQYDK2VwAyEAq/Lp03Rt0HZlhJF6fac3sFsb2Tq2Q75cFL+tpRNWNvc=')throw Error('original pinned application public key required');
  function signed(domain,body,text){
    const canonical=text.endsWith('\n')?text.slice(0,-1):text,bytes=Buffer.from(canonical,'base64');
    if(bytes.length!==64||bytes.toString('base64')!==canonical||!verify(null,Buffer.concat([Buffer.from(domain),Buffer.from(body)]),key,bytes))throw Error('country or original parent signature invalid');
  }
  signed('yunzhan-geodata-countries-v1\n',raw,signature);
  const m=JSON.parse(raw);
  if(!exact(m,['format','channel','release','revision','build_epoch','parent_manifest','parent_signature','generator_sha256','assets_json','bytes','networks','license','attribution_url'])||raw!==pretty(m))throw Error('country manifest must be canonical closed JSON without duplicate fields');
  if(m.format!==1||m.channel!=='dbip-country-lite-v1'||!/^20[2-9][0-9]-(0[1-9]|1[0-2])$/.test(m.release)||!integer(m.revision,1000)||!integer(m.build_epoch,Number.MAX_SAFE_INTEGER)||!digest.test(m.generator_sha256)||m.license!==licence||m.attribution_url!==attribution||typeof m.parent_manifest!=='string'||typeof m.parent_signature!=='string'||typeof m.assets_json!=='string')throw Error('country format, generator, release or attribution invalid');
  if(Buffer.byteLength(m.parent_manifest)>4096||m.parent_signature.length>128)throw Error('original parent size invalid');
  signed('yunzhan-geodata-city-v1\n',m.parent_manifest,m.parent_signature);
  const parent=JSON.parse(m.parent_manifest),keys=[...m.parent_manifest.matchAll(/"([^"\\]*)"\s*:/g)].map(v=>v[1]),fields=['format','channel','release','build_epoch','compressed_bytes','compressed_sha256','bytes','sha256','source','license','attribution_url'];
  if(!exact(parent,fields)||keys.length!==fields.length||new Set(keys).size!==fields.length||keys.some(k=>!fields.includes(k))||parent.format!==1||parent.channel!=='dbip-city-lite-v1'||parent.release!==m.release||parent.build_epoch!==m.build_epoch||!integer(parent.compressed_bytes,80*1048576)||!integer(parent.bytes,160*1048576)||!digest.test(parent.sha256)||!digest.test(parent.compressed_sha256)||parent.source!==`https://download.db-ip.com/free/dbip-city-lite-${m.release}.mmdb.gz`||parent.license!==licence||parent.attribution_url!==attribution)throw Error('original parent authority, source or attribution differs');
  const month=new Date(m.release+'-01T00:00:00Z'),next=new Date(Date.UTC(month.getUTCFullYear(),month.getUTCMonth()+1,1)),built=m.build_epoch*1000;
  if(!Number.isFinite(now.getTime())||now.getUTCFullYear()<2026||m.release>now.toISOString().slice(0,7)||built<month.getTime()-7*86400000||built>=next.getTime()+7*86400000||built>now.getTime()+3600000)throw Error('country release epoch is future or unrelated');
  const assets=JSON.parse(m.assets_json);
  if(!Array.isArray(assets)||assets.length<1||assets.length>675||JSON.stringify(assets)!==m.assets_json)throw Error('country inventory must be complete canonical JSON without duplicate fields');
  let bytes=0,networks=0;
  for(let i=0;i<assets.length;i++){
    const a=assets[i];
    if(!exact(a,['code','bytes','sha256','networks'])||!/^[A-Z]{2}$/.test(a.code)||a.code==='ZZ'||i>0&&assets[i-1].code>=a.code||!integer(a.bytes,64*1048576)||!integer(a.networks,1<<20)||!digest.test(a.sha256))throw Error('country asset identity, order or resource bound invalid');
    bytes+=a.bytes;networks+=a.networks;
    if(bytes>256*1048576||networks>4*1048576)throw Error('country publisher aggregate exceeded');
  }
  if(bytes!==m.bytes||networks!==m.networks)throw Error('country complete inventory totals differ');
  const sha=sha256(raw);
  if(previous){
    const p=verifyCountryDataManifest(previous.manifest,previous.signature,keyBytes,now);
    if(m.release<p.manifest.release||m.release===p.manifest.release&&(m.revision<p.manifest.revision||m.revision===p.manifest.revision&&sha!==p.sha256))throw Error('country rollback or immutable revision replacement refused');
  }
  return {manifest:m,assets,parent,sha256:sha};
}
