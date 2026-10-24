// Real original-key provider bytes in a restricted prototype worker.
// This is NOT installed app2.6, Main delivery, or all50 acceptance.
import assert from 'node:assert/strict';
import {createPublicKey,createHash,verify,randomUUID} from 'node:crypto';
import {lstatSync,readFileSync,createReadStream,writeFileSync} from 'node:fs';
import {resolve} from 'node:path';
import {spawn,execFileSync} from 'node:child_process';
const [dataArg,outputArg]=process.argv.slice(2);assert(dataArg&&outputArg&&process.argv.length===4);
const data=resolve(dataArg),output=resolve(outputArg);
for(const dir of [data,output]){const s=lstatSync(dir);assert(s.isDirectory()&&!s.isSymbolicLink()&&s.uid===process.getuid()&&(s.mode&0o777)===0o700);}
const rawManifest=readFileSync(resolve(data,'manifest.json'));
assert.equal(createHash('sha256').update(rawManifest).digest('hex'),'072848fd40e0a17eaf4fb95ba7f7370e9dcde9b2841ac58412ac11512461e1e7');
const key=createPublicKey({key:Buffer.from('MCowBQYDK2VwAyEAq/Lp03Rt0HZlhJF6fac3sFsb2Tq2Q75cFL+tpRNWNvc=','base64'),type:'spki',format:'der'});
assert(verify(null,Buffer.concat([Buffer.from('yunzhan-geodata-city-v1\n'),rawManifest]),key,Buffer.from(readFileSync(resolve(data,'manifest.json.sig'),'utf8').trim(),'base64')));
const manifest=JSON.parse(rawManifest);assert.equal(manifest.release,'2026-10');
const database=resolve(data,'dbip-city-lite-2026-10.mmdb');const info=lstatSync(database);assert(info.isFile()&&!info.isSymbolicLink()&&info.nlink===1&&info.size===manifest.bytes);
const digest=createHash('sha256');for await(const block of createReadStream(database))digest.update(block);assert.equal(digest.digest('hex'),manifest.sha256);
const config='/Volumes/MacSSD/MacData/PanelDev/lima/panel-development24beil-debian13/ssh.config';
const host='lima-panel-development24beil-debian13';
const program='/opt/pgv24besg.dFjofr/statistics-bounded-reader24besg-linux-arm64';
const ssh=['-F',config,'-o','ControlMaster=no','-o','ControlPath=none',host];
const quote=s=>"'"+s.replaceAll("'","'\\''")+"'";
const properties=['DynamicUser=yes','NoNewPrivileges=yes','CapabilityBoundingSet=','AmbientCapabilities=','ProtectSystem=strict','ProtectHome=yes','PrivateTmp=yes','PrivateDevices=yes','RestrictAddressFamilies=AF_UNIX','RestrictSUIDSGID=yes','KillMode=control-group','RuntimeMaxSec=300s','TimeoutStopSec=5s','MemoryMax=768M','MemoryHigh=512M','MemorySwapMax=0','TasksMax=32','CPUQuota=70%','LimitCORE=0'];
const unit='panel-geodata-verify-'+randomUUID().replaceAll('-','')+'.service';
const args=['sudo','/usr/bin/systemd-run','--quiet','--wait','--pipe','--collect','--no-ask-password','--service-type=exec','--unit='+unit,...properties.map(v=>'--property='+v),'--setenv=GOMEMLIMIT=512MiB',program,'--statistics-geodata-reader'];
const started=Date.now();const child=spawn('ssh',[...ssh,args.map(quote).join(' ')],{stdio:['pipe','pipe','pipe']});
let stdout='',stderr='';child.stdout.on('data',b=>{stdout+=b.toString();if(stdout.length>128)child.kill('SIGTERM');});child.stderr.on('data',b=>{stderr+=b.toString();if(stderr.length>4096)child.kill('SIGTERM');});
const finished=new Promise((done,reject)=>{child.once('error',reject);child.once('exit',(code,signal)=>done({code,signal}));});
let stdinError='';child.stdin.on('error',e=>{stdinError=e.message;});
child.stdin.write('PANEL_GEODATA_STRUCTURE_V1\n'+JSON.stringify(manifest)+'\n');
const stream=createReadStream(database);stream.pipe(child.stdin);
const observed=await(async()=>{for(let i=0;i<30;i++){
  const value=execFileSync('ssh',[...ssh,['sudo','/usr/bin/systemctl','show',unit,'--property=LoadState,ActiveState,MainPID,DynamicUser,NoNewPrivileges,CapabilityBoundingSet,RestrictAddressFamilies,MemoryMax,MemoryHigh,MemorySwapMax,CPUQuotaPerSecUSec,RuntimeMaxUSec'].map(quote).join(' ')],{encoding:'utf8',timeout:5000});
  if(value.includes('ActiveState=active')&&/MainPID=[1-9][0-9]*/.test(value))return value;
  await new Promise(r=>setTimeout(r,200));
}throw new Error('No observed live restricted worker');})();
const state=Object.fromEntries(observed.trim().split('\n').map(v=>v.split('=')));
assert.equal(state.DynamicUser,'yes');assert.equal(state.NoNewPrivileges,'yes');assert.equal(state.CapabilityBoundingSet,'');assert.equal(state.RestrictAddressFamilies,'AF_UNIX');assert.equal(state.MemoryMax,'805306368');assert.equal(state.MemoryHigh,'536870912');assert.equal(state.MemorySwapMax,'0');assert.equal(state.CPUQuotaPerSecUSec,'700ms');assert.equal(state.RuntimeMaxUSec,'5min');
const result=await finished;
writeFileSync(resolve(output,'worker.stdout'),stdout,{flag:'wx',mode:0o600});writeFileSync(resolve(output,'worker.stderr'),stderr,{flag:'wx',mode:0o600});
const ok=result.code===0&&!result.signal&&!stdinError&&stdout==='PANEL_GEODATA_STRUCTURE_V1\n'+manifest.sha256+'\n';
const proof={ok,scope:'Real original-key signed October2026 DB-IP bytes; full structure check by development prototype under observed actual DynamicUser/capability/address/memory/time/CPU limits. No app installation, Main changes, or all50 claim.',unit,state,exit:result,stdin_error:stdinError,elapsed_seconds:(Date.now()-started)/1000,database_bytes:manifest.bytes,database_sha256:manifest.sha256,manifest_sha256:'072848fd40e0a17eaf4fb95ba7f7370e9dcde9b2841ac58412ac11512461e1e7'};
writeFileSync(resolve(output,'proof.json'),JSON.stringify(proof,null,2)+'\n',{flag:'wx',mode:0o600});console.log(JSON.stringify(proof));assert(ok);
