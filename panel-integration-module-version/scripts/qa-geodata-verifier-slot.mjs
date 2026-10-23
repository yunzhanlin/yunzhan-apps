// Real manager slot exclusion and owner-scoped cancellation; prototype only.
import assert from 'node:assert/strict';
import {randomUUID} from 'node:crypto';
import {readFileSync,lstatSync,writeFileSync} from 'node:fs';
import {resolve} from 'node:path';
import {spawn,execFileSync} from 'node:child_process';
const [sourceArg,outArg]=process.argv.slice(2);assert(sourceArg&&outArg&&process.argv.length===4);
const output=resolve(outArg);const info=lstatSync(output);assert(info.isDirectory()&&info.uid===process.getuid()&&(info.mode&0o777)===0o700);
const manifest=JSON.parse(readFileSync(resolve(sourceArg,'manifest.json'),'utf8'));
const ssh=['-F','/Volumes/MacSSD/MacData/PanelDev/lima/panel-development24beil-debian13/ssh.config','-o','ControlMaster=no','-o','ControlPath=none','lima-panel-development24beil-debian13'];
const q=s=>"'"+s.replaceAll("'","'\\''")+"'";
const call=args=>execFileSync('ssh',[...ssh,args.map(q).join(' ')],{encoding:'utf8',timeout:7000});
const unit='panel-geodata-verify-cache.service';const token=randomUUID().replaceAll('-','');
const properties=['DynamicUser=yes','NoNewPrivileges=yes','CapabilityBoundingSet=','AmbientCapabilities=','ProtectSystem=strict','ProtectHome=yes','PrivateTmp=yes','PrivateDevices=yes','RestrictAddressFamilies=AF_UNIX','RestrictSUIDSGID=yes','KillMode=control-group','RuntimeMaxSec=300s','TimeoutStopSec=5s','MemoryMax=768M','MemoryHigh=512M','MemorySwapMax=0','TasksMax=32','CPUQuota=70%','LimitCORE=0'];
const args=['sudo','/usr/bin/systemd-run','--quiet','--wait','--pipe','--collect','--no-ask-password','--service-type=exec','--unit='+unit,...properties.map(v=>'--property='+v),'--setenv=GOMEMLIMIT=512MiB','--setenv=PANEL_GEODATA_VERIFY_TOKEN='+token,'/opt/pgv24besg.dFjofr/statistics-bounded-reader24besg-linux-arm64','--statistics-geodata-reader'];
const state=()=>Object.fromEntries(call(['sudo','systemctl','show','--all',unit,'--property=LoadState,ActiveState,SubState,Environment,MainPID']).trim().split('\n').map(v=>v.split(/=(.*)/s).slice(0,2)));
assert.equal(state().LoadState,'not-found');
const child=spawn('ssh',[...ssh,args.map(q).join(' ')],{stdio:['pipe','pipe','pipe']});let stdout='',stderr='',closed=false;
child.stdout.on('data',v=>{stdout+=v.toString();assert(stdout.length<128);});child.stderr.on('data',v=>{stderr+=v.toString();assert(stderr.length<4096);});child.stdin.on('error',()=>{});
const done=new Promise((resolve,reject)=>{child.once('error',reject);child.once('exit',(code,signal)=>{closed=true;resolve({code,signal});});});
child.stdin.write('PANEL_GEODATA_STRUCTURE_V1\n'+JSON.stringify(manifest)+'\n'); // Hold raw stream open: no successful verification possible.
let observed,duplicateRejected=false;
try {
  for(let i=0;i<40;i++){observed=state();if(observed.ActiveState==='active'&&Number(observed.MainPID)>0)break;await new Promise(r=>setTimeout(r,100));}
  assert.equal(observed.ActiveState,'active');assert(observed.Environment.includes('PANEL_GEODATA_VERIFY_TOKEN='+token));
  try{call(args.slice(0,-2).concat(['/usr/bin/true']));}catch(e){duplicateRejected=true;assert(e.status!==0);}
  assert(duplicateRejected);assert.equal(state().MainPID,observed.MainPID);assert(!closed);
  // Do not stop a slot unless the original nonce is still owned by this test.
  assert(state().Environment.includes('PANEL_GEODATA_VERIFY_TOKEN='+token));
  call(['sudo','systemctl','stop','--no-block',unit]);child.stdin.destroy();
  // systemd-run may return0 when another controller explicitly stopped its
  // unit. Production requires the exact full-verification frame as well as
  // exit0, so an empty interrupted result MUST NOT become success.
  const terminal=await done;assert.equal(stdout,'');assert.notEqual(stdout,'PANEL_GEODATA_STRUCTURE_V1\n'+manifest.sha256+'\n');
  let final;for(let i=0;i<40;i++){final=state();if(final.LoadState==='not-found')break;await new Promise(r=>setTimeout(r,100));}assert.equal(final.LoadState,'not-found');
  const proof={ok:true,scope:'Actual prototype sandbox slot refuses duplicate start; owner nonce checked before stop; interrupted incomplete raw stream produces no verified receipt. Not installed app or Main acceptance.',duplicate_rejected:true,original_pid_unchanged_before_stop:true,no_false_verified_output:true,unit_collected:true,terminal};
  writeFileSync(resolve(output,'slot-proof.json'),JSON.stringify(proof,null,2)+'\n',{flag:'wx',mode:0o600});console.log(JSON.stringify(proof));
} finally {
  const current=state();if(current.LoadState==='loaded'&&current.Environment.includes('PANEL_GEODATA_VERIFY_TOKEN='+token))call(['sudo','systemctl','stop','--no-block',unit]);
  child.stdin.destroy();
}
