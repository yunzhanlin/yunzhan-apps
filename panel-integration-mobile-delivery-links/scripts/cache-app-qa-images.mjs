// Optional local QA accelerator. Fixed upstream digests are never substituted.
import fs from 'node:fs';
import path from 'node:path';
import {execFileSync} from 'node:child_process';
const root=path.resolve(import.meta.dirname,'..');
const source=fs.readFileSync(path.join(root,'internal/core/app_compose_templates.go'),'utf8');
const images=Object.fromEntries([...source.matchAll(/"(php-legacy-\d+)":\s*"([^"]+)"/g)].map(v=>[v[1],v[2]]));
images.rabbitmq='rabbitmq:4.1.4-management-alpine@sha256:5cbd7145b0306399ad68422c3350b6cbd1bb95704b39f5896480e5b6d4238a04';
images['qa-mariadb']='mariadb:11.8.9@sha256:6422478cb8e159f080fb1d8ccf65101e26fe51385787fde7d16c3b165a331f15';
const dev=process.env.PANEL_DEV_HOME||'/Volumes/MacSSD/MacData/PanelDev';
const vm=process.env.PANEL_VM||'panel-store-apps-debian13';
const lima=path.join(dev,'tools/lima/bin/limactl');
const directory=path.join(root,'.build/cache-app-images');fs.mkdirSync(directory,{recursive:true});
for(const id of process.argv.slice(2)){
 const image=images[id];if(!image||!image.includes('@sha256:'))throw Error('Unapproved QA image: '+id);
 const archive=path.join(directory,id+'.tar');
 console.log('CACHE',id);
 for(let attempt=0;;attempt++){
  try{execFileSync('/usr/local/bin/docker',['pull','--platform','linux/amd64',image],{stdio:['ignore','ignore','pipe'],timeout:600000});break}
  catch(error){if(attempt>=3||!/timeout|EOF|connection reset/.test(String(error.stderr)))throw error;console.log('RETRY',id,attempt+1)}
 }
 execFileSync('/usr/local/bin/docker',['save','--platform','linux/amd64','--output',archive,image],{stdio:'pipe',timeout:300000});
 execFileSync(lima,['shell','--workdir=/tmp',vm,'sudo','docker','load','-i','/workspace/.build/cache-app-images/'+id+'.tar'],{stdio:'pipe',env:{...process.env,LIMA_HOME:path.join(dev,'lima')},timeout:300000});
 fs.unlinkSync(archive);console.log('CACHED',id);
}
