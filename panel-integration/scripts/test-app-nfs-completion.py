#!/usr/bin/env python3
"""Actual NFSv4 round trip with an owned loopback-only QA Ganesha export."""
import json, os, pathlib, time, uuid
from panel_client import PanelClient
assert os.environ.get('PANEL_VM')=='panel-compat-ubuntu24', 'Isolated Ubuntu application QA required'
assert os.environ.get('PANEL_BASE')=='http://127.0.0.1:19220', 'QA panel only'
p=PanelClient();name='qa-nfs-'+uuid.uuid4().hex[:8];unit='qa-nfs-server-'+uuid.uuid4().hex[:8];mounted=False
create=r'''import pathlib,tempfile,socket,json,subprocess,sys
v=json.load(sys.stdin)
with socket.socket() as s:s.bind(('127.0.0.1',2049))
base=pathlib.Path(tempfile.mkdtemp(prefix='cloudstack-nfs-',dir='/var/tmp'));base.chmod(0o755)
share=base/'share';share.mkdir(mode=0o755);(share/'marker.txt').write_text('nfs-completion-verified')
config='NFS_Core_Param { Bind_addr = 127.0.0.1; NFS_Protocols = 4; Enable_NLM = false; Enable_RQUOTA = false; }\nEXPORT { Export_Id = 77; Path = "'+str(share)+'"; Pseudo = /'+v['name']+'; Access_Type = RO; Squash = root_squash; Protocols = 4; Transports = TCP; CLIENT { Clients = 127.0.0.1; Access_Type = RO; } FSAL { Name = VFS; } }\n'
(base/'ganesha.conf').write_text(config)
subprocess.run(['systemd-run','--unit='+v['unit'],'--property=RuntimeMaxSec=240','/usr/bin/ganesha.nfsd','-F','-f',str(base/'ganesha.conf'),'-p',str(base/'ganesha.pid'),'-L',str(base/'ganesha.log')],check=True,capture_output=True)
print(base)'''
try:
 base=p.vm('sudo','python3','-c',create,input=json.dumps({'name':name,'unit':unit})).stdout.strip()
 assert base.startswith('/var/tmp/cloudstack-nfs-')
 for _ in range(30):
  r=p.vm('python3','-c',"import socket;s=socket.create_connection(('127.0.0.1',2049),1);s.close()",check=False)
  if not r.returncode:break
  time.sleep(.2)
 assert r.returncode==0,'QA export did not become ready'
 p.api('/app-modules/nfs-manager/mount',{'resource_id':name,'source':'127.0.0.1:/'+name,'read_only':True});mounted=True
 assert p.vm('sudo','cat','/srv/panel/nfs/'+name+'/marker.txt').stdout=='nfs-completion-verified'
 options=p.vm('findmnt','-n','-o','OPTIONS','/srv/panel/nfs/'+name).stdout.strip().split(',')
 assert all(k in options for k in ('ro','nosuid','nodev','noexec'))
 p.vm('sudo','systemctl','restart','panel-nfs@'+name)
 assert p.vm('sudo','cat','/srv/panel/nfs/'+name+'/marker.txt').stdout=='nfs-completion-verified'
 entries=p.api('/app-modules/nfs-manager/run',{})['mounts'];assert any(x['mount']['id']==name and x['state']=='active' for x in entries)
 p.api('/app-modules/nfs-manager/unmount',{'resource_id':name});mounted=False
 assert not any(x['mount']['id']==name for x in p.api('/app-modules/nfs-manager/run',{})['mounts'])
 report={'passed':True,'actual_nfs_v4_marker':True,'safe_mount_options':options,'service_restart_remount':True,'owned_mount_removed':True,'server_loopback_only':True}
 (pathlib.Path(__file__).resolve().parents[1]/'.local/app-nfs-completion-acceptance.json').write_text(json.dumps(report,indent=2)+'\n')
 print('PASS actual NFSv4 content, security options, persisted service remount and owned mount removal',flush=True)
finally:
 if mounted:p.api('/app-modules/nfs-manager/unmount',{'resource_id':name})
 p.vm('sudo','systemctl','stop',unit,check=False)
 p.close()
