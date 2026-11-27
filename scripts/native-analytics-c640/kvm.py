from pathlib import Path
import hashlib,json,os,platform,re,secrets,shlex,shutil,signal,socket,stat,subprocess,sys,tarfile,tempfile,time,traceback,urllib.request
os.umask(0o077);assert os.geteuid()==0 and platform.machine()=='x86_64'and len(sys.argv)==4;assets,source,public=(Path(v).resolve(strict=True)for v in sys.argv[1:]);owner=public.stat();assert stat.S_ISCHR(Path('/dev/kvm').stat().st_mode);work=Path(tempfile.mkdtemp(prefix='c640-native-pair-',dir=public.parent));controller=work/'controller';controller.mkdir(mode=0o700);cert_sha='55ac5d4129117009583d47c47442bd07cc1de997e6a2a10b5652b3cb7fa54495';node_tool=os.environ['C640_NODE_TOOL'];processes={};proof={'ok':False,'out':str(work),'source_inputs_sha256':'b223c28247d9d20e50a356643a9744a9ab174068dd567a2c57f15c342934c15f','Main_changes':0,'all40_commercial':False,'original_operation_replays':0,'native_architecture':'amd64','owned_memory_MiB_each':2048,'emulation_fallback':False}
def sha(p):
 h=hashlib.sha256()
 with Path(p).open('rb')as f:
  for b in iter(lambda:f.read(1<<20),b''):h.update(b)
 return h.hexdigest()
def save(p,v):
 with Path(p).open('x')as f:json.dump(v,f,indent=2);f.write('\n');f.flush();os.fsync(f.fileno())
def command(a,timeout=60,data=None):
 r=subprocess.run(a,input=data,capture_output=True,timeout=timeout)
 if r.returncode:
  f=controller/('infrastructure-'+secrets.token_hex(8)+'.log');f.write_bytes(r.stdout+b'\n'+r.stderr);raise AssertionError('Infrastructure failed: '+str(a[0])+'; original private output retained')
 return r.stdout
def host_state():
 out={}
 for name in('/etc/nginx/nginx.conf','/etc/panel','/opt/panel','/var/lib/panel','/var/lib/panel-executor','/etc/systemd/system/panel.service'):
  p=Path(name)
  if not os.path.lexists(p):out[name]={'exists':False};continue
  s=p.lstat();out[name]={'exists':True,'uid':s.st_uid,'gid':s.st_gid,'mode':s.st_mode,'inode':s.st_ino}
  if p.is_file()and not p.is_symlink():out[name]['sha256']=sha(p)
 return out
before=host_state();save(controller/'CI-host-before.json',before)
def hardware(sock):
 with socket.socket(socket.AF_UNIX)as client:
  client.settimeout(5);client.connect(str(sock))
  with client.makefile('rb')as f:
   assert 'QMP'in json.loads(f.readline(65536))
   def call(name):
    client.sendall(json.dumps({'execute':name}).encode()+b'\r\n')
    for _ in range(30):
     v=json.loads(f.readline(65536));assert 'error'not in v
     if 'return'in v:return v['return']
    raise AssertionError('QMP result absent')
   call('qmp_capabilities');value=call('query-kvm');assert value=={'enabled':True,'present':True};return value

def stop(proc,ssh):
 if proc.poll()is not None:return
 try:subprocess.run(ssh+['sudo','-n','poweroff'],capture_output=True,timeout=15)
 except subprocess.TimeoutExpired:proof['shutdown_transport_uncertain']=True
 try:proc.wait(timeout=45)
 except subprocess.TimeoutExpired:proc.terminate();proc.wait(timeout=10);proof['forced_shutdown']=True
try:
 dispatch=json.loads((source/'dispatch.json').read_bytes());assert sha(source/'kvm.py')==dispatch['kvm_sha256']and sha(source/'cases.json')==dispatch['cases_sha256']and sha(assets/'assets.json')==dispatch['payload_sha256'];assert all(sha(source/n)==h for n,h in dispatch['controller_files'].items());pin=json.loads((assets/'assets.json').read_bytes());assert pin['architecture']=='amd64'and pin['source_inputs_sha256']==proof['source_inputs_sha256'];assert all(re.fullmatch('[A-Za-z0-9._-]+',n)and sha(assets/n)==h for n,h in pin['files'].items());assert pin['files']['release-signing-dev.pub']=='4ccfcc861d56a41e3ba7f7ace7e2432c815f366c58448d783df92c6632f01339';assert sha(source/'recipient.pem')==cert_sha and(source/'recipient.pem').read_bytes().startswith(b'-----BEGIN CERTIFICATE-----\n')and b'PRIVATE KEY'not in(source/'recipient.pem').read_bytes()
 for n in dispatch['controller_files']:shutil.copyfile(source/n,controller/n)
 case=json.loads((source/'cases.json').read_bytes())['ubuntu24'];assert case['architecture']=='amd64';base=controller/'official-original.qcow2';h=hashlib.sha256();count=0
 with urllib.request.urlopen(case['image'],timeout=60)as response,base.open('xb')as f:
  assert response.status==200
  while b:=response.read(1<<20):count+=len(b);assert count<2<<30;h.update(b);f.write(b)
 assert case['digest']=='sha256:'+h.hexdigest();save(controller/'official-image-verified.json',{'url':case['image'],'sha256':h.hexdigest(),'bytes':count});original_image_sha=sha(base);bootstrap=[]
 for ident in('peer1',):
  out=controller/('bootstrap-'+ident);out.mkdir(mode=0o700);guest=out/'temporary-guest';guest.mkdir(mode=0o700);fixture=out/'fixture';fixture.mkdir(mode=0o700);p=json.loads(json.dumps(pin));p['OS_case']={**case,'hostname':'c640-platform-ubuntu24-amd64-'+ident}
  for n in p['files']:shutil.copyfile(assets/n,fixture/n)
  save(fixture/'assets.json',p);root=guest/'root.qcow2';data=guest/'owned-secondary-data.qcow2';command(['/usr/bin/qemu-img','create','-f','qcow2','-F','qcow2','-b',str(base),str(root),'64G']);command(['/usr/bin/qemu-img','create','-f','qcow2',str(data),'256M']);shutil.copyfile('/usr/share/OVMF/OVMF_VARS_4M.fd',guest/'variables.fd')
  for name in('ssh-client','ssh-host'):command(['/usr/bin/ssh-keygen','-q','-t','ed25519','-N','','-f',str(guest/name)])
  pub=(guest/'ssh-host.pub').read_text().strip();userdata={'hostname':p['OS_case']['hostname'],'manage_etc_hosts':True,'ssh_pwauth':False,'disable_root':True,'users':[{'name':'qa','groups':['sudo'],'shell':'/bin/bash','sudo':['ALL=(ALL) NOPASSWD:ALL'],'lock_passwd':True,'ssh_authorized_keys':[(guest/'ssh-client.pub').read_text().strip()]}],'ssh_keys':{'ed25519_private':(guest/'ssh-host').read_text(),'ed25519_public':pub}};(guest/'user-data').write_text('#cloud-config\n'+json.dumps(userdata));save(guest/'meta-data',{'instance-id':'c640-'+ident+'-'+secrets.token_hex(8),'local-hostname':p['OS_case']['hostname']});command(['/usr/bin/cloud-localds',str(guest/'seed.iso'),str(guest/'user-data'),str(guest/'meta-data')])
  with socket.socket()as r:r.bind(('127.0.0.1',0));port=r.getsockname()[1]
  known=guest/'known_hosts';known.write_text('[127.0.0.1]:'+str(port)+' '+pub+'\n');ssh=['/usr/bin/ssh','-F','/dev/null','-i',str(guest/'ssh-client'),'-p',str(port),'-o','IdentitiesOnly=yes','-o','StrictHostKeyChecking=yes','-o','UserKnownHostsFile='+str(known),'-o','GlobalKnownHostsFile=/dev/null','-o','ConnectTimeout=5','-o','BatchMode=yes','-o','ForwardAgent=no','-o','LogLevel=ERROR','qa@127.0.0.1'];scp=['/usr/bin/scp',*ssh[1:-1]];i=scp.index('-p');scp[i]='-P';qmp_dir=Path(tempfile.mkdtemp(prefix='c640-'+ident+'-',dir='/tmp'));sock=qmp_dir/'control.sock';nodes=[{'driver':'file','node-name':'original-file','filename':str(base),'read-only':True,'auto-read-only':False},{'driver':'qcow2','node-name':'original-image','file':'original-file','read-only':True},{'driver':'file','node-name':'root-new-file','filename':str(root),'read-only':False},{'driver':'qcow2','node-name':'root-new-image','file':'root-new-file','backing':'original-image','read-only':False}]
  args=['/usr/bin/qemu-system-x86_64','-name','yunzhan-c640-bootstrap-'+ident,'-machine','q35','-accel','kvm','-cpu','host','-smp','2','-m','2048','-display','none','-serial','file:'+str(guest/'serial.log'),'-no-reboot','-drive','if=pflash,format=raw,readonly=on,file=/usr/share/OVMF/OVMF_CODE_4M.fd','-drive','if=pflash,format=raw,file='+str(guest/'variables.fd'),'-drive','if=virtio,format=raw,readonly=on,file='+str(guest/'seed.iso')]
  for node in nodes:args+=['-blockdev',json.dumps(node,separators=(',',':'))]
  args+=['-device','virtio-blk-pci,drive=root-new-image,bootindex=0','-drive','if=none,id=data,format=qcow2,file='+str(data),'-device','virtio-blk-pci,drive=data,serial=c303-owned-data','-netdev','user,id=qa,hostfwd=tcp:127.0.0.1:'+str(port)+'-:22','-device','virtio-net-pci,netdev=qa','-qmp','unix:'+str(sock)+',server=on,wait=off'];save(out/'original-bootstrap-intent.json',{'args':args,'maximum_starts':1,'original_base_node_readonly':True})
  with(guest/'qemu.log').open('xb')as log:proc=subprocess.Popen(args,stdin=subprocess.DEVNULL,stdout=log,stderr=subprocess.STDOUT)
  processes[ident]=(proc,ssh);actual=None
  try:
   for _ in range(120):
    assert proc.poll()is None
    if subprocess.run(ssh+['true'],capture_output=True,timeout=7).returncode==0:break
    time.sleep(2)
   else:raise TimeoutError('Fresh native bootstrap SSH unavailable')
   save(out/'actual-KVM.json',{'query_kvm':hardware(sock),'TCG_fallback':False,'memory_MiB':2048});command(ssh+['sudo','-n','cloud-init','status','--wait'],180);command(ssh+['mkdir','-m','700','/home/qa/native-input']);command(scp+[str(fixture/n)for n in sorted(p['files'])]+[str(fixture/'assets.json'),'qa@127.0.0.1:/home/qa/native-input/'],150)
   with(out/'original-bootstrap.stdout').open('xb')as o,(out/'original-bootstrap.stderr').open('xb')as e:r=subprocess.run(ssh+[shlex.join(['sudo','-n','python3','-I','-B','/home/qa/native-input/guest.py','/home/qa/native-input'])],stdout=o,stderr=e,timeout=7200)
   actual=json.loads((out/'original-bootstrap.stdout').read_text().splitlines()[-1]);assert r.returncode==0 and actual['ok']and actual['architecture']=='amd64'and actual['version']=='1.3.1';base_evidence=actual['base'];assert re.fullmatch('/opt/panel-platform-native-peer-[a-f0-9]{32}',base_evidence)
   with(out/'original-bootstrap-evidence.tar.gz').open('xb')as f:r=subprocess.run(ssh+[shlex.join(['sudo','-n','tar','-C',base_evidence+'/evidence','-czf','-','.'])],stdout=f,stderr=subprocess.PIPE,timeout=90)
   assert r.returncode==0
   command(ssh+['mkdir','-m','700','/home/qa/analytics-input']);command(scp+[str(source/n)for n in ('case.py','cold.py','plan.json')]+['qa@127.0.0.1:/home/qa/analytics-input/'],120)
   for phase in ('business','cold'):
    if phase=='cold':
     stop(proc,ssh);assert proc.poll()is not None and not proof.get('forced_shutdown');assert sock.is_socket();sock.unlink()
     with(guest/'cold-qemu.log').open('xb')as log:proc=subprocess.Popen(args,stdin=subprocess.DEVNULL,stdout=log,stderr=subprocess.STDOUT)
     processes[ident]=(proc,ssh)
     for _ in range(120):
      assert proc.poll()is None
      if subprocess.run(ssh+['true'],capture_output=True,timeout=7).returncode==0:break
      time.sleep(2)
     else:raise TimeoutError('Original analytics cold SSH unavailable')
     save(out/'actual-analytics-cold-KVM.json',{'query_kvm':hardware(sock),'TCG_fallback':False,'memory_MiB':2048})
    argv=['sudo','-n','python3','-I','-B','/home/qa/analytics-input/'+('case.py'if phase=='business'else'cold.py'),'/home/qa/analytics-input']+(['cold']if phase=='cold'else[])
    with(out/('original-analytics-'+phase+'.stdout')).open('xb')as o,(out/('original-analytics-'+phase+'.stderr')).open('xb')as e:result=subprocess.run(ssh+[shlex.join(argv)],stdin=subprocess.DEVNULL,stdout=o,stderr=e,timeout=1800)
    observed=json.loads((out/('original-analytics-'+phase+'.stdout')).read_text().splitlines()[-1]);proof['actual_analytics_'+phase]=observed;assert result.returncode==0 and observed['ok'],'Original actual native analytics phase failed; preserved without replay'
   assert proof['actual_analytics_cold']['different_boot_and_all_original_state_exact']and proof['actual_analytics_business']['boot']!=proof['actual_analytics_cold']['boot']
   case_base=json.loads((source/'plan.json').read_bytes())['case_base'];assert re.fullmatch('/opt/panel-analytics-c637-qa-[a-f0-9]{32}',case_base)
   with(out/'original-analytics-evidence.tar.gz').open('xb')as f:r=subprocess.run(ssh+[shlex.join(['sudo','-n','tar','-C',case_base+'/evidence','-czf','-','.'])],stdout=f,stderr=subprocess.PIPE,timeout=120)
   assert r.returncode==0
  finally:
   stop(proc,ssh)
   if sock.exists():assert sock.is_socket();sock.unlink()
   qmp_dir.rmdir()
  assert actual and actual['ok']and proc.poll()is not None and not proof.get('forced_shutdown');save(out/'peer-host-plan.json',{'ssh':ssh,'fixture':str(fixture)});record={'ok':True,'out':str(out),'prepared':actual,'owned_guest_stopped':True,'successful_bootstrap_parent_retained_stopped_for_readonly_COW_pair':True};save(controller/('C610-platform-'+ident+'-amd64-bootstrap-qualified-once.json'),record);bootstrap.append(record);print(json.dumps({'phase':'native-bootstrap-completed','peer':ident,'original_installation':actual['installation_id']}),flush=True)
 assert len(bootstrap)==1;proof.update(ok=True,full_native_business_completed=True,bootstraps=[r['prepared']for r in bootstrap],owned_guest_stopped=True)
except BaseException:proof['original_failure']=traceback.format_exc()[-4500:];save(controller/'original-wrapper-failure.json',{'traceback':traceback.format_exc()})
finally:
 for proc,ssh in processes.values():stop(proc,ssh)
 proof['paired_owned_guests_stopped']=True
 proof['bootstrap_owned_guests_stopped']=all(proc.poll()is not None for proc,ssh in processes.values());proof['host_protected_state_unchanged']=host_state()==before;proof['official_original_image_unchanged']=not(controller/'official-original.qcow2').exists()or sha(controller/'official-original.qcow2')==locals().get('original_image_sha');proof['ok']=bool(proof['ok']and proof['bootstrap_owned_guests_stopped']and proof['paired_owned_guests_stopped']and proof['host_protected_state_unchanged']and proof['official_original_image_unchanged']and not proof.get('forced_shutdown'))
 envelope=work/'original-private-evidence.tar.gz'
 try:
  with tarfile.open(envelope,'x:gz')as t:
   for p in controller.rglob('*'):
    if not p.is_file()or p.is_symlink()or p.suffix not in('.json','.stdout','.stderr','.log','.pem')and not p.name.endswith('.tar.gz'):continue
    if p.stat().st_size>64<<20:continue
    t.add(p,arcname=str(p.relative_to(controller)),recursive=False)
  encrypted=public/'private-evidence.cms';command(['/usr/bin/openssl','cms','-encrypt','-binary','-aes-256-gcm','-in',str(envelope),'-outform','DER','-out',str(encrypted),'-recip',str(source/'recipient.pem'),'-keyopt','rsa_padding_mode:oaep','-keyopt','rsa_oaep_md:sha256']);os.chown(encrypted,owner.st_uid,owner.st_gid);proof['private_evidence']={'encrypted':True,'certificate_sha256':cert_sha,'sha256':sha(encrypted),'plaintext_sha256':sha(envelope),'plaintext_bytes':envelope.stat().st_size}
 except BaseException:proof['ok']=False;proof['evidence_failure']=traceback.format_exc()[-1500:]
 save(public/'result.json',proof);os.chown(public/'result.json',owner.st_uid,owner.st_gid);print(json.dumps({'ok':proof['ok'],'native_architecture':'amd64','bootstrap_owned_guests_stopped':proof['bootstrap_owned_guests_stopped'],'paired_owned_guests_stopped':proof['paired_owned_guests_stopped'],'original_failure':proof.get('original_failure'),'all40_commercial':False}),flush=True)
sys.exit(0 if proof['ok']else 1)
