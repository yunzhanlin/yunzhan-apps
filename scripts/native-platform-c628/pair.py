from pathlib import Path
import hashlib,io,json,os,re,secrets,shlex,shutil,socket,subprocess,sys,tarfile,tempfile,time
os.umask(0o077);q=Path(__file__).resolve().parent;image_tool='/usr/bin/qemu-img';qemu_tool='/usr/bin/qemu-system-x86_64';node_case=q/'node-case.mjs';cold_case=q/'cold.py';node_tool=os.environ['C628_NODE_TOOL'];assert Path(node_tool).is_file()
def sha(p):
 with Path(p).open('rb')as f:return hashlib.file_digest(f,'sha256').hexdigest()
def write(p,v):
 with Path(p).open('x')as f:json.dump(v,f,indent=2);f.write('\n');f.flush();os.fsync(f.fileno())
def command(a,timeout=60):return subprocess.check_output(a,stderr=subprocess.PIPE,timeout=timeout)
def vm_state():
 paths={}
 for name in('/etc/nginx/nginx.conf','/etc/panel','/opt/panel','/var/lib/panel','/var/lib/panel-executor','/etc/systemd/system/panel.service'):
  p=Path(name)
  if not os.path.lexists(p):paths[name]={'exists':False};continue
  st=p.lstat();paths[name]={'exists':True,'uid':st.st_uid,'gid':st.st_gid,'mode':st.st_mode,'inode':st.st_ino}
  if p.is_file()and not p.is_symlink():paths[name]['sha256']=sha(p)
 return {'CI-host':{'namespaces_checked':True,'files':paths}}

def closed(files):
 r=subprocess.run(['/usr/bin/lsof','-nP','-F','p','--',*map(str,files)],capture_output=True,text=True,timeout=30);assert r.returncode==1 and not r.stdout and not r.stderr,'Original evidence must not be open'
def prepare():
 assert sys.argv[1:]==['--prepare-only'];assert not(q/'C628-native-pair-prepared-once.json').exists();source=[]
 for ident in('peer1','peer2'):
  receipt=q/('C610-platform-'+ident+'-amd64-bootstrap-qualified-once.json');r=json.loads(receipt.read_bytes());assert r['ok']and r['owned_guest_stopped']and r['successful_bootstrap_parent_retained_stopped_for_readonly_COW_pair'];parent=Path(r['out'])/'temporary-guest';host=json.loads((parent.parent/'peer-host-plan.json').read_bytes());source.append((ident,r,parent,host))
 assert source[0][1]['prepared']['installation_id']!=source[1][1]['prepared']['installation_id'];out=Path(tempfile.mkdtemp(prefix='C628-native-platform-pair-RO-',dir=q));ctl=Path(tempfile.mkdtemp(prefix='c628-platform-pair-',dir='/tmp'));protected={};peers=[]
 for ident,r,parent,host in source:
  work=out/ident;work.mkdir(mode=0o700);chains={kind:json.loads(command([image_tool,'info','--backing-chain','--output=json',str(parent/name)]))for kind,name in(('root','root.qcow2'),('data','owned-secondary-data.qcow2'))};assert all(chain and all(x['format']=='qcow2'for x in chain)and not chain[-1].get('backing-filename')for chain in chains.values())
  for chain in chains.values():
   for row in chain:original=Path(row['filename']).resolve(strict=True);protected[str(original)]=sha(original)
  for original in(parent/'variables.fd',parent/'seed.iso'):protected[str(original.resolve(strict=True))]=sha(original)
  closed(protected);nodes=[]
  for kind,chain in chains.items():
   original=Path(chain[0]['filename']).resolve(strict=True);overlay=work/(kind+'-overlay.qcow2');command([image_tool,'create','-f','qcow2','-F','qcow2','-b',str(original),str(overlay)]);previous=None
   for index in reversed(range(len(chain))):
    original=Path(chain[index]['filename']).resolve(strict=True);name=kind+'-parent-'+str(index);nodes.append({'driver':'file','node-name':name+'-file','filename':str(original),'read-only':True,'auto-read-only':False});image={'driver':'qcow2','node-name':name+'-image','file':name+'-file','read-only':True}
    if previous:image['backing']=previous
    nodes.append(image);previous=name+'-image'
   nodes.extend([{'driver':'file','node-name':kind+'-new-file','filename':str(overlay),'read-only':False},{'driver':'qcow2','node-name':kind+'-new-image','file':kind+'-new-file','backing':previous,'read-only':False}])
  shutil.copyfile(parent/'variables.fd',work/'variables.fd');pub=(parent/'known_hosts').read_text().strip().split(' ',1)[1]
  with socket.socket()as reserve:reserve.bind(('127.0.0.1',0));port=reserve.getsockname()[1]
  known=work/'known_hosts';known.open('x').write('[127.0.0.1]:'+str(port)+' '+pub+'\n');key=host['ssh'][host['ssh'].index('-i')+1];ssh=['/usr/bin/ssh','-F','/dev/null','-i',key,'-p',str(port),'-o','IdentitiesOnly=yes','-o','StrictHostKeyChecking=yes','-o','UserKnownHostsFile='+str(known),'-o','GlobalKnownHostsFile=/dev/null','-o','ConnectTimeout=5','-o','BatchMode=yes','-o','ForwardAgent=no','-o','LogLevel=ERROR','qa@127.0.0.1'];args=[qemu_tool,'-name','yunzhan-c628-native-platform-'+ident,'-machine','q35','-accel','kvm','-cpu','host','-smp','2','-m','2048','-display','none','-serial','file:'+str(work/'serial.log'),'-no-reboot','-drive','if=pflash,format=raw,readonly=on,file=/usr/share/OVMF/OVMF_CODE_4M.fd','-drive','if=pflash,format=raw,file='+str(work/'variables.fd'),'-drive','if=virtio,format=raw,readonly=on,file='+str(parent/'seed.iso')]
  for n in nodes:args+=['-blockdev',json.dumps(n,separators=(',',':'))]
  args+=['-device','virtio-blk-pci,drive=root-new-image,bootindex=0','-device','virtio-blk-pci,drive=data-new-image,serial=c303-owned-data','-netdev','user,id=qa,hostfwd=tcp:127.0.0.1:'+str(port)+'-:22','-device','virtio-net-pci,netdev=qa','-qmp','unix:'+str(ctl/(ident+'.sock'))+',server=on,wait=off'];writable={n['filename']for n in nodes if n['driver']=='file'and not n['read-only']};assert writable=={str(work/'root-overlay.qcow2'),str(work/'data-overlay.qcow2')}and all(n['read-only']for n in nodes if'-parent-'in n['node-name']);fixture=json.loads((Path(host['fixture'])/'assets.json').read_bytes());peers.append({'id':ident,'architecture':'amd64','parent':str(parent),'work':str(work),'args':args,'nodes':nodes,'ssh':ssh,'prior':r['prepared'],'host':fixture['OS_case']['hostname'],'qmp':str(ctl/(ident+'.sock')),'new_writable_files':sorted(writable),'memory_MiB':2048,'owned_QA':True})
 plan={'out':str(out),'ctl':str(ctl),'peers':peers,'protected_sha256':protected,'original_VM_statuses':vm_state(),'driver_sha256':sha(__file__),'node_case_sha256':sha(node_case),'cold_case_sha256':sha(cold_case),'all_original_parent_nodes_explicitly_readonly':True,'maximum_owned_guest_memory_MiB':4096,'Main_changes':0,'all40_commercial':False};assert plan['original_VM_statuses']['CI-host']['namespaces_checked'];write(out/'prepared-plan.json',plan);write(q/'C628-native-pair-prepared-once.json',{'ok':True,'out':str(out),'plan_sha256':sha(out/'prepared-plan.json'),'VM_started':False,'original_parent_nodes_readonly':True,'only_new_overlays_writable':4,'owned_guest_memory_MiB_each':2048});print(json.dumps({'ok':True,'out':str(out),'VM_started':False,'new_writable_overlays':4,'owned_memory_MiB_each':2048}))

def verify_kvm(path):
 with socket.socket(socket.AF_UNIX)as client:
  client.settimeout(5);client.connect(path)
  with client.makefile('rb')as reader:
   assert 'QMP'in json.loads(reader.readline(65536))
   def call(name):
    client.sendall(json.dumps({'execute':name}).encode()+b'\r\n')
    for _ in range(30):
     r=json.loads(reader.readline(65536));assert 'error'not in r
     if 'return'in r:return r['return']
    raise AssertionError('QMP response absent')
   call('qmp_capabilities');value=call('query-kvm');assert value=={'enabled':True,'present':True};return value

def execute():
 assert len(sys.argv)==3 and sys.argv[1]=='--run-prepared';receipt=json.loads((q/'C628-native-pair-prepared-once.json').read_bytes());out=Path(sys.argv[2]).resolve(strict=True);assert str(out)==receipt['out']and out.parent==q and sha(out/'prepared-plan.json')==receipt['plan_sha256'];p=json.loads((out/'prepared-plan.json').read_bytes());assert sha(__file__)==p['driver_sha256']and sha(node_case)==p['node_case_sha256']and sha(cold_case)==p['cold_case_sha256'];assert not(out/'execution-intent.json').exists();assert all(sha(n)==v for n,v in p['protected_sha256'].items());closed(p['protected_sha256']);assert vm_state()==p['original_VM_statuses'];assert p['maximum_owned_guest_memory_MiB']==4096 and len(p['peers'])==2
 for peer in p['peers']:
  nodes=[json.loads(peer['args'][i+1])for i,x in enumerate(peer['args'])if x=='-blockdev'];assert nodes==peer['nodes']and all(n['read-only']for n in nodes if'-parent-'in n['node-name']);assert {n['filename']for n in nodes if n['driver']=='file'and not n['read-only']}==set(peer['new_writable_files'])and all(Path(n).parent==Path(peer['work'])for n in peer['new_writable_files']);assert peer['args'][peer['args'].index('-m')+1]=='2048'and peer['args'][peer['args'].index('-accel')+1]=='kvm'
 write(out/'execution-intent.json',{'maximum_original_business_test_runs':1,'original_app_request_replays':0,'maximum_simultaneous_owned_guests':2,'memory_MiB_per_guest':2048,'all_parent_nodes_readonly':True});processes={};report={'ok':False,'out':str(out),'Main_changes':0,'all40_commercial':False,'original_operation_replays':0,'original_parent_nodes_explicitly_read_only':True};remotes={}
 def start(peer,phase):
  args=list(peer['args']);args[args.index('-serial')+1]='file:'+str(Path(peer['work'])/('serial-'+phase+'.log'));sock=Path(peer['qmp'])
  if sock.exists():assert sock.is_socket();sock.unlink()
  with(Path(peer['work'])/('qemu-'+phase+'.log')).open('xb')as log:proc=subprocess.Popen(args,stdin=subprocess.DEVNULL,stdout=log,stderr=subprocess.STDOUT)
  processes[peer['id']]=proc
  status_path=Path('/proc')/str(proc.pid)/'stat';start_stamp=status_path.read_text().rsplit(')',1)[1].split()[19]if status_path.exists()else'';write(Path(peer['work'])/('owned-qemu-process-'+phase+'.json'),{'pid':proc.pid,'start_stamp':start_stamp,'args':args})
  for _ in range(100):
   assert proc.poll()is None
   if subprocess.run(peer['ssh']+['true'],capture_output=True,timeout=7).returncode==0:break
   time.sleep(2)
  else:raise TimeoutError('Owned native peer SSH unavailable')
  code="import json,pathlib,platform;print(json.dumps({'boot':pathlib.Path('/proc/sys/kernel/random/boot_id').read_text().strip(),'arch':platform.machine(),'pid1':pathlib.Path('/proc/1/comm').read_text().strip()}))";boot=json.loads(command(peer['ssh']+[shlex.join(['python3','-I','-B','-c',code])],25));assert boot['arch']=='x86_64'and boot['pid1']=='systemd';write(out/(peer['id']+'-'+phase+'-native-boot.json'),{'boot':boot,'actual_accelerator':'kvm','query_kvm':verify_kvm(peer['qmp']),'TCG_fallback':False,'memory_MiB':2048});return boot
 def stop(peer):
  proc=processes.get(peer['id'])
  if proc is None or proc.poll()is not None:return
  try:subprocess.run(peer['ssh']+['sudo','-n','poweroff'],capture_output=True,timeout=15)
  except subprocess.TimeoutExpired:report['shutdown_request_uncertain']=True
  try:proc.wait(timeout=45)
  except subprocess.TimeoutExpired:proc.terminate();proc.wait(timeout=10);report['forced_cleanup']=True
 def stage(peer,operation_ids):
  remote='/var/lib/panel-executor/c614-input-'+secrets.token_hex(16);plan={'host':peer['host'],'source':peer['prior']['source_inputs_sha256'],'installation_id':peer['prior']['installation_id'],'case_base':'/var/lib/panel-executor/c614-owned-platform-cold-'+secrets.token_hex(16),'operation_ids':operation_ids,'original_owned_site':peer['prior']['original_owned_site'],'original_owned_file':peer['prior']['original_owned_file']};raws={'case.py':cold_case.read_bytes(),'plan.json':json.dumps(plan).encode()};pins={n:hashlib.sha256(b).hexdigest()for n,b in raws.items()};buf=io.BytesIO()
  with tarfile.open(fileobj=buf,mode='w')as t:
   for n,b in raws.items():m=tarfile.TarInfo(n);m.mode=0o600;m.size=len(b);t.addfile(m,io.BytesIO(b))
  code="import hashlib,json,os,pathlib,sys,tarfile;d=pathlib.Path(sys.argv[1]);p=json.loads(sys.argv[2]);assert os.geteuid()==0 and d.parent==pathlib.Path('/var/lib/panel-executor')and not d.exists();d.mkdir(mode=0o700);t=tarfile.open(fileobj=sys.stdin.buffer,mode='r|');seen=set();\nfor m in t:\n assert m.isfile()and m.name in p and m.name not in seen;seen.add(m.name);b=t.extractfile(m).read();assert hashlib.sha256(b).hexdigest()==p[m.name];f=(d/m.name).open('xb');f.write(b);f.flush();os.fsync(f.fileno());f.close()\nassert seen==set(p)";r=subprocess.run(peer['ssh']+[shlex.join(['sudo','-n','python3','-I','-B','-c',code,remote,json.dumps(pins)])],input=buf.getvalue(),capture_output=True,timeout=80);write(out/(peer['id']+'-cold-input-staging.json'),{'exit':r.returncode,'stderr':r.stderr.decode()[-1200:]});assert r.returncode==0;remotes[peer['id']]={'input':remote,'case_base':plan['case_base']}
 def observe(peer,phase):
  with(out/(peer['id']+'-'+phase+'.stdout')).open('xb')as o,(out/(peer['id']+'-'+phase+'.stderr')).open('xb')as e:r=subprocess.run(peer['ssh']+[shlex.join(['sudo','-n','python3','-I','-B',remotes[peer['id']]['input']+'/case.py',remotes[peer['id']]['input'],phase])],stdout=o,stderr=e,timeout=300)
  lines=(out/(peer['id']+'-'+phase+'.stdout')).read_text().splitlines();actual=json.loads(lines[-1]);write(out/(peer['id']+'-'+phase+'-original.json'),actual);assert r.returncode==0 and actual['ok'],actual;return actual
 try:
  live=[]
  for peer in p['peers']:
   boot=start(peer,'paired');assert boot['boot']!=peer['prior']['boot'];prior=dict(peer['prior']);prior['boot']=boot['boot'];live.append({'id':peer['id'],'ssh':peer['ssh'],'architecture':'amd64','owned_QA':True,'prior':prior})
  node_plan={'owned_QA':True,'Main_changes':0,'peers':live,'out':str(out),'openssl':'/usr/bin/openssl'};write(out/'paired-plan-without-credentials.json',node_plan);print(json.dumps({'phase':'current-native-two-peer-TLS-health-fleet-and-lost-ack','out':str(out),'memory_MiB_each':2048}),flush=True)
  with(out/'original-paired-TLS.stdout').open('xb')as o,(out/'original-paired-TLS.stderr').open('xb')as e:r=subprocess.run([node_tool,str(node_case)],input=json.dumps(node_plan).encode(),stdout=o,stderr=e,timeout=1800)
  report['native_pair_exit']=r.returncode;lines=(out/'original-paired-TLS.stdout').read_text().splitlines();actual=json.loads(lines[-1])if lines else{'ok':False};report['actual_native_paired_business']=actual;assert r.returncode==0 and actual['ok']and actual['fleet']['ok']and actual['health']['ok'];ids={peer['id']:[]for peer in p['peers']}
  for v in actual['targets'].values():ids[v['target']].append(v['request_id'])
  for i,peer in enumerate(p['peers']):ids[peer['id']].append(actual['fleet']['original_request_ids'][i]);assert len(set(ids[peer['id']]))==3;stage(peer,ids[peer['id']])
  snapshots={peer['id']:observe(peer,'snapshot')for peer in p['peers']};report['original_snapshots']=snapshots
  for peer in p['peers']:stop(peer)
  assert all(proc.poll()is not None for proc in processes.values())and not report.get('forced_cleanup')
  for peer in p['peers']:boot=start(peer,'cold');assert boot['boot']!=snapshots[peer['id']]['boot']
  cold={peer['id']:observe(peer,'cold')for peer in p['peers']};assert all(r['different_boot_and_all_original_state_exact']for r in cold.values());report['original_cold']=cold;report['ok']=True
 finally:
  for peer in p['peers']:
   proc=processes.get(peer['id'])
   if proc is not None and proc.poll()is None and peer['id']in remotes:
    with(out/(peer['id']+'-original-cold-evidence.tar.gz')).open('xb')as f:r=subprocess.run(peer['ssh']+[shlex.join(['sudo','-n','tar','-C',remotes[peer['id']]['case_base'],'-czf','-','.'])],stdout=f,stderr=subprocess.PIPE,timeout=80)
    report[peer['id']+'_cold_evidence_exit']=r.returncode;report['ok']=report['ok']and r.returncode==0
   stop(peer)
  report['owned_guests_stopped']=len(processes)==2 and all(proc.poll()is not None for proc in processes.values());report['protected_originals_byte_identical']=all(sha(n)==v for n,v in p['protected_sha256'].items());after=vm_state();report['CI_host_state_preserved']=after==p['original_VM_statuses'];report['unowned_VM_status_differences']={n:{'before':p['original_VM_statuses'].get(n),'after':after.get(n)}for n in p['original_VM_statuses'].keys()|after.keys()if p['original_VM_statuses'].get(n)!=after.get(n)};report['ok']=report['ok']and report['owned_guests_stopped']and report['protected_originals_byte_identical']and report['CI_host_state_preserved']and not report.get('forced_cleanup');assert report['protected_originals_byte_identical'];ctl=Path(p['ctl'])
  for sock in ctl.iterdir():assert sock.is_socket();sock.unlink()
  ctl.rmdir();write(out/'result.json',report);write(q/'C628-current-native-AMD-platform-pair-qualified-once.json',report);print(json.dumps({k:v for k,v in report.items()if k not in('actual_native_paired_business','original_snapshots','original_cold')}),flush=True)
 assert report['ok']
if sys.argv[1:]==['--prepare-only']:prepare()
else:execute()
