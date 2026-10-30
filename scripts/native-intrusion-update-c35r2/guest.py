"""Fresh actual native signed110 installation, preserved programme and signed111 update.
Original failures remain terminal. No source/key/feature/catalogue URL override,
existing-host application adoption, Main changes, or original operation replay.
"""
import hashlib,json,os,pathlib,platform,re,secrets,shutil,stat,subprocess,sys,traceback
os.umask(0o077);assert os.geteuid()==0 and len(sys.argv)==2
incoming=pathlib.Path(sys.argv[1]).resolve(strict=True);arch={'x86_64':'amd64','aarch64':'arm64'}[platform.machine()]
base=pathlib.Path('/opt/panel-intrusion-native-qa-'+secrets.token_hex(16));base.mkdir(mode=0o700);evidence=base/'evidence';evidence.mkdir(mode=0o700);cases={}
SOURCE='3c8dbb9dacc68ad23a5904c99303f421703e48db39e3f4d0215d5013603b48a8';VERSION='0.1.0-dev.proapps24intrusionubuntu22candidate35r2';OLD_SOURCE='e2800be6bf3da01db4548e7fc90bc88861a3ba5d7ca32284a72cdd72d66d2a46';OLD_VERSION='0.1.0-dev.proapps24intrusionbaseline35r1'
def sha(p):return hashlib.sha256(pathlib.Path(p).read_bytes()).hexdigest()
def save(name,value):
 assert re.fullmatch('[A-Za-z0-9._-]+',name)
 with(evidence/name).open('x')as f:json.dump(value,f,sort_keys=True,indent=2);f.write('\n');f.flush();os.fsync(f.fileno())
def exact_copy(source,destination,digest,allow_empty=False):
 fd=os.open(source,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
 with os.fdopen(fd,'rb')as f:
  s=os.fstat(f.fileno());assert stat.S_ISREG(s.st_mode)and s.st_nlink==1 and(0<=s.st_size<=64<<20 if allow_empty else 0<s.st_size<=64<<20);raw=f.read((64<<20)+1);assert len(raw)==s.st_size and hashlib.sha256(raw).hexdigest()==digest
  z=os.fstat(f.fileno());assert(s.st_dev,s.st_ino,s.st_size,s.st_mtime_ns,s.st_ctime_ns)==(z.st_dev,z.st_ino,z.st_size,z.st_mtime_ns,z.st_ctime_ns)
 with os.fdopen(os.open(destination,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600),'wb')as f:f.write(raw);f.flush();os.fsync(f.fileno())
def stage(label,prefix,mapping,extra=None):
 path=pathlib.Path(prefix+secrets.token_hex(16));path.mkdir(mode=0o700);files={}
 for dest,name in mapping.items():
  assert re.fullmatch('[A-Za-z0-9._-]+',dest)and name in pins['files'];exact_copy(payload/name,path/dest,pins['files'][name]);files[dest]=pins['files'][name]
 intent={'peer':peer,'files':files,'version':VERSION,**(extra or{})}
 with(path/'intent.json').open('x')as f:json.dump(intent,f,sort_keys=True);f.write('\n')
 cases[label]=path;return path,intent

def run(label,script,path,timeout):
 save(label+'-once-intent.json',{'script':str(script),'case':str(path),'maximum_submissions':1,'unknown_outcome_observe_only':True})
 with(evidence/(label+'.stdout.log')).open('xb')as out,(evidence/(label+'.stderr.log')).open('xb')as err:r=subprocess.run(['python3','-I','-B',str(script),str(path)],stdin=subprocess.DEVNULL,stdout=out,stderr=err,timeout=timeout)
 save(label+'-outcome.json',{'exit':r.returncode,'stdout_sha256':sha(evidence/(label+'.stdout.log')),'stderr_sha256':sha(evidence/(label+'.stderr.log'))})
 lines=(evidence/(label+'.stdout.log')).read_text().splitlines();values=[]
 for line in lines:
  if line.startswith('{'):
   try:values.append(json.loads(line))
   except ValueError:pass
 if label=='old110'and values and isinstance(values[-1],dict)and re.fullmatch('/opt/panel-intrusion-native-qa-[a-f0-9]{32}',str(values[-1].get('base',''))):
  child=pathlib.Path(values[-1]['base'])/'evidence';assert sha(child/'proof.json')==values[-1]['proof_sha256'];cases['old110']=child
 assert r.returncode==0,'Original '+label+' failed; no reset, retry or later phase submitted'
 assert values and values[-1]['ok'];return values[-1]
proof={'ok':False,'source_inputs_sha256':SOURCE,'architecture':arch,'normal_110_install_programme_upgrade_111_update':False,'Main_changed':False,'all50_commercial':False,'failed_or_unknown_requests_replayed':False}
try:
 assert pathlib.Path('/proc/1/comm').read_text().strip()=='systemd'and 'VERSION_ID="24.04"'in pathlib.Path('/usr/lib/os-release').read_text()
 assert pathlib.Path('/etc/hostname').read_text().strip()=={'amd64':'yunzhan-native-kvm-c35-update','arm64':'lima-panel-intrusion-c35-update2-ubuntu24'}[arch]
 assert all(not os.path.lexists(n)for n in('/opt/panel','/var/lib/panel','/var/lib/panel-executor','/etc/panel-release','/etc/nginx/nginx.conf'))
 pins=json.loads((incoming/'assets.json').read_bytes());assert pins['format']==1 and pins['architecture']==arch and pins['source_inputs_sha256']==SOURCE and pins['version']==VERSION and pins['baseline_source_inputs_sha256']==OLD_SOURCE and pins['baseline_version']==OLD_VERSION
 for name,h in pins['files'].items():assert re.fullmatch('[A-Za-z0-9._-]+',name)and re.fullmatch('[a-f0-9]{64}',h)and sha(incoming/name)==h
 assert pins['files']['programme.pub']=='4ccfcc861d56a41e3ba7f7ace7e2432c815f366c58448d783df92c6632f01339'and pins['files']['signed-release.py']=='fe128e82b4e11345b320cd782134768bfe1a4df14947c425d7494873a7a7b7b5'
 payload=base/'verified-input';payload.mkdir(mode=0o700)
 for name,digest in pins['files'].items():exact_copy(incoming/name,payload/name,digest)
 peer={'arch':arch,'boot':pathlib.Path('/proc/sys/kernel/random/boot_id').read_text().strip(),'machine_id_sha256':sha('/etc/machine-id')};save('actual-native-identity-and-inputs.json',{'peer':peer,'source_inputs_sha256':SOURCE,'files':pins['files'],'Root_private_input_directory':True,'original_signer_and_key':True})
 old_archive='panel-'+OLD_VERSION+'-linux-'+arch+'.tar.gz';current_archive='panel-'+VERSION+'-linux-'+arch+'.tar.gz'
 common={n:n for n in('programme.pub','signed-release.py')};old={old_archive+s:old_archive+s for s in('','.manifest','.sig')};current={current_archive+s:current_archive+s for s in('','.manifest','.sig')}
 initial,intent=stage('baseline','/var/tmp/yunzhan-intrusion-c35-update-baseline-',{**common,**old,'guest.py':'baseline.py'})
 run('baseline',initial/'guest.py',initial,1500);assert json.loads(pathlib.Path('/opt/panel/current/SOURCE_INPUTS.json').read_bytes())['inputs_sha256']==OLD_SOURCE
 old_input=base/'old110-input';old_input.mkdir(mode=0o700);old_files={}
 for dest,name in{**common,**old,'guest.py':'old110.py','ssh-journey.py':'ssh-journey.py'}.items():exact_copy(payload/name,old_input/dest,pins['files'][name]);old_files[dest]=pins['files'][name]
 with(old_input/'assets.json').open('x')as f:json.dump({'format':1,'architecture':arch,'source_inputs_sha256':OLD_SOURCE,'version':OLD_VERSION,'files':old_files,'app_manifest_sha256':'63df83f7a31237cfdf810d3374b379032f609d9c97b2c77eaa5fde174b31a112'},f,indent=2)
 summary=run('old110',old_input/'guest.py',old_input,600);assert re.fullmatch('/opt/panel-intrusion-native-qa-[a-f0-9]{32}',summary['base']);old_evidence=pathlib.Path(summary['base'])/'evidence';assert sha(old_evidence/'proof.json')==summary['proof_sha256'];cases['old110']=old_evidence
 old_proof=json.loads((old_evidence/'proof.json').read_bytes());assert old_proof['normal_original_key_signed_registry_app110_install']and old_proof['actual_SSH_authentication_journey_passed'];proof['old110_original_jobs']={'install':old_proof['install_job'],'configure':old_proof['actual_SSH_journey']['configure_job']}
 upgrade,intent=stage('programme','/var/tmp/yunzhan-intrusion-c35r2-old110-upgrade-',{**common,**current,'guest.py':'programme-upgrade.py',**{n:n for n in('business.py','observations.py','capture-model.py')}},{'installed110_case':{'proof_path':str(old_evidence/'proof.json'),'proof_sha256':summary['proof_sha256']}})
 run('programme',upgrade/'guest.py',upgrade,1500);assert json.loads(pathlib.Path('/etc/panel/security-apps/intrusion-prevention.json').read_bytes())['version']=='1.1.0'
 update,update_intent=stage('app_update','/var/tmp/yunzhan-intrusion-c35r2-update-app-',{'guest.py':'app-update.py','old110-source.py':'old110.py'},{'programme_case':str(upgrade),'programme_files':intent['files'],'old110_source_sha256':pins['files']['old110.py']})
 result=run('app_update',update/'guest.py',update,420);cases['app_update']=update/'evidence';assert re.fullmatch('[a-f0-9]{32}',result['job']);proof['update_original_job']=result['job']
 proof.update(ok=True,normal_110_install_programme_upgrade_111_update=True,normal_original_programme_and_application_trust_roots_unchanged=True,exact_old110_history_and_live_bans_preserved=True,independent_full_evidence_qualification_pending=True,historical_baseline_OS_numeric22_explicitly_loaded_before_first_app_request=True,fresh_current_Ubuntu24_auto_initialization_acceptance=False)
except BaseException:save('failure.json',{'traceback':traceback.format_exc()})
finally:
 # Retain the original live journal/pending/Core evidence even if a phase
 # fails before its own after-snapshot. Never reset or replay an unknown job.
 try:
  if 'payload'in globals()and pathlib.Path('/var/lib/panel/panel.db').is_file():
   import runpy
   library=runpy.run_path(str(payload/'business.py'));core=library['capture_core']();save('terminal-original-current-Core.json',core)
   state=evidence/'terminal-original-security-files';state.mkdir(mode=0o700);inventory={};candidates=[]
   security=pathlib.Path('/etc/panel/security-apps')
   for name in('intrusion.pending.json','intrusion-prevention.json','intrusion-policy.json','intrusion-configuration.lock'):
    f=security/name
    if os.path.lexists(f):candidates.append(f)
   archive=security/'intrusion-transactions'
   if archive.exists():
    a=archive.lstat();assert stat.S_ISDIR(a.st_mode)and a.st_uid==0 and stat.S_IMODE(a.st_mode)==0o700
    for f in sorted(archive.iterdir()):
     assert re.fullmatch(r'[a-f0-9]{32}\.json',f.name)or re.fullmatch(r'\.intrusion-terminal-[a-f0-9]{32}\.tmp',f.name);candidates.append(f)
   jail=pathlib.Path('/etc/fail2ban/jail.d/panel-intrusion.local')
   if os.path.lexists(jail):candidates.append(jail)
   size=0
   for i,f in enumerate(candidates):
    z=f.lstat();assert stat.S_ISREG(z.st_mode)and z.st_uid==0 and z.st_nlink==1 and stat.S_IMODE(z.st_mode)in(0o600,0o640,0o644)and z.st_size<=2<<20
    size+=z.st_size;assert size<=32<<20 and i<256
    name=str(i)+'-'+f.name;digest=sha(f);exact_copy(f,state/name,digest,allow_empty=True);inventory[name]={'original_path':str(f),'sha256':digest,'original_mode':stat.S_IMODE(z.st_mode),'bytes':z.st_size}
   save('terminal-original-security-index.json',inventory);proof['original_current_Core_and_pending_terminal_security_evidence_retained']=True
 except BaseException:
  proof['ok']=False;save('terminal-original-state-collection-failure.json',{'traceback':traceback.format_exc()})
 # Copy only known original QA evidence, never private keys, seed, root disk,
 # first-login file or live application credentials; the host encrypts it.
 retained={};retained_count=0;retained_bytes=0
 for label,path in cases.items():
  if label=='app_update'and not(path/'proof.json').exists()and(path/'evidence').is_dir():path=path/'evidence'
  dest=evidence/label;dest.mkdir(mode=0o700);retained[label]={}
  for f in sorted(path.iterdir()):
   if not f.name.endswith(('.json','.log','.stdout','.stderr')):continue
   s=f.lstat();assert stat.S_ISREG(s.st_mode)and s.st_uid==0 and s.st_nlink==1 and s.st_size<=32<<20 and(stat.S_IMODE(s.st_mode)==0o600 or f.name=='worker.log'and stat.S_IMODE(s.st_mode)==0o644)
   retained_count+=1;retained_bytes+=s.st_size;assert retained_count<=256 and retained_bytes<=128<<20
   digest=sha(f);exact_copy(f,dest/f.name,digest,allow_empty=True);retained[label][f.name]={'sha256':digest,'original_mode':stat.S_IMODE(s.st_mode),'bytes':s.st_size}
 save('original-evidence-members.json',retained);save('proof.json',proof);print(json.dumps({'ok':proof['ok'],'base':str(base),'proof_sha256':sha(evidence/'proof.json'),'source_inputs_sha256':SOURCE,'architecture':arch,'Main_changed':False,'all50_commercial':False}),flush=True)
sys.exit(0 if proof['ok']else 1)
