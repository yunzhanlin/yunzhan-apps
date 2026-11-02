"""The five original installation observers; entry count bound to exactly two signed cohorts."""
def guard(label):
 for i in range(9):
  r=subprocess.run(['/opt/panel/current/bin/panel-executor','--check-program-upgrade-queues'],capture_output=True,timeout=35);u=unit('panel-mysql-overwrite-recovery.service');save(label+'-guard-'+str(i)+'.json',{'exit':r.returncode,'stdout_hex':r.stdout.hex(),'stderr_hex':r.stderr.hex(),'recovery_unit':u})
  if r.returncode==0:assert r.stdout==r.stderr==b'';return
  assert i<8 and r.stdout==b''and b'panel-mysql-overwrite-recovery.service'in r.stderr and u['ActiveState']=='activating'and u['SubState']=='condition'and u['MainPID']=='0';time.sleep(1)

def wait_initial_cpu_observation():
 deadline=time.monotonic()+90;observations=[]
 while True:
  with contextlib.closing(sqlite3.connect('file:/var/lib/panel/panel.db?mode=ro',uri=True,timeout=3))as db:
   db.execute('PRAGMA query_only=ON');db.execute('BEGIN');conditions=db.execute('SELECT metric,active_since,clear_since,last_value FROM monitor_conditions ORDER BY metric').fetchall();samples=db.execute('SELECT sampled_at,state,error,boot_id,cpu_total,cpu_idle,cpu_percent FROM monitor_samples ORDER BY id DESC LIMIT 2').fetchall()
  metrics={x[0]for x in conditions};observations.append({'at':time.time(),'conditions':conditions,'latest_samples':samples})
  assert metrics<= {'collector','cpu','disk','memory','service:nginx:nginx'}
  if metrics=={'collector','cpu','disk','memory','service:nginx:nginx'}and len(samples)==2 and all(x[1]=='ok'and x[2]==''and x[3]==boot for x in samples)and samples[0][6]is not None:
   cpu=next(x for x in conditions if x[0]=='cpu');assert 0<=cpu[3]<=100
   if cpu[1]==cpu[2]==0 and cpu[3]<80 and cpu[3]==samples[0][6]:
    save('initial-CPU-monitor-readonly-warmup.json',{'ok':True,'no_configuration_or_job_mutations':True,'all_original_observations':observations,'first_valid_CPU_sample_completed_before_upgrade_baseline':True});proof['initial_CPU_monitor_settled_before_baseline']=True;return
  assert time.monotonic()<deadline,'Fresh initial CPU sample unresolved; no installer attempted';time.sleep(1)

def run_once(label,args,timeout):
 save(label+'-once-intent.json',{'args':args,'maximum_submissions':1,'unknown_observe_only':True})
 with(evidence/(label+'.stdout.log')).open('xb')as out,(evidence/(label+'.stderr.log')).open('xb')as err:r=subprocess.run(args,stdin=subprocess.DEVNULL,stdout=out,stderr=err,timeout=timeout)
 save(label+'-original-outcome.json',{'exit':r.returncode,'stdout_sha256':sha(evidence/(label+'.stdout.log')),'stderr_sha256':sha(evidence/(label+'.stderr.log'))});assert r.returncode==0,'Original operation failed; no replay: '+label

def installed_archive(label,version,source):
 count={(OLD_VERSION,OLD):203,(VERSION,NEW):204}[(version,source)]
 archive=payload/('panel-'+version+'-linux-amd64.tar.gz');assert sha(archive)==pins['files'][archive.name];root=pathlib.Path('/opt/panel/current').resolve(strict=True);assert str(root)=='/opt/panel/releases/'+version;entries=[];prefix='panel-'+version+'-linux-amd64'
 with tarfile.open(archive,'r:gz')as tar:
  for member in tar:
   assert member.name==prefix or member.name.startswith(prefix+'/');relative=member.name[len(prefix):].lstrip('/');f=root/relative;s=f.lstat();assert s.st_uid==0 and stat.S_IMODE(s.st_mode)==member.mode;record={'path':relative,'mode':member.mode,'uid':s.st_uid,'gid':s.st_gid,'inode':s.st_ino}
   if member.isfile():assert stat.S_ISREG(s.st_mode)and s.st_nlink==1;record.update(type='file',bytes=s.st_size,sha256=sha(f));assert hashlib.sha256(tar.extractfile(member).read()).hexdigest()==record['sha256']
   else:assert member.isdir()and stat.S_ISDIR(s.st_mode);record['type']='directory'
   entries.append(record)
 assert len(entries)==count and {''}|{str(f.relative_to(root))for f in root.rglob('*')}=={r['path']for r in entries}
 assert json.loads((root/'SOURCE_INPUTS.json').read_bytes())['inputs_sha256']==source
 save(label+'-entire-normal-installed-tree.json',{'ok':True,'source_inputs_sha256':source,'archive_sha256':sha(archive),'entries':entries,'count':count})
 return {r['path'][4:]:r['sha256']for r in entries if r['path'].startswith('bin/')and r['type']=='file'}

def preserving_programme_compare(before,after,target_programmes=None):
 for key in('nss','packages','NFS_state','schema','boot'):assert before[key]==after[key],key
 def protected(s):return{n:v for n,v in s['protected_files'].items()if not any(n==path or n.startswith(path+'/')for path in('/opt/panel/current/bin','/opt/panel/current/web'))}
 assert protected(before)==protected(after);reference=copy.deepcopy(before)
 if target_programmes:
  for unit_name,binary in(('panel.service','panel'),('panel-executor.service','panel-executor')):
   assert before['lifetimes'][unit_name]!=after['lifetimes'][unit_name]and after['lifetimes'][unit_name]['exe_sha256']==target_programmes[binary];reference['lifetimes'][unit_name]=copy.deepcopy(after['lifetimes'][unit_name])
 else:assert before['protected_files']==after['protected_files']
 assert reference['lifetimes']==after['lifetimes'];delta=qualify(reference,after)
 return {'ok':True,'all113_tables_qualified':True,'old_protected_nonprogramme_entries_identical':len(protected(before)),'NSS_packages_NFS_and_other_service_lifetimes_identical':True,'only_two_expected_programme_lifetimes_changed':bool(target_programmes),'typed_background_delta':delta}
