"""Actual signed-service archive API, independent inode and held-UID33-FD QA.

Only the new owned KVM sites/sinks created by acceptance.py are used. The
unknown journal case is explicitly a Root-controlled fault fixture, not a
claim of a naturally interrupted write. Every original phase file is kept.
"""
import base64,concurrent.futures,grp,hashlib,http.client,json,os,pathlib,pwd,re,secrets,stat,subprocess,sys

LIMIT=32<<20
ROOT=pathlib.Path('/var/lib/panel-apache-body')
SINK=ROOT/'cc-events.log'
EXECUTOR_GID=grp.getgrnam('panel').gr_gid
def verify_executor_identity():
 properties=dict(v.split('=',1)for v in subprocess.check_output(['systemctl','show','panel-executor.service','--property=User,Group,MainPID'],text=True).splitlines());assert properties['User']=='root'and properties['Group']=='panel'and int(properties['MainPID'])>1
 status=dict(v.split(':',1)for v in pathlib.Path('/proc',properties['MainPID'],'status').read_text().splitlines()if ':'in v);assert int(status['Uid'].split()[1])==0 and int(status['Gid'].split()[1])==EXECUTOR_GID
 return {'uid':0,'gid':EXECUTOR_GID,'service_group':'panel','private_file_mode':0o600,'private_directory_mode':0o700}


def digest(path):
 h=hashlib.sha256()
 with path.open('rb')as f:
  for b in iter(lambda:f.read(65536),b''):h.update(b)
 return h.hexdigest()

def identity(path,root=False):
 s=path.lstat();assert stat.S_ISREG(s.st_mode)and s.st_nlink==1 and stat.S_IMODE(s.st_mode)==0o600
 if root:assert s.st_uid==0 and s.st_gid==EXECUTOR_GID
 return {'uid':s.st_uid,'gid':s.st_gid,'mode':stat.S_IMODE(s.st_mode),'bytes':s.st_size,'dev':s.st_dev,'ino':s.st_ino,'links':s.st_nlink,'sha256':digest(path)}

def private_witness():
 verify_executor_identity();result={}
 for base in (ROOT/'cc-archives',ROOT/'cc-archive-history'):
  if not base.exists():continue
  st=base.lstat();assert stat.S_ISDIR(st.st_mode)and st.st_uid==0 and st.st_gid==EXECUTOR_GID and stat.S_IMODE(st.st_mode)==0o700
  children=list(base.iterdir());assert len(children)<=32
  for directory in children:
   assert re.fullmatch('[a-f0-9]{32}',directory.name)
   st=directory.lstat();assert stat.S_ISDIR(st.st_mode)and st.st_uid==0 and st.st_gid==EXECUTOR_GID and stat.S_IMODE(st.st_mode)==0o700
   files=list(directory.iterdir());assert len(files)<=21
   for p in files:
    value=identity(p,True);assert value['bytes']<=LIMIT+(1 if p.name=='next.log'else 0)
    result[str(p)]=value
 return result

def run(h,result):
 calls=0;receipts=[];extra=[]
 def api(label,path,body=None,expected=200,key=None):
  nonlocal calls
  calls+=1
  return h.api('cc57-archive-'+str(calls)+'-'+label,path,body,expected,key or(secrets.token_hex(16)if body is not None else None))
 cfg=api('original-config','/software/apache-waf/config');assert cfg['settings']==result['settings']and cfg['status']['healthy']and cfg['status']['version']=='2.5.1'
 inventory=api('original-inventory','/software/apache-waf/cc-log/archives');inherited=getattr(h,'inherited_archives',[]);assert inventory['archives']==inherited and inventory['history']==[]and inventory['inventory_complete']and inventory['maintenance_healthy'];executor_identity=verify_executor_identity();original_private_witness=private_witness()
 installed=pathlib.Path('/etc/panel/security-apps/modules/apache-waf/installed.json').read_bytes();apache=h.unit('panel-apache.service');assert identity(SINK)==result['CC_log']and result['CC_log']['bytes']==LIMIT
 account=pwd.getpwnam('www-data');assert account.pw_uid==account.pw_gid==33
 worker_code=r'''import json,os,sys
assert os.geteuid()==os.getegid()==33
fd=os.open('/var/lib/panel-apache-body/cc-events.log',os.O_RDWR|os.O_NOFOLLOW)
print('READY UID33',flush=True)
for line in sys.stdin:
 command=json.loads(line)
 if command['op']=='alter':
  os.ftruncate(fd,0);os.pwrite(fd,b'owned old descriptor changed source\n',0);os.fsync(fd)
 elif command['op']=='grow':
  os.ftruncate(fd,(32<<20)+1);os.fsync(fd)
 elif command['op']=='private-open':
  try:other=os.open(command['path'],os.O_RDWR|os.O_NOFOLLOW)
  except PermissionError:pass
  else:os.close(other);raise AssertionError('Root private copy was worker writable')
 else:raise AssertionError('unexpected owned control')
 print('DONE '+command['op'],flush=True)
os.close(fd)
'''
 def spawn():
  child=subprocess.Popen(['/usr/bin/python3','-I','-B','-c',worker_code],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,user=33,group=33,extra_groups=[])
  assert child.stdout.readline()=='READY UID33\n';return child
 def control(child,op,**kw):
  child.stdin.write(json.dumps({'op':op,**kw})+'\n');child.stdin.flush();assert child.stdout.readline()=='DONE '+op+'\n'
 def download(row,expected):
  file=row.get('completed',{}).get('archive')or row['retained']['archive'];assert file['bytes']==expected['bytes']and file['sha256']==expected['sha256'];total=0;whole=hashlib.sha256()
  for part in range((file['bytes']+262143)//262144):
   value=api('chunk-'+row['id']+'-'+str(part),'/software/apache-waf/cc-log/archives/'+row['id']+'/chunks/'+str(part));raw=base64.b64decode(value['data_base64'],validate=True)
   assert value['archive_id']==row['id']and value['part']==part and value['offset']==total and value['bytes']==len(raw)==min(262144,file['bytes']-total)and value['total_bytes']==file['bytes']and value['sha256']==file['sha256']and value['raw_original_private_log']and value['original_outcome_unknown']==(row['state']=='retained-unknown');whole.update(raw);total+=len(raw)
  assert total==file['bytes']and whole.hexdigest()==expected['sha256'];return {'parts':(total+262143)//262144,'bytes':total,'sha256':whole.hexdigest()}
 def fill_owned_current():
  before=identity(SINK);assert before['bytes']==0
  h.save('cc57-owned-new-current-capacity-fixture-'+str(len(receipts))+'-once.json',{'owned_new_inode':before,'maximum_submissions':1,'original_user_data_touched':False,'synthetic_capacity_fixture_not_traffic':True})
  with SINK.open('ab')as f:
   left=LIMIT
   while left:
    data=b'\n'+b' '*(min(left,65536)-1);f.write(data);left-=len(data)
   f.flush();os.fsync(f.fileno())
  assert identity(SINK)['bytes']==LIMIT
 for kind in ('completed','retained-unknown'):
  source=identity(SINK);assert source['bytes']==LIMIT
  child=spawn();request_id=secrets.token_hex(16)
  try:
   request={'request_id':request_id,'expected_revision':cfg['settings']['policy']['revision'],'allow_incomplete':True}
   row=api('one-'+kind,'/software/apache-waf/cc-log/archive',request,key=request_id);assert row['id']==request_id and row['state']=='completed'and row['intent']['format']==row['prepared']['format']==row['completed']['format']==2
   directory=ROOT/'cc-archives'/request_id;copy_path=directory/'data.log';copy=identity(copy_path,True);assert copy['sha256']==source['sha256']and copy['bytes']==source['bytes']and(copy['dev'],copy['ino'])!=(source['dev'],source['ino'])and row['completed']['archive']['inode']==str(copy['ino']);assert identity(directory/'next.log',True)['ino']==source['ino']
   fault=None
   if kind=='retained-unknown':
    original=directory/'completed.json';prior=identity(original,True);kept=h.evidence/('cc57-controlled-original-completed-'+request_id+'.json');h.save('cc57-controlled-journal-fixture-'+request_id+'.json',{'owned_only':True,'original_completed':prior,'preserved_at':str(kept),'genuine_interrupted_write_claim':False,'maximum_moves':1});os.rename(original,kept);assert identity(kept,True)==prior
    observation=api('unknown-before-retain','/software/apache-waf/cc-log/archives/'+request_id+'/recovery');assert observation['record']['state']=='unknown'and observation['automatic_replay_allowed']is False and observation['snapshot']['source_identity_only']is True
    row=api('one-explicit-retention','/software/apache-waf/cc-log/archives/'+request_id+'/retain',{'sha256':observation['snapshot_sha256'],'confirm_unknown':True});assert row['state']=='retained-unknown'and row['retained']['format']==2 and row['retained']['original_outcome_unknown']and row['retained']['current_log_untouched'];fault={'kind':'Root-controlled owned completion-file absence','original_completion_preserved':str(kept),'original_completion_sha256':prior['sha256'],'genuine_interrupted_write_claim':False}
   control(child,'private-open',path=str(copy_path));control(child,'alter');assert identity(copy_path,True)==copy and identity(SINK)['bytes']==0
   row=api('after-old-FD-modification','/software/apache-waf/cc-log/archives/'+request_id);assert row['state']==kind and row['source_status']==('changed-after-copy'if kind=='completed'else'not-authoritative')
   whole=download(row,source)
   if kind=='completed':
    observation=api('history-snapshot','/software/apache-waf/cc-log/archives/'+request_id+'/history');moved=api('one-history-transfer','/software/apache-waf/cc-log/archives/'+request_id+'/history',{'sha256':observation['snapshot_sha256'],'confirm_preserve':True});assert moved['history']and moved['current_log_untouched']and moved['no_delete'];directory=ROOT/'cc-archive-history'/request_id;copy_path=directory/'data.log';assert identity(copy_path,True)==copy
   control(child,'grow');assert identity(copy_path,True)==copy and identity(directory/'next.log',True)['bytes']==LIMIT+1
   row=api('after-original-overlimit','/software/apache-waf/cc-log/archives/'+request_id);assert row['state']==kind
   first=api('export-after-original-overlimit','/software/apache-waf/cc-log/archives/'+request_id+'/chunks/0');raw=base64.b64decode(first['data_base64'],validate=True)
   with copy_path.open('rb')as original_copy:first_original=original_copy.read(len(raw))
   assert first['archive_id']==request_id and first['part']==0 and first['offset']==0 and first['sha256']==copy['sha256']and raw==first_original and len(raw)==262144
   child.stdin.close();assert child.wait(timeout=10)==0,child.stderr.read()
   assert h.unit('panel-apache.service')==apache and pathlib.Path('/etc/panel/security-apps/modules/apache-waf/installed.json').read_bytes()==installed
   observed=api('original-readonly-receipt','/software/apache-waf/cc-log/requests/'+request_id);assert observed['kind']=='archive'and observed['read_only']and observed['record']['state']==kind
   receipts.append({'id':request_id,'state':kind,'source':source,'copy':copy,'download':whole,'old_UID33_raw_FD_altered_only_original_inode':True,'fresh_worker_open_of_copy_denied':True,'first_download_chunk_after_original_overlimit_verified':True,'history':kind=='completed','controlled_unknown_fixture':fault})
  finally:
   if child.poll()is None:child.kill();child.wait()
  # Restore only capacity of this newly-created, owned empty sink. No file is
  # truncated, removed or relabelled as actual events; originals stay copied.
  fill_owned_current()
 inventory=api('final-inventory','/software/apache-waf/cc-log/archives');assert inventory['inventory_complete']and inventory['maintenance_healthy']and len(inventory['archives'])==len(inherited)+1 and len(inventory['history'])==1
 result['CC_log']=identity(SINK);result['archive_private_witness']=private_witness();result['archive_receipts']=receipts
 for path,value in original_private_witness.items():assert result['archive_private_witness'][path]==value
 assert all(next(v for v in inventory['archives']if v['id']==original['id'])==original for original in inherited)
 h.save('cc57-real-service-private-copies-and-held-FD-proof.json',{'ok':True,'actual_signed_programme_service_API':True,'actual_unprivileged_UID33_descriptor_mutations':True,'executor_private_ownership':executor_identity,'inherited_original_receipts_preserved':inherited,'receipts':receipts,'current_log':result['CC_log'],'private_witness':result['archive_private_witness'],'Apache_lifetime_and_original_configuration_unchanged':True,'original_unknown_outcome_not_relabelled':True,'genuine_crash_retention_claim':False,'all50_commercial':False})
 h.proof.update(actual_service_independent_Root_copies=True,actual_service_UID33_held_descriptor_proof=True,actual_service_archive_history_and_full_SHA_download=True,actual_service_explicit_unknown_retention_controlled_fixture=True,actual_service_archive_automatic_replays=0)
 return result
