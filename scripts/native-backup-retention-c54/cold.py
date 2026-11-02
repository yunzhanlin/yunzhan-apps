"""Read-only post-hard-power-loss verification; no login, retry, installer or config writes."""
import ast,contextlib,copy,datetime,hashlib,json,math,os,pathlib,pwd,re,runpy,sqlite3,stat,subprocess,sys,time,traceback,urllib.request
os.umask(0o077);assert os.geteuid()==0 and len(sys.argv)==2
base=pathlib.Path(sys.argv[1]);assert re.fullmatch('/opt/panel-retention-c54-native-qa-[a-f0-9]{32}',str(base));intent=json.loads((base/'cold-intent.json').read_bytes());assert intent['base']==str(base)
payload=base/'verified-input';evidence=base/'evidence/cold';evidence.mkdir(mode=0o700)
def sha(f):return hashlib.sha256(pathlib.Path(f).read_bytes()).hexdigest()
assert sha(payload/'cold.py')==intent['cold_script_sha256']and sha('/etc/machine-id')==intent['machine_id_sha256']and subprocess.check_output(['findmnt','-n','-o','UUID','/'],text=True).strip()==intent['root_uuid']
boot=pathlib.Path('/proc/sys/kernel/random/boot_id').read_text().strip();assert boot!=intent['boot'];p={'boot':boot};own_site=None
def save(n,v):
 assert re.fullmatch('[A-Za-z0-9._-]+',n)
 with os.fdopen(os.open(evidence/n,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600),'w')as f:json.dump(v,f,sort_keys=True,indent=2);f.write('\n');f.flush();os.fsync(f.fileno())
nodes=[v for v in ast.parse((payload/'capture.py').read_bytes()).body if isinstance(v,ast.FunctionDef)and v.name in {'command','unit','snapshot'}];assert len(nodes)==3;exec(compile(ast.Module(body=nodes,type_ignores=[]),'<unchanged-original-113-observer>','exec'),globals())
proof={'ok':False,'base':str(base),'boot':boot,'previous_boot':intent['boot'],'source_inputs_sha256':intent['source_inputs_sha256'],'Main_changed':False,'all50_commercial':False,'mutations_submitted':0}
try:
 deadline=time.monotonic()+100;opener=urllib.request.build_opener(urllib.request.ProxyHandler({}))
 while True:
  try:
   with opener.open('http://127.0.0.1:19100/api/ready',timeout=2)as r:assert r.status==200
   break
  except Exception:assert time.monotonic()<deadline;time.sleep(1)
 assert json.loads(pathlib.Path('/opt/panel/current/SOURCE_INPUTS.json').read_bytes())['inputs_sha256']==intent['source_inputs_sha256']
 time.sleep(18);a=json.loads((base/'evidence/before-hard-powerloss-original113.json').read_bytes());z=snapshot();save('after-hard-powerloss-original113.json',z);assert a['schema']==z['schema']and a['boot']==intent['boot']and z['boot']==boot
 for key in('nss','packages','NFS_state','protected_files'):assert a[key]==z[key],key
 for name,v in a['lifetimes'].items():
  now=z['lifetimes'][name];assert now['MainPID']!='0'and now['ActiveState']=='active'and now['InvocationID']!=v['InvocationID']and now['exe_sha256']==v['exe_sha256']
 def records(v,n):return[dict(zip(v['tables'][n]['columns'],row))for row in v['tables'][n]['rows']]
 background={'database_connection_samples','monitor_conditions','monitor_samples','monitor_services','notification_dispatch_status'};changed=[]
 for n,v in a['tables'].items():
  assert v['columns']==z['tables'][n]['columns']
  if v!=z['tables'][n]:changed.append(n);assert n in background,'Non-background table changed after cold boot: '+n
 old={json.dumps(v,sort_keys=True)for v in records(a,'monitor_samples')};added=[v for v in records(z,'monitor_samples')if json.dumps(v,sort_keys=True)not in old];assert len(added)>=1 and all(v['boot_id']==boot and v['state']=='ok'and not v['error']for v in added)
 initial=[v for v in added if v['cpu_percent']is None];assert len(initial)<=1
 if initial:
  first=initial[0];assert first['id']==min(v['id']for v in added)and isinstance(first['cpu_total'],int)and isinstance(first['cpu_idle'],int)and 0<=first['cpu_idle']<=first['cpu_total'];save('explicit-original-first-CPU-sample.json',first)
 projected_before=copy.deepcopy(a);projected_before['boot']=boot;projected_after=copy.deepcopy(z)
 if initial:
  cols=projected_after['tables']['monitor_samples']['columns'];idx=cols.index('id');projected_after['tables']['monitor_samples']['rows']=[row for row in projected_after['tables']['monitor_samples']['rows']if row[idx]!=initial[0]['id']]
 qualify=runpy.run_path(str(payload/'preservation.py'))['qualify_background'];delta=qualify(projected_before,projected_after)
 cleanup=records(z,'site_schedule_cleanup_jobs');assert cleanup==json.loads((base/'evidence/cold-enabled-original-records.json').read_bytes())and len(cleanup)==3 and all(v['attempts']==1 for v in cleanup)
 schedules=records(z,'schedules');assert {v['id']for v in schedules}==set(intent['schedule_ids'])and all(v['enabled']==1 and v['retention_count']==2 and v['revision']==4 for v in schedules)
 nodes=[v for v in ast.parse((payload/'business.py').read_bytes()).body if isinstance(v,ast.FunctionDef)and v.name in {'entry','backup_inventory'}];assert len(nodes)==2;exec(compile(ast.Module(body=nodes,type_ignores=[]),'<original-backup-inventory>','exec'),globals());current=backup_inventory('after-hard-powerloss-backups');assert current==json.loads((base/'evidence/before-hard-powerloss-backups.json').read_bytes())
 proof.update(ok=True,actual_hard_powerloss_two_distinct_boots=True,same_machine_root_and_original_SSH_identity=True,original_cleanup_and_single_dispatch_audits_unchanged=True,eligible_owned_schedules_remain_enabled=True,no_automatic_replay_after_cold_boot=True,all113_original_tables_reconciled=True,typed_background_delta=delta,explicit_first_CPU_sample_count=len(initial),all_backup_bytes_owner_inode_modes_unchanged=True,original_accounts_packages_and_all_protected_files_preserved=True,actual_running_binary_digests_preserved=True)
except BaseException:save('original-failure.json',{'traceback':traceback.format_exc()})
save('proof.json',proof);print(json.dumps(proof),flush=True);sys.exit(0 if proof['ok']else 1)
