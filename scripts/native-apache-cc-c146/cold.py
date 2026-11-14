"""Read-only verification after an actual owned KVM hard power loss.

No login, installer, record repair, application configuration or job replay.
Four fresh owned-site requests follow reconciliation of all original state.
The fixed native HEAD probe is empty and does not reach PHP or charge quota.
"""
import ast,concurrent.futures,contextlib,copy,datetime,hashlib,http.client,json,math,os,pathlib,pwd,re,runpy,secrets,socket,sqlite3,stat,subprocess,sys,time,traceback,urllib.request
os.umask(0o077);assert os.geteuid()==0 and len(sys.argv)==2
base=pathlib.Path(sys.argv[1]);assert re.fullmatch('/opt/panel-apache-cc-c146-native-qa-[a-f0-9]{32}',str(base));intent=json.loads((base/'cold-intent.json').read_bytes());assert intent['base']==str(base)
payload=base/'verified-input';evidence=base/'evidence/cold';evidence.mkdir(mode=0o700)
def sha(f):return hashlib.sha256(pathlib.Path(f).read_bytes()).hexdigest()
def save(n,v):
 assert re.fullmatch('[A-Za-z0-9._-]+',n)
 with os.fdopen(os.open(evidence/n,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600),'w')as f:json.dump(v,f,sort_keys=True,indent=2);f.write('\n');f.flush();os.fsync(f.fileno())
assert sha(payload/'cold.py')==intent['cold_script_sha256']and sha('/etc/machine-id')==intent['machine_id_sha256']and subprocess.check_output(['findmnt','-n','-o','UUID','/'],text=True).strip()==intent['root_uuid']
boot=pathlib.Path('/proc/sys/kernel/random/boot_id').read_text().strip();assert boot!=intent['boot'];p={'boot':boot};own_site=None
nodes=[n for n in ast.parse((payload/'capture.py').read_bytes()).body if isinstance(n,ast.FunctionDef)and n.name in {'command','unit','snapshot'}];assert len(nodes)==3
exec(compile(ast.Module(body=nodes,type_ignores=[]),'<original-readonly-114-observer>','exec'),globals())
nodes=[n for n in ast.parse((payload/'boot-transition.py').read_bytes()).body if isinstance(n,ast.FunctionDef)and n.name=='qualify_monitor_boot_transition'];assert len(nodes)==1
exec(compile(ast.Module(body=nodes,type_ignores=[]),'<unchanged-original-typed-boot-transition>','exec'),globals())
class ExecutorConnection(http.client.HTTPConnection):
 def connect(self):
  self.sock=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM);self.sock.settimeout(self.timeout);self.sock.connect('/run/panel-executor/control.sock')
def read_executor(label,path):
 connection=ExecutorConnection('localhost',timeout=30)
 try:
  connection.request('GET',path);reply=connection.getresponse();raw=reply.read((8<<20)+1);assert reply.status==200 and len(raw)<=8<<20;value=json.loads(raw)
 finally:connection.close()
 save(label+'.json',value);return value
proof={'ok':False,'base':str(base),'previous_boot':intent['boot'],'boot':boot,'source_inputs_sha256':intent['source_inputs_sha256'],'Main_changed':False,'all50_commercial':False,'application_mutations_submitted':0}
try:
 opener=urllib.request.build_opener(urllib.request.ProxyHandler({}));deadline=time.monotonic()+100
 while True:
  try:
   with opener.open('http://127.0.0.1:19100/api/ready',timeout=2)as response:assert response.status==200
   break
  except Exception:assert time.monotonic()<deadline;time.sleep(1)
 assert json.loads(pathlib.Path('/opt/panel/current/SOURCE_INPUTS.json').read_bytes())['inputs_sha256']==intent['source_inputs_sha256']
 result=intent['owned_result'];witness=runpy.run_path(str(payload/'archive_acceptance.py'))['private_witness'];assert witness()==result['archive_private_witness'];save('original-Root-private-copy-tree-preserved.json',result['archive_private_witness']);config=read_executor('actual-cold-native-config','/v1/software/apache-waf/config');assert config['settings']==result['settings']and config['status']['healthy']and config['status']['version']=='2.5.1'
 sink=pathlib.Path('/var/lib/panel-apache-body/cc-events.log');s=sink.lstat();actual={'uid':s.st_uid,'gid':s.st_gid,'mode':stat.S_IMODE(s.st_mode),'bytes':s.st_size,'dev':s.st_dev,'ino':s.st_ino,'links':s.st_nlink,'sha256':sha(sink)};assert actual==intent['CC_log'];save('original-full-owned-CC-sink-preserved.json',actual)
 reports=read_executor('actual-cold-bounded-event-report','/v1/software/apache-waf/report');assert reports['cc_log_capacity_near_limit']and reports['partial']and reports['metadata_best_effort']
 for name,value in intent['native_engine_receipts'].items():
  f=pathlib.Path('/var/lib/panel-executor/apache-body-builds')/name;assert re.fullmatch('[a-f0-9]{32}.json',name)and f.read_bytes().hex()==value['original_hex']and sha(f)==value['sha256']
 for site in result['sites']:
  f=pathlib.Path(site['counter']);rows=f.read_text().splitlines();assert len(rows)==len(set(rows))and set(rows)==set(site['reached'])
  connection=http.client.HTTPConnection('127.0.0.1',19080,timeout=10)
  try:
   connection.request('HEAD','/__yunzhan_waf_probe',headers={'Host':site['domain']});response=connection.getresponse();raw=response.read(1);headers={k.lower():v for k,v in response.getheaders()};assert response.status==204 and raw==b''and headers['x-panel-apache-cc-probe']=='1.1.0'and headers['x-panel-apache-cc'].startswith('1.1.0:')and headers['x-panel-apache-waf'].startswith('2.5.1:')
  finally:connection.close()
  assert f.read_text().splitlines()==rows
 assert sha(sink)==intent['CC_log']['sha256']
 guard=subprocess.run(['/opt/panel/current/bin/panel-executor','--check-program-upgrade-queues'],capture_output=True,timeout=35);save('actual-cold-complete-guard.json',{'exit':guard.returncode,'stdout_hex':guard.stdout.hex(),'stderr_hex':guard.stderr.hex()});assert guard.returncode==0 and guard.stdout==guard.stderr==b''
 time.sleep(18);before=json.loads((base/'evidence/before-hard-powerloss-original114.json').read_bytes());after=json.loads(json.dumps(snapshot()));save('after-hard-powerloss-original114.json',after)
 for key in ('schema','nss','packages','NFS_state','protected_files'):assert before[key]==after[key],key
 for name,v in before['lifetimes'].items():
  now=after['lifetimes'][name];assert now['MainPID']!='0'and now['ActiveState']=='active'and now['InvocationID']!=v['InvocationID']and now['exe_sha256']==v['exe_sha256']
 qualify=runpy.run_path(str(payload/'preservation.py'))['qualify_background'];transition=qualify_monitor_boot_transition(before,after,qualify);save('original-full114-boot-transition-qualified.json',transition)
 # Original-state reconciliation above precedes these four new, explicitly
 # owned application requests. No old request/configuration/job is replayed.
 site=result['sites'][0];counter=pathlib.Path(site['counter']);original=counter.read_text().splitlines();body=b'{"owned_cold_probe":true}'
 save('four-new-owned-cold-requests-once-intent.json',{'maximum_HTTP_submissions':4,'automatic_retries':0,'site_id':site['id'],'path':'/cc56/quota','fresh_effective_client':'198.51.100.250','existing_configuration_unchanged':True})
 def request():
  identity=secrets.token_hex(16);connection=http.client.HTTPConnection('127.0.0.1',19080,timeout=10)
  try:
   connection.request('POST','/cc56/quota',body=body,headers={'Host':site['domain'],'X-Forwarded-For':'198.51.100.250','X-Yunzhan-QA-Request':identity,'Content-Type':'application/json'});response=connection.getresponse();raw=response.read(8193);headers={k.lower():v for k,v in response.getheaders()};assert len(raw)<=8192
   if response.status==200:
    value=json.loads(raw);assert headers['x-yunzhan-qa-reached']==identity and value['marker']==site['marker']and value['php']=='8.2.35'and value['original_path']=='/cc56/quota'and value['raw_sha256']==hashlib.sha256(body).hexdigest()
   else:assert response.status==429 and 'x-yunzhan-qa-reached'not in headers
   return {'request_id':identity,'status':response.status,'response_hex':raw.hex(),'headers':headers}
  finally:connection.close()
 started=time.monotonic()
 with concurrent.futures.ThreadPoolExecutor(max_workers=4)as pool:responses=[future.result()for future in[pool.submit(request)for _ in range(4)]]
 elapsed=time.monotonic()-started;assert elapsed<0.9 and sorted(v['status']for v in responses)==[200,200,200,429]
 admitted={v['request_id']for v in responses if v['status']==200};rows=counter.read_text().splitlines();assert len(rows)==len(set(rows))==len(original)+3 and rows[:len(original)]==original and set(rows[len(original):])==admitted
 assert sha(sink)==intent['CC_log']['sha256']and witness()==result['archive_private_witness'];save('actual-four-new-cold-HTTP-responses.json',{'requests':responses,'seconds':elapsed,'original_counter_prefix_unchanged':True,'only_three_new_owned_PHP_counter_rows':sorted(admitted),'original_full_log_unchanged':True})
 proof.update(ok=True,actual_hard_powerloss_two_distinct_boots=True,independent_Root_archive_bytes_and_original_phase_inodes_survived=True,same_original_machine_root_disk_and_SSH_identity=True,all114_tables_qualified=True,original_accounts_packages_files_and_engine_receipts_unchanged_before_new_owned_requests=True,original_full_CC_sink_inode_bytes_permissions_unchanged=True,full_log_enforcement_survived=True,actual_new_cold_HTTP_requests=4,actual_new_cold_PHP_admissions=3,actual_new_cold_blocked_before_PHP=1,full_log_warning_and_bounded_reader_survived=True,actual_empty_native_CC_probe_after_cold_boot=True,actual_original_PHP_counter_prefix_preserved=True,no_native_job_replay=True,typed_boot_transition=transition)
except BaseException:save('original-failure.json',{'traceback':traceback.format_exc()})
save('proof.json',proof);print(json.dumps(proof),flush=True);sys.exit(0 if proof['ok']else 1)
