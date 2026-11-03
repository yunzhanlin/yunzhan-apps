"""Owned-site HTTP acceptance against the installed, original signed programme.

There are no programme, catalogue, module or compiler substitutions here. A
lost original HTTP response is evidence of uncertainty and is never retried.
"""
import concurrent.futures,copy,hashlib,http.client,json,math,os,pathlib,pwd,re,runpy,secrets,signal,stat,subprocess,time

class Acceptance:
 def __init__(self,h,engine,legacy_body=None):
  assert os.geteuid()==0 and json.loads(pathlib.Path('/opt/panel/current/SOURCE_INPUTS.json').read_bytes())['inputs_sha256']=='1d04d55fd7f94ab192517b1467f4760686c57ebe5365515d8b4d4bc8d6ffe66d'
  self.h=h;self.engine=engine;self.legacy_body=legacy_body;self.sites=[];self.requests=[];self.groups=[];self.operations=0
  self.nonce=secrets.token_hex(16);self.private_marker='cc56-private-'+self.nonce
  self.body=json.dumps({'ordinary':'owned acceptance','private_note':self.private_marker},separators=(',',':')).encode()
  self.book=runpy.run_path(str(h.payload/'casebook.py'));self.base=self.api('original-config','/software/apache-waf/config')
  assert self.base['status']['healthy']and self.base['status']['version']=='2.5.0'
  self.last=copy.deepcopy(self.base['settings']);self.baseline=copy.deepcopy(self.last)
  detail=self.api('original-ready-engine','/software/apache-waf/body-engine/jobs/'+engine)
  assert detail['job_id']==engine and detail['state']=='ready'and detail['native_cc_version']=='1.0.0'and detail['module_abi_validated']and detail['integrity_verified']and detail['elf_hardening_validated']and detail['compiler_groups_collected']
  self.original_installed=json.loads(pathlib.Path('/etc/panel/security-apps/modules/apache-waf/installed.json').read_bytes())
  self.initial_CC_exists=os.path.lexists('/var/lib/panel-apache-body/cc-events.log')
  assert not self.initial_CC_exists,'CC failure fixtures require this acceptance to own the newly created sink'
 def api(self,label,path,body=None,expected=200):
  self.operations+=1
  return self.h.api('cc56-'+str(self.operations)+'-'+label,path,body,expected,secrets.token_hex(16)if body is not None else None)
 def save(self,name,value):self.h.save('cc56-'+name+'.json',value)
 def digest(self,p):return hashlib.sha256(pathlib.Path(p).read_bytes()).hexdigest()
 def blob(self,name,raw):
  assert re.fullmatch('[a-z0-9-]+',name)and len(raw)<=32<<20
  file=self.h.evidence/('cc56-'+name+'.bin')
  with os.fdopen(os.open(file,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600),'wb')as f:f.write(raw);f.flush();os.fsync(f.fileno())
  return {'file':file.name,'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest()}
 def configure(self,label,edit):
  current=self.api(label+'-current','/software/apache-waf/config');assert current['settings']==self.last,'Configuration changed outside this owned acceptance; no overwrite'
  settings=copy.deepcopy(self.last);edit(settings)
  preview=self.api(label+'-preview','/software/apache-waf/preview',{'settings':settings});assert preview['read_only']and preview['implementation_version']=='2.5.0'
  reply=self.api(label+'-configure','/software/apache-waf/configure',{'settings':settings},202)
  self.h.wait_job('cc56-'+label,reply['job_id'],'runtime_jobs')
  result=self.api(label+'-actual','/software/apache-waf/config');settings['policy']['revision']+=1
  assert result['settings']==settings and result['status']['healthy']and result['status']['version']=='2.5.0'
  installed=json.loads(pathlib.Path('/etc/panel/security-apps/modules/apache-waf/installed.json').read_bytes())
  assert installed['installed_at']==self.original_installed['installed_at']
  for k,v in self.original_installed.items():
   if k not in('version','settings','updated_at','manifest_sha256','manifest_version','manifest_features'):assert installed.get(k)==v,('opaque installation field changed',k)
  self.last=copy.deepcopy(settings);return result
 def site_policy(self,settings,mode='block',enabled=True):
  ids={s['id']for s in self.sites};settings['policy']['sites']=[v for v in settings['policy']['sites']if v['site_id']not in ids]
  settings['policy']['sites'] += [{'site_id':s['id'],'mode':mode,'rate_per_second':200,'burst':1000,'cc_enabled':enabled}for s in self.sites]
  settings['apache_cc']={'engine_job_id':self.engine}
 def rule(self,settings,burst=2):
  ids={v['id']for v in self.rules};settings['policy']['cc_rules']=[v for v in settings['policy']['cc_rules']if v['id']not in ids]
  rules=copy.deepcopy(self.rules);rules[0]['burst']=burst;settings['policy']['cc_rules']+=rules
 def create_sites(self):
  for index in range(2):
   nonce=secrets.token_hex(16);domain='qa-cc56-'+nonce[:12]+'.example.test';probe='qa-apache24-body-'+nonce[:12]+'.php'
   reply=self.api('site'+str(index)+'-create','/sites',{'name':'Owned native CC acceptance '+str(index),'slug':'qa-cc56-'+nonce[:12],'domain':domain,'php_version_id':'php-8.2.35'},202)
   row=self.h.wait_job('cc56-site'+str(index)+'-create',reply['job_id'],'jobs');identity=row['site_id'];assert re.fullmatch('[a-f0-9]{32}',identity)
   site=self.api('site'+str(index)+'-settings','/sites/'+identity+'/settings');assert site['status']=='running'and site['settings']['web_server']=='nginx'
   settings=copy.deepcopy(site['settings']);settings['web_server']='apache';settings['rewrite']='custom';settings['rules']=[{'pattern':'^/(?:cc56/.*|__yunzhan_waf_probe)$','replacement':'/'+probe,'flag':'last'}]
   preview=self.api('site'+str(index)+'-preview','/sites/'+identity+'/settings/preview',{'settings':settings,'expected_revision':site['settings_revision']})
   assert preview['revision']==site['settings_revision']and hashlib.sha256(preview['current'].encode()).hexdigest()==preview['config_sha']
   reply=self.api('site'+str(index)+'-save','/sites/'+identity+'/settings',{'settings':settings,'expected_revision':site['settings_revision'],'expected_config_sha':preview['config_sha']},202)
   self.h.wait_job('cc56-site'+str(index)+'-save',reply['job_id'],'jobs')
   account=pwd.getpwnam('ps'+identity[:24]);assert account.pw_uid>0 and account.pw_gid>0
   root=pathlib.Path('/srv/panel/sites')/identity;counter=root/'private'/('qa-apache24-counter-'+nonce)
   with os.fdopen(os.open(counter,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600),'wb')as f:os.fchown(f.fileno(),account.pw_uid,account.pw_gid);f.flush();os.fsync(f.fileno())
   marker='apache24-php-'+nonce;body_marker='apache24-body-'+nonce
   source=self.book['php_fixture'](marker,str(counter));assert source.count('!fflush($f)')==1;source=source.replace('!fflush($f)','!fflush($f)||!fsync($f)')
   assert source.count("'pid'=>getmypid()") == 1
   source=source.replace("'pid'=>getmypid()","'original_path'=>explode('?',$_SERVER['REQUEST_URI']??'',2)[0],'pid'=>getmypid()")
   file=root/'public'/probe
   with os.fdopen(os.open(file,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o640),'w')as f:os.fchown(f.fileno(),account.pw_uid,pwd.getpwnam('www-data').pw_gid);f.write(source);f.flush();os.fsync(f.fileno())
   conf=pathlib.Path('/etc/panel/sites-enabled')/(identity+'.conf');assert re.search(r'^\s*listen 127\.0\.0\.1:19101;',conf.read_text(),re.M)
   self.sites.append({'id':identity,'domain':domain,'probe':probe,'counter':str(counter),'UID':account.pw_uid,'GID':account.pw_gid,'marker':marker,'body_marker':body_marker,'reached':set()})
  assert self.api('after-sites-config','/software/apache-waf/config')['settings']==self.last
  self.rules=[{'id':secrets.token_hex(16),'site_id':self.sites[0]['id'],'path':path,'prefix':prefix,'rate_per_second':1,'burst':burst,'enabled':True}for path,prefix,burst in[('/cc56/quota',False,2),('/cc56/prefix/',True,2),('/__yunzhan_waf_probe',False,1)]]
  self.save('owned-sites',[{k:v for k,v in s.items()if k!='reached'}for s in self.sites])
 def counters(self):
  result={}
  for site in self.sites:
   file=pathlib.Path(site['counter']);info=file.lstat();assert stat.S_ISREG(info.st_mode)and info.st_nlink==1 and stat.S_IMODE(info.st_mode)==0o600 and info.st_uid==site['UID']and info.st_gid==site['GID']and info.st_size<262144
   rows=file.read_text().splitlines();assert len(rows)==len(set(rows))and set(rows)==site['reached'];result[site['id']]=rows
  return result
 def request(self,site,path,body=None,method='POST',port=19080,xff=None,source='127.0.0.1',ctype='application/json',encoding='',case=None):
  identity=secrets.token_hex(16);raw=self.body if body is None else body
  headers={'Host':site['domain'],'User-Agent':'Mozilla/5.0 '+self.private_marker,'X-Yunzhan-QA-Request':identity,'Cookie':'owned_cookie='+self.private_marker,'Authorization':'Bearer '+self.private_marker}
  if ctype:headers['Content-Type']=ctype
  if xff is not None:headers['X-Forwarded-For']=xff
  if encoding:headers['Content-Encoding']=encoding
  before=time.monotonic();connection=http.client.HTTPConnection('127.0.0.1',port,timeout=15,source_address=(source,0))
  try:
   connection.request(method,path,body=None if method in('GET','HEAD')else raw,headers=headers);response=connection.getresponse();data=response.read(8193);status=response.status;reply_headers=dict(response.getheaders())
  finally:connection.close()
  assert len(data)<=8192
  lower={k.lower():v for k,v in reply_headers.items()};reached=lower.get('x-yunzhan-qa-reached','');result={'request_id':identity,'site_id':site['id'],'port':port,'source':source,'xff':xff,'path':path,'method':method,'body_bytes':len(raw),'body_sha256':hashlib.sha256(raw).hexdigest(),'status':status,'headers':reply_headers,'response_hex':data.hex(),'seconds':time.monotonic()-before,'PHP_reached':reached}
  self.requests.append(result)
  if status==200:
   assert reached==identity
   if method!='HEAD':
    answer=json.loads(data);assert answer['marker']==site['marker']and answer['php']=='8.2.35'and answer['original_path']==path.split('?',1)[0]
    process=pathlib.Path('/proc')/str(answer['pid']);state=dict(v.split(':',1)for v in(process/'status').read_text().splitlines()if':'in v)
    assert int(state['Uid'].split()[1])==site['UID']and int(state['Gid'].split()[1])==site['GID']and state['NoNewPrivs'].strip()=='1'and all(int(state[k],16)==0 for k in('CapPrm','CapEff','CapAmb'))
    if case and case['expected_upload_sha256']is not None:assert answer['files']['upload']=={'error':0,'bytes':len(b'ordinary owned upload content\n'),'sha256':case['expected_upload_sha256']}and answer['raw_bytes']==0
    else:assert answer['raw_bytes']==(0 if method=='GET'else len(raw))and answer['raw_sha256']==hashlib.sha256(b''if method=='GET'else raw).hexdigest()
    if case and case['expected_term_sha256']is not None:assert answer['term_sha256']==case['expected_term_sha256']
   site['reached'].add(identity)
  else:assert not reached
  return result
 def burst(self,label,site,path='/cc56/quota',amount=5,xff=None,source='127.0.0.1',allowed=None,port=19080,vary_spoof=False):
  self.save(label+'-once-intent',{'maximum_HTTP_submissions':amount,'automatic_retries':0,'site_id':site['id'],'path':path,'source':source,'xff':xff,'port':port})
  start=time.monotonic()
  with concurrent.futures.ThreadPoolExecutor(max_workers=min(16,amount))as pool:
   futures=[pool.submit(self.request,site,path+'?private_query='+self.private_marker,xff=('203.0.113.'+str(i+1)if vary_spoof else xff),source=source,port=port)for i in range(amount)]
   replies=[f.result()for f in futures]
  duration=time.monotonic()-start;statuses=[v['status']for v in replies];assert set(statuses)<={200,429},(label,statuses)
  group={'label':label,'actual_HTTP_requests':amount,'seconds':duration,'statuses':statuses,'request_ids':[v['request_id']for v in replies]};self.groups.append(group);self.save(label+'-original',group);self.counters()
  if allowed is not None:assert duration<0.9 and statuses.count(200)==allowed and statuses.count(429)==amount-allowed,(label,duration,statuses)
  return replies,duration
 def body_cases(self):
  site=self.sites[0];cfg=self.last.get('body');body_engine=cfg['engine_job_id']if cfg else self.legacy_body or self.engine
  cases=self.book['request_cases'](site['body_marker']);assert len(cases)==28
  for mode in('block','observe','off'):
   def edit(s):
    if not s.get('body'):s['body']={'engine_job_id':body_engine,'sites':[]}
    s['body']['sites']=[v for v in s['body']['sites']if v['site_id']!=site['id']]+[{'site_id':site['id'],'policy':{'mode':mode,'paranoia_level':1,'inbound_threshold':5,'body_limit_kib':128,'non_file_limit_kib':64,'json_depth':64,'argument_limit':256}}]
   self.configure('body-'+mode,edit)
   for port in(19080,19101):
    for case in cases:
     raw=bytes.fromhex(case['body_hex']);assert len(raw)==case['body_bytes']and hashlib.sha256(raw).hexdigest()==case['body_sha256']
     result=self.request(site,'/cc56/body',raw,case['method'],port,ctype=case['content_type'],encoding=case['encoding'],case=case)
     assert result['status']==(case['block_status']if mode=='block'else 200),(mode,case['name'],port,result['status'])
   self.counters()
  def restore(s):s['body']['sites']=[v for v in s['body']['sites']if v['site_id']!=site['id']]
  self.configure('body-owned-site-disable',restore)
  self.save('actual-body-coexistence',{'HTTP_requests':168,'PHP_reached':136,'blocked_never_reached':32,'body_engine':body_engine,'CC_engine':self.engine,'different_legacy_body_engine':body_engine!=self.engine,'all_original_response_bytes_retained':True})
 def workers(self):
  state=self.h.unit('panel-apache.service');master=int(state['MainPID']);assert state['ActiveState']=='active'and master>1
  executable=self.digest(pathlib.Path('/proc')/str(master)/'exe');children=[]
  for path in pathlib.Path('/proc').iterdir():
   if not path.name.isdecimal():continue
   try:
    fields=dict(v.split(':',1)for v in(path/'status').read_text().splitlines()if':'in v)
    if int(fields['PPid'].strip())==master and int(fields['Uid'].split()[1])==pwd.getpwnam('www-data').pw_uid and self.digest(path/'exe')==executable:
     maps=(path/'maps').read_text();assert '/'+self.engine+'/apache/mod_yunzhan_cc.so'in maps and '/'+self.last['body']['engine_job_id']+'/apache/mod_security2.so'in maps
     children.append({'pid':int(path.name),'start_ticks':(path/'stat').read_text().rsplit(')',1)[1].split()[19],'exe_sha256':executable,'native_CC_mapped':True})
   except FileNotFoundError:continue
  assert children,'Installed Apache has no independently observed CC worker mapping';return state,children
 def quota_recovery(self):
  a=self.sites[0]
  self.configure('shared-budget64',lambda s:(self.site_policy(s),self.rule(s,64)))
  started=time.monotonic();first,_=self.burst('shared-real-worker-admission',a,amount=128,xff='198.51.100.90');accepted=sum(v['status']==200 for v in first)
  assert 64<=accepted<=64+math.ceil(time.monotonic()-started)
  before,workers=self.workers();self.save('native-actual-worker-mappings',{'master':before,'workers':workers})
  site=self.api('active-site-current','/sites/'+a['id']+'/settings');settings=copy.deepcopy(site['settings']);settings['index_files']=[a['probe'],'index.html']
  pv=self.api('active-site-readonly-preview','/sites/'+a['id']+'/settings/preview',{'settings':settings,'expected_revision':site['settings_revision']})
  reply=self.api('active-site-once-save','/sites/'+a['id']+'/settings',{'settings':settings,'expected_revision':site['settings_revision'],'expected_config_sha':pv['config_sha']},202);self.h.wait_job('cc56-active-site-save',reply['job_id'],'jobs')
  assert self.api('after-active-site-WAF','/software/apache-waf/config')['settings']==self.last
  after,_=self.burst('after-normal-site-graceful-preserves-quota',a,amount=32,xff='198.51.100.90');accepted+=sum(v['status']==200 for v in after)
  assert time.monotonic()-started<16 and accepted<=64+math.ceil(time.monotonic()-started)and any(v['status']==429 for v in after)
  _,workers=self.workers();victim=workers[0];process=pathlib.Path('/proc')/str(victim['pid']);fd=os.pidfd_open(victim['pid'],0)
  try:
   assert (process/'stat').read_text().rsplit(')',1)[1].split()[19]==victim['start_ticks']and self.digest(process/'exe')==victim['exe_sha256']
   self.save('one-owned-worker-SIGKILL-intent',{'victim':victim,'parent':before['MainPID'],'maximum_submissions':1,'pidfd_bound':True});signal.pidfd_send_signal(fd,signal.SIGKILL,None,0)
  finally:os.close(fd)
  tail,_=self.burst('after-owned-worker-SIGKILL-preserves-quota',a,amount=32,xff='198.51.100.90');accepted+=sum(v['status']==200 for v in tail)
  now=self.h.unit('panel-apache.service');assert now['MainPID']==before['MainPID']and now['InvocationID']==before['InvocationID']and now['ActiveState']=='active'
  duration=time.monotonic()-started;assert duration<16 and accepted<=64+math.ceil(duration)and any(v['status']==429 for v in tail)
  self.save('real-worker-and-normal-site-reload-quota-preservation',{'ok':True,'HTTP_requests':192,'admissions':accepted,'original_burst':64,'rate_per_second':1,'elapsed_seconds':duration,'maximum_admissions_from_actual_time':64+math.ceil(duration),'same_original_Apache_master':True,'normal_site_transaction_completed':True,'actual_owned_worker_SIGKILL':victim})
 def log_identity(self):
  file=pathlib.Path('/var/lib/panel-apache-body/cc-events.log');s=file.lstat();www=pwd.getpwnam('www-data');assert stat.S_ISREG(s.st_mode)and s.st_nlink==1 and s.st_uid==www.pw_uid and s.st_gid==www.pw_gid and s.st_size<=32<<20
  return {'uid':s.st_uid,'gid':s.st_gid,'mode':stat.S_IMODE(s.st_mode),'bytes':s.st_size,'dev':s.st_dev,'ino':s.st_ino,'links':s.st_nlink,'sha256':self.digest(file)}
 def log_cases(self):
  file=pathlib.Path('/var/lib/panel-apache-body/cc-events.log');before=self.log_identity();assert before['mode']==0o600 and before['bytes']>0
  raw=file.read_bytes();lines=[json.loads(v)for v in raw.splitlines()];required={'epoch','epoch_us','status','site_id','site','ip','peer','method','path','path_truncated','reason','action'}
  assert lines and all(set(v)==required and v['reason']in('cc','cc-capacity','cc-unavailable')and v['site_id']in{s['id']for s in self.sites}and '?'not in v['path']for v in lines)
  assert self.private_marker.encode()not in raw and all(s['body_marker'].encode()not in raw for s in self.sites)
  assert any(v['ip']=='127.0.0.1'and v['peer']=='127.0.0.1'for v in lines)and any(v['ip']=='127.0.0.2'and v['peer']=='127.0.0.2'for v in lines)and any(v['ip']=='198.51.100.10'and v['peer']=='127.0.0.1'for v in lines)
  assert any(v['action']=='observe'and v['status']==200 for v in lines)
  self.save('actual-CC-private-log',{'identity':before,'events':lines,'raw':self.blob('original-real-CC-events',raw),'no_body_query_auth_cookie_or_UA_marker':True})
  report=self.api('actual-event-report','/software/apache-waf/report');assert report['metadata_best_effort']and report['events']
  # This sink was absent at entry and belongs solely to these newly owned test
  # sites. Deliberate fixtures never chmod or repair a pre-existing user file.
  self.save('owned-CC-mode0640-fixture-intent',{'created_by_this_acceptance':True,'before':before,'maximum_submissions':1});os.chmod(file,0o640)
  bad=self.log_identity();assert bad['mode']==0o640 and bad['sha256']==before['sha256']
  self.api('bad-mode-report','/software/apache-waf/report',expected=503)
  self.burst('bad-mode-enforcement-continues',self.sites[0],amount=5,xff='198.51.100.60',allowed=2)
  assert self.log_identity()==bad,'Product silently changed the deliberately invalid owned sink'
  self.save('owned-mode-fixture-explicit-restore-intent',{'original_mode':0o600,'maximum_submissions':1,'product_repairs':0});os.chmod(file,0o600);assert self.log_identity()==before
  with os.fdopen(os.open(file,os.O_WRONLY|os.O_APPEND|os.O_NOFOLLOW),'ab')as output:output.write(b'{owned-incomplete-tail');output.flush();os.fsync(output.fileno())
  tail=self.log_identity();report=self.api('incomplete-tail-report','/software/apache-waf/report');assert report['cc_log_tail_incomplete']and report['partial']
  self.burst('incomplete-tail-enforcement-continues',self.sites[0],amount=5,xff='198.51.100.61',allowed=2);assert self.log_identity()==tail
  # Append a labelled, deliberately invalid capacity fixture; no existing
  # event is truncated or relabelled as real traffic. Keep the entire original.
  with os.fdopen(os.open(file,os.O_WRONLY|os.O_APPEND|os.O_NOFOLLOW),'ab')as output:
   left=(32<<20)-tail['bytes'];assert left>0
   while left:chunk=b'\n'+b' '*(min(left,65536)-1);assert chunk;output.write(chunk);left-=len(chunk)
   output.flush();os.fsync(output.fileno())
  full=self.log_identity();assert full['bytes']==32<<20
  self.burst('full32MiB-log-enforcement-continues',self.sites[0],amount=5,xff='198.51.100.62',allowed=2);assert self.log_identity()==full
  report=self.api('full-capacity-report','/software/apache-waf/report');assert report['cc_log_capacity_near_limit']and report['partial']and report['metadata_best_effort']
  self.save('bounded-original-sink-failure-cases',{'ok':True,'wrong_mode_original_bytes_preserved':True,'wrong_mode_not_repaired_by_product':True,'tail_original_bytes_preserved':True,'full_file':full,'full_original':self.blob('full-CC-owned-capacity-fixture',file.read_bytes()),'capacity_fixture_is_not_traffic':True,'enforcement_continued_for_each_fixture':True,'automatic_archive_or_repair_not_claimed':True})
 def run(self):
  self.create_sites();self.body_cases();a,b=self.sites
  invalid=copy.deepcopy(self.last);invalid['policy']['cc_enabled']=True
  self.api('unselected-CC-refuses-preview','/software/apache-waf/preview',{'settings':invalid},409)
  assert not os.path.lexists('/var/lib/panel-apache-body/cc-events.log')and self.api('unselected-still-unchanged','/software/apache-waf/config')['settings']==self.last
  self.configure('explicit-native-selection',lambda s:(self.site_policy(s),self.rule(s)))
  before=self.counters();probe=self.request(a,'/__yunzhan_waf_probe',b'',method='HEAD');headers={k.lower():v for k,v in probe['headers'].items()};assert probe['status']==204 and probe['response_hex']==''and headers['x-panel-apache-cc-probe']=='1.0.0'and headers['x-panel-apache-cc'].startswith('1.0.0:')and headers['x-panel-apache-waf'].startswith('2.5.0:')and self.counters()==before
  legacy=pathlib.Path('/var/log/apache2/panel-waf.events.log');legacy_before=legacy.read_bytes()
  self.burst('disabled-proxy-spoofs-share-one-quota',a,allowed=2,vary_spoof=True)
  self.burst('independent-second-site',b,allowed=5)
  self.burst('independent-other-path',a,path='/cc56/ordinary',allowed=5)
  self.burst('prefix-rule-matches-original-before-rewrite',a,path='/cc56/prefix/original',allowed=2)
  self.configure('explicit-trusted-proxy',lambda s:s.update(trusted_proxy={'enabled':True,'header':'X-Forwarded-For','recursive':True,'trusted_cidrs':['127.0.0.1/32'],'acknowledge_header_control':True}))
  self.burst('trusted-client10-first',a,amount=1,xff='198.51.100.10',allowed=1);self.burst('trusted-client11-independent',a,amount=1,xff='198.51.100.11',allowed=1);self.burst('trusted-client10-exhaustion',a,amount=3,xff='198.51.100.10',allowed=1)
  self.burst('untrusted-direct-peer-ignores-XFF',a,source='127.0.0.2',vary_spoof=True,allowed=2)
  self.burst('normal-front-preserves-untrusted-rightmost-peer',a,source='127.0.0.3',vary_spoof=True,port=19101,allowed=2)
  self.burst('mapped-IPv4-canonical-initial',a,amount=2,xff='::ffff:198.51.100.20',allowed=2);self.burst('mapped-IPv4-same-budget',a,amount=2,xff='198.51.100.20',allowed=0)
  self.quota_recovery()
  self.configure('observe',lambda s:(self.site_policy(s,'observe'),self.rule(s)))
  self.burst('observe-continues-PHP-and-records',a,xff='198.51.100.40',allowed=5)
  self.configure('off',lambda s:self.site_policy(s,'off'))
  before_log=self.digest('/var/lib/panel-apache-body/cc-events.log');self.burst('off-no-charge-and-no-event',a,xff='198.51.100.41',allowed=5);assert self.digest('/var/lib/panel-apache-body/cc-events.log')==before_log
  allow_id=secrets.token_hex(16)
  def allow(s):self.site_policy(s);s['policy']['lists']['ip_allow'].append({'id':allow_id,'site_id':a['id'],'value':'198.51.100.44/32'})
  self.configure('explicit-owned-whitelist',allow);self.burst('whitelist-does-not-charge',a,xff='198.51.100.44',amount=12,allowed=12)
  self.configure('owned-whitelist-remove',lambda s:s['policy']['lists'].__setitem__('ip_allow',[v for v in s['policy']['lists']['ip_allow']if v['id']!=allow_id]))
  self.burst('former-whitelist-still-has-original-burst',a,xff='198.51.100.44',allowed=2)
  # Exact loopback HEAD remains a bounded empty probe. Query and method variants
  # go to the real application and share the ordinary URL quota.
  first=self.request(a,'/__yunzhan_waf_probe?private_query='+self.private_marker,b'',method='HEAD',xff='198.51.100.70');second=self.request(a,'/__yunzhan_waf_probe',b'owned ordinary POST',xff='198.51.100.70');assert first['status']==200 and second['status']==429
  assert legacy.read_bytes()==legacy_before,'CC leaked into the legacy unbounded CustomLog'
  self.log_cases();assert legacy.read_bytes()==legacy_before
  self.save('all-original-HTTP-results',self.requests);self.save('all-actual-PHP-counters',self.counters());self.save('all-original-groups',self.groups)
  self.h.proof.update(native_CC_actual_HTTP_requests=len(self.requests),native_CC_owned_sites=[s['id']for s in self.sites],native_CC_normal_engine=self.engine,real_body_168_and32_blocked=True,real_proxy_disabled_and_explicit_trusted_chain_verified=True,real_site_and_URL_isolation_verified=True,real_worker_and_graceful_quota_preservation_verified=True,real_CC_log_capacity_permission_and_tail_verified=True,original_HTTP_responses_retained=True,automatic_failure_repair_not_claimed=True)
  return {'sites':[{k:(sorted(v)if isinstance(v,set)else v)for k,v in s.items()}for s in self.sites],'engine':self.engine,'body_engine':self.last['body']['engine_job_id'],'settings':self.last,'CC_log':self.log_identity(),'original_HTTP_requests':len(self.requests),'programme_source_inputs_sha256':'1d04d55fd7f94ab192517b1467f4760686c57ebe5365515d8b4d4bc8d6ffe66d'}

def run(h,engine,legacy_body=None):return Acceptance(h,engine,legacy_body).run()
