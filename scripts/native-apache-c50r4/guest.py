"""Fresh original-signed programme, Apache/PHP installation and body requests.
All mutations are submitted once; an unknown result is retained, never replayed.
"""
import ast,contextlib,copy,hashlib,http.cookiejar,json,os,pathlib,platform,pwd,re,runpy,secrets,socket,sqlite3,stat,subprocess,sys,time,traceback,urllib.error,urllib.request
os.umask(0o077);assert len(sys.argv)==2 and os.geteuid()==0
payload=pathlib.Path(sys.argv[1]).resolve(strict=True);pins=json.loads((payload/'assets.json').read_bytes())
SOURCE='1d3a807f72780f23724decb93d9a5ee479a675cf3c759b068f4494ed4afbc61b'
VERSION='0.1.0-dev.proapps24apachelogscandidate50r4'
assert platform.machine()=='x86_64'and pins['architecture']=='amd64'and pins['source_inputs_sha256']==SOURCE and pins['version']==VERSION
case=pins['OS_case'];assert case['architecture']=='amd64'and case['platform']in('debian-12','debian-13','ubuntu-22.04','ubuntu-24.04','ubuntu-26.04')
assert pathlib.Path('/etc/hostname').read_text().strip()==case['hostname']
assert 'VERSION_ID="'+case['version_id']+'"'in pathlib.Path('/usr/lib/os-release').read_text()and pathlib.Path('/proc/1/comm').read_text().strip()=='systemd'
base=pathlib.Path('/opt/panel-apache-c50r4-native-qa-'+secrets.token_hex(16));base.mkdir(mode=0o700);evidence=base/'evidence';evidence.mkdir(mode=0o700)
def sha(f):return hashlib.sha256(pathlib.Path(f).read_bytes()).hexdigest()
def save(n,v):
 assert re.fullmatch('[A-Za-z0-9._-]+',n)
 with os.fdopen(os.open(evidence/n,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600),'w')as f:json.dump(v,f,sort_keys=True,indent=2);f.write('\n');f.flush();os.fsync(f.fileno())
verified=base/'verified-input';verified.mkdir(mode=0o700)
for name,digest in pins['files'].items():
 assert re.fullmatch('[A-Za-z0-9._-]+',name)
 with os.fdopen(os.open(payload/name,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC),'rb')as f:
  s=os.fstat(f.fileno());assert stat.S_ISREG(s.st_mode)and s.st_nlink==1 and 0<s.st_size<=64<<20
  raw=f.read((64<<20)+1);z=os.fstat(f.fileno())
  assert len(raw)==s.st_size and hashlib.sha256(raw).hexdigest()==digest and(s.st_dev,s.st_ino,s.st_size,s.st_mtime_ns,s.st_ctime_ns)==(z.st_dev,z.st_ino,z.st_size,z.st_mtime_ns,z.st_ctime_ns)
 with os.fdopen(os.open(verified/name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600),'wb')as f:f.write(raw);f.flush();os.fsync(f.fileno())
payload=verified
assert sha(payload/'signed-release.py')=='fe128e82b4e11345b320cd782134768bfe1a4df14947c425d7494873a7a7b7b5'
assert sha(payload/'release-signing-dev.pub')=='4ccfcc861d56a41e3ba7f7ace7e2432c815f366c58448d783df92c6632f01339'
names={'command','unit','snapshot','api','NoRedirect'}
nodes=[n for n in ast.parse((payload/'capture.py').read_bytes()).body if isinstance(n,(ast.FunctionDef,ast.ClassDef))and n.name in names]
assert len(nodes)==len(names);exec(compile(ast.Module(body=nodes,type_ignores=[]),'<original-bound-readonly-and-once-HTTP-client>','exec'),globals())
boot=pathlib.Path('/proc/sys/kernel/random/boot_id').read_text().strip();p={'boot':boot};own_site=None;secret=secrets.token_hex(32)
origin='http://127.0.0.1:19100';csrf='';events=[];requests=[];reached=[];native_processes={}
client=urllib.request.build_opener(urllib.request.ProxyHandler({}),NoRedirect(),urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))
proof={'ok':False,'architecture':'amd64','base':str(base),'source_inputs_sha256':SOURCE,'OS_case':case,'normal_programme_installer_submissions':0,'legacy_WAF_install_POSTs':0,'signed_runtime_install_POSTs':0,'signed_WAF_update_POSTs':0,'site_create_POSTs':0,'site_settings_POSTs':0,'body_engine_build_POSTs':0,'body_configure_POSTs':0,'synthetic_HTTP_requests':0,'Main_changed':False,'all50_commercial':False,'original_operations_replayed':False,'actual_browser_UI_acceptance':False}
def wait_job(label,jid,table):
 assert re.fullmatch('[a-f0-9]{32}',jid)and table in('jobs','runtime_jobs');deadline=time.monotonic()+5400;observations=[]
 while True:
  with contextlib.closing(sqlite3.connect('file:/var/lib/panel/panel.db?mode=ro',uri=True))as db:
   db.row_factory=sqlite3.Row;db.execute('PRAGMA query_only=ON');row=dict(db.execute('SELECT *FROM '+table+' WHERE id=?',(jid,)).fetchone())
  if not observations or observations[-1]['state']!=row['state']:observations.append({'state':row['state'],'at':time.time()})
  if row['state']not in('queued','running'):break
  assert time.monotonic()<deadline,'Original job unresolved; observe only';time.sleep(2)
 save(label+'-original-observations.json',observations);save(label+'-original-terminal.json',row)
 assert row['state']=='succeeded'and not row['error'],(label,row['state'],row['error']);return row
def guard(label):
 for i in range(9):
  v=subprocess.run(['/opt/panel/current/bin/panel-executor','--check-program-upgrade-queues'],capture_output=True,timeout=35)
  u=unit('panel-mysql-overwrite-recovery.service')
  save(label+'-guard-'+str(i)+'.json',{'exit':v.returncode,'stdout_hex':v.stdout.hex(),'stderr_hex':v.stderr.hex(),'recovery_unit':u})
  if v.returncode==0:assert v.stdout==v.stderr==b'';return
  assert i<8 and v.stdout==b''and b'panel-mysql-overwrite-recovery.service'in v.stderr and u['ActiveState']=='activating'and u['SubState']=='condition'and u['MainPID']=='0'
  time.sleep(1)
def run_once(label,args,timeout):
 save(label+'-once-intent.json',{'args':args,'maximum_submissions':1,'unknown_observe_only':True})
 with(evidence/(label+'.stdout.log')).open('xb')as out,(evidence/(label+'.stderr.log')).open('xb')as err:v=subprocess.run(args,stdin=subprocess.DEVNULL,stdout=out,stderr=err,timeout=timeout)
 save(label+'-original-outcome.json',{'exit':v.returncode,'stdout_sha256':sha(evidence/(label+'.stdout.log')),'stderr_sha256':sha(evidence/(label+'.stderr.log'))})
 assert v.returncode==0,'Original operation failed; no replay: '+label
def catalogue(label):
 v=api(label,'/app-registry?refresh=1');assert len(v['catalog']['apps'])==50 and not v['source']['stale']and v['host']=={'platform':case['platform'],'architecture':'amd64'};return v
def pair(v,app):return next(x for x in v['catalog']['apps']if x['id']==app),next(x for x in v['status']if x['id']==app)
def install_runtime(app,version):
 v=catalogue(app+'-original-signed-catalogue');item,status=pair(v,app);assert item['version']==version and status['state_known']and not status['installed']
 proof['signed_runtime_install_POSTs']+=1
 reply=api(app+'-one-original-signed-runtime-install','/app-registry/'+app+'/install',{'expected_version':item['version'],'expected_sha256':item['sha256']},202,secrets.token_hex(16))
 row=wait_job(app+'-original-install',reply['job_id'],'runtime_jobs');assert row['kind']=='install_runtime'
 v=catalogue(app+'-actual-installed-catalogue');_,status=pair(v,app);assert status['state_known']and status['installed']and status['installed_version']==version and not status['update_available']
 save(app+'-signed-runtime-receipt.json',{'job_id':reply['job_id'],'item':item,'status':status})
 return reply['job_id']
def counter_rows():
 s=counter.lstat();assert stat.S_ISREG(s.st_mode)and stat.S_IMODE(s.st_mode)==0o600 and s.st_nlink==1 and s.st_uid==account.pw_uid and s.st_gid==account.pw_gid and s.st_size<=16384
 rows=counter.read_text().splitlines();assert all(re.fullmatch('[a-f0-9]{32}',x)for x in rows)and len(rows)==len(set(rows));return rows
def request_once(mode,port,c):
 rid=secrets.token_hex(16);label=mode+'-'+str(port)+'-'+c['name'];before=counter_rows();assert before==reached
 raw=bytes.fromhex(c['body_hex']);assert len(raw)==c['body_bytes']and hashlib.sha256(raw).hexdigest()==c['body_sha256']
 headers={'Host':domain,'User-Agent':'Mozilla/5.0 Yunzhan owned native acceptance','X-Yunzhan-QA-Request':rid}
 if c['content_type']:headers['Content-Type']=c['content_type']
 if c['encoding']:headers['Content-Encoding']=c['encoding']
 wanted=c['block_status']if mode=='block'else 200
 save(label+'-one-HTTP-intent.json',{'request_id':rid,'method':c['method'],'port':port,'body_bytes':len(raw),'body_sha256':c['body_sha256'],'expected_status':wanted,'maximum_submissions':1})
 req=urllib.request.Request('http://127.0.0.1:'+str(port)+'/'+probe_name,data=None if c['method']=='GET'else raw,headers=headers,method=c['method'])
 opener=urllib.request.build_opener(urllib.request.ProxyHandler({}),NoRedirect());proof['synthetic_HTTP_requests']+=1
 try:
  with opener.open(req,timeout=15)as response:status=response.status;body=response.read(8193);rh=response.headers.get('X-Yunzhan-QA-Reached','')
 except urllib.error.HTTPError as e:status=e.code;body=e.read(8193);rh=e.headers.get('X-Yunzhan-QA-Reached','')
 assert len(body)<=8192
 # Actual original successful PHP response bytes are retained encrypted.
 result={'mode':mode,'route_port':port,'case':c['name'],'request_id':rid,'status':status,'body_bytes':len(body),'body_sha256':hashlib.sha256(body).hexdigest(),'original_body_hex':body.hex(),'PHP_reached_header':rh};save(label+'-original-HTTP-result.json',result);requests.append(result)
 assert status==wanted,(label,status,wanted)
 if wanted==200:
  v=json.loads(body);assert v['marker']==php_marker and v['php']=='8.2.35'and v['pid']>1 and rh==rid
  process=pathlib.Path('/proc')/str(v['pid']);ps=dict(x.split(':',1)for x in(process/'status').read_text().splitlines()if':'in x)
  assert int(ps['Uid'].split()[1])==account.pw_uid and int(ps['Gid'].split()[1])==account.pw_gid and ps['NoNewPrivs'].strip()=='1'and all(int(ps[k],16)==0 for k in('CapPrm','CapEff','CapAmb'))
  native_processes[str(v['pid'])]={'UID':int(ps['Uid'].split()[1]),'GID':int(ps['Gid'].split()[1]),'NoNewPrivs':ps['NoNewPrivs'].strip(),'capabilities':{k:ps[k].strip()for k in('CapInh','CapPrm','CapEff','CapAmb')},'cgroup':(process/'cgroup').read_text(),'exe_sha256':sha(process/'exe'),'start_ticks':process.joinpath('stat').read_text().rsplit(')',1)[1].split()[19]}
  if c['expected_upload_sha256']is not None:assert v['files']['upload']=={'error':0,'bytes':len(b'ordinary owned upload content\n'),'sha256':c['expected_upload_sha256']}and v['raw_bytes']==0 and v['raw_sha256']==hashlib.sha256(b'').hexdigest()
  else:assert v['raw_bytes']==len(raw)and v['raw_sha256']==c['body_sha256']and v['files']==[]
  if c['expected_term_sha256']is not None:assert v['term_sha256']==c['expected_term_sha256']
  reached.append(rid);assert counter_rows()==reached
 else:assert not rh and counter_rows()==before
arch='amd64'
def verify_full_installed_archive():
    import tarfile
    name = 'panel-' + VERSION + '-linux-' + arch + '.tar.gz'
    archive = payload / name
    assert sha(archive) == pins['files'][name]
    installed = pathlib.Path('/opt/panel/current').resolve(strict=True)
    assert str(installed) == '/opt/panel/releases/' + VERSION
    records = []
    prefix = 'panel-' + VERSION + '-linux-' + arch + '/'
    with tarfile.open(archive, 'r:gz') as stream:
        for member in stream.getmembers():
            if member.name.rstrip('/') == prefix.rstrip('/'):
                relative = ''
            else:
                assert member.name.startswith(prefix)
                relative = member.name[len(prefix):].rstrip('/')
            assert not pathlib.PurePosixPath(relative).is_absolute() and '..' not in pathlib.PurePosixPath(relative).parts
            f = installed / relative
            s = f.lstat()
            assert s.st_uid == 0 and stat.S_IMODE(s.st_mode) == member.mode
            record = {'path': relative, 'mode': member.mode, 'uid': s.st_uid, 'gid': s.st_gid, 'inode': s.st_ino}
            if member.isfile():
                assert stat.S_ISREG(s.st_mode) and s.st_nlink == 1
                digest = hashlib.sha256(stream.extractfile(member).read()).hexdigest()
                assert sha(f) == digest
                record.update(type='file', sha256=digest, bytes=s.st_size)
            else:
                assert member.isdir() and stat.S_ISDIR(s.st_mode)
                record.update(type='directory')
            records.append(record)
    actual = {''} | {str(f.relative_to(installed)) for f in installed.rglob('*')}
    assert actual == {v['path'] for v in records} and len(records) == 203
    save('actual-entire-signed-installed-tree.json', {'ok': True, 'read_only': True, 'archive_sha256': sha(archive), 'installed': str(installed), 'entries': records, 'count': 203, 'source_inputs_sha256': json.loads((installed / 'SOURCE_INPUTS.json').read_bytes())['inputs_sha256']})

try:
 assert all(not os.path.lexists(n)for n in('/opt/panel','/var/lib/panel','/var/lib/panel-executor','/etc/panel-release','/etc/nginx/nginx.conf'))
 archive=payload/('panel-'+VERSION+'-linux-amd64.tar.gz');signer=['python3','-I','-B',str(payload/'signed-release.py')];key=['--public-key',str(payload/'release-signing-dev.pub')]
 run_once('original-programme-signature-verify',signer+['verify',str(archive)]+key,30)
 proof['normal_programme_installer_submissions']+=1;run_once('one-original-programme-first-install',signer+['install',str(archive)]+key,1800)
 assert json.loads(pathlib.Path('/opt/panel/current/SOURCE_INPUTS.json').read_bytes())['inputs_sha256']==SOURCE and not os.path.lexists('/opt/panel/DEVELOPMENT_RELEASE')
 verify_full_installed_archive()
 guard('programme-ready');save('programme-installed-before-apps.json',snapshot())
 access_file=pathlib.Path('/etc/panel/first-login.json');s=access_file.lstat();assert stat.S_ISREG(s.st_mode)and s.st_uid==0 and s.st_nlink==1 and stat.S_IMODE(s.st_mode)==0o600
 access=json.loads(access_file.read_bytes())
 try:csrf=api('login','/login',{k:access[k]for k in('username','password')})['csrf']
 finally:access.clear()
 install_runtime('apache','2.4.68-compat1');install_runtime('php-82','8.2.35-compat2')
 nonce=secrets.token_hex(16);domain='qa-ap24-'+nonce[:12]+'.example.test';probe_name='qa-apache24-body-'+nonce[:12]+'.php';php_marker='apache24-php-'+nonce;body_marker='apache24-body-'+nonce
 proof['site_create_POSTs']+=1;reply=api('one-owned-PHP-site-create','/sites',{'name':'Apache native real PHP acceptance','slug':'qa-ap24-'+nonce[:12],'domain':domain,'php_version_id':'php-8.2.35'},202,secrets.token_hex(16));created=wait_job('owned-site-create',reply['job_id'],'jobs');own_site=created['site_id'];assert re.fullmatch('[a-f0-9]{32}',own_site)
 site=api('actual-created-PHP-site','/sites/'+own_site+'/settings');assert site['status']=='running'and site['settings']['web_server']=='nginx'and site['php_version_id']=='php-8.2.35'
 settings=copy.deepcopy(site['settings']);settings['web_server']='apache';preview=api('owned-Apache-site-readonly-preview','/sites/'+own_site+'/settings/preview',{'settings':settings,'expected_revision':site['settings_revision']})
 assert preview['revision']==site['settings_revision']and hashlib.sha256(preview['current'].encode()).hexdigest()==preview['config_sha']and 'proxy_pass http://127.0.0.1:19080;'in preview['candidate']
 proof['site_settings_POSTs']+=1;reply=api('one-owned-Apache-site-save','/sites/'+own_site+'/settings',{'settings':settings,'expected_revision':site['settings_revision'],'expected_config_sha':preview['config_sha']},202,secrets.token_hex(16));wait_job('owned-Apache-site-save',reply['job_id'],'jobs')
 account=pwd.getpwnam('ps'+own_site[:24]);assert account.pw_uid>0 and account.pw_gid>0
 root=pathlib.Path('/srv/panel/sites')/own_site
 public=(root/'public').lstat();private=(root/'private').lstat()
 assert stat.S_IMODE(public.st_mode)==0o750 and public.st_uid==account.pw_uid and public.st_gid==pwd.getpwnam('www-data').pw_gid
 assert stat.S_IMODE(private.st_mode)==0o700 and private.st_uid==account.pw_uid and private.st_gid==account.pw_gid
 save('actual-site-native-account.json',{'site_id':own_site,'UID':account.pw_uid,'primary_GID':account.pw_gid,'public_GID':public.st_gid,'domain':domain,'probe':probe_name})
 # Observe the actual managed front listener; do not change an existing port.
 conf=pathlib.Path('/etc/panel/sites-enabled')/(own_site+'.conf');text=conf.read_text()
 assert re.search(r'^\s*listen 127\.0\.0\.1:19101;',text,re.M);front_port=19101
 save('actual-managed-front-listener.json',{'path':str(conf),'sha256':sha(conf),'port':front_port})
 assert not os.path.lexists('/etc/panel/security-apps/modules/apache-waf/installed.json')
 proof['legacy_WAF_install_POSTs']+=1;reply=api('one-original-legacy-default-WAF-install','/software/apache-waf/install',{},202,secrets.token_hex(16));legacyjob=wait_job('legacy-WAF-install',reply['job_id'],'runtime_jobs')
 cfg=api('legacy-metadata-installed-config','/software/apache-waf/config');assert cfg['status']['healthy']and cfg['status']['version']=='2.3.0'and cfg['settings'].get('body')is None
 module=pathlib.Path('/etc/panel/security-apps/modules/apache-waf')
 original_installed=(module/'installed.json').read_bytes();history_before={n:(module/n).read_bytes()for n in('history.json','last-report.json','history.sqlite')if(module/n).exists()}
 save('legacy-WAF-baseline-original.json',{'job':legacyjob,'installed_hex':original_installed.hex(),'history_originals':{k:v.hex()for k,v in history_before.items()},'normal_legacy_install_not_signed_catalogue_claim':True})
 v=catalogue('original-signed-WAF-update-offered');item,status=pair(v,'apache-waf');assert item['version']=='2.4.0'and status['installed_version']=='2.3.0'and status['update_available']
 proof['signed_WAF_update_POSTs']+=1;reply=api('one-original-signed-WAF24-update','/app-registry/apache-waf/update',{'expected_version':item['version'],'expected_sha256':item['sha256']},202,secrets.token_hex(16));wait_job('signed-WAF-update',reply['job_id'],'runtime_jobs')
 current=api('native-WAF24-actual-config','/software/apache-waf/config');assert current['status']['healthy']and current['status']['version']=='2.4.0'and current['settings'].get('body')is None
 original=json.loads(original_installed);installed=json.loads((module/'installed.json').read_bytes());assert original['installed_at']==installed['installed_at']and all((module/k).read_bytes()==v for k,v in history_before.items())
 v=catalogue('signed-update-completed-no-repeat');_,status=pair(v,'apache-waf');assert status['installed_version']=='2.4.0'and not status['update_available']
 engines=api('original-empty-engine-inventory','/software/apache-waf/body-engines');assert engines['entries']==[]
 proof['body_engine_build_POSTs']+=1;reply=api('one-original-engine-build','/software/apache-waf/body-engine/build',{},202,secrets.token_hex(16));engine_id=reply['job_id'];wait_job('original-engine-build',engine_id,'runtime_jobs')
 eng=api('actual-ready-engine','/software/apache-waf/body-engine/jobs/'+engine_id);assert eng['state']=='ready'and eng['engine_version']=='2.9.15-yz5'and eng['integrity_verified']and eng['module_abi_validated']and eng['elf_hardening_validated']and eng['compiler_groups_collected']
 book=runpy.run_path(str(payload/'casebook.py'));cases=book['request_cases'](body_marker);assert len(cases)==28
 counter=root/'private'/('qa-apache24-counter-'+nonce);assert not os.path.lexists(counter)
 with os.fdopen(os.open(counter,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600),'wb')as f:os.fchown(f.fileno(),account.pw_uid,account.pw_gid);f.flush();os.fsync(f.fileno())
 code=book['php_fixture'](php_marker,str(counter));created=api('one-owned-PHP-file-create','/sites/'+own_site+'/files/action',{'action':'create','path':probe_name,'content':code});assert created['sha256']==hashlib.sha256(code.encode()).hexdigest()
 original=api('original-before-body-modes','/software/apache-waf/config');save('before-real-body-requests.json',snapshot())
 for mode in('observe','block','off'):
  cfg=api('mode-'+mode+'-current-config','/software/apache-waf/config');settings=copy.deepcopy(cfg['settings'])
  settings['body']={'engine_job_id':engine_id,'sites':[{'site_id':own_site,'policy':{'mode':mode,'paranoia_level':1,'inbound_threshold':5,'body_limit_kib':128,'non_file_limit_kib':64,'json_depth':64,'argument_limit':256}}]}
  pv=api('mode-'+mode+'-readonly-preview','/software/apache-waf/preview',{'settings':settings});assert pv['read_only']and pv['implementation_version']=='2.4.0'
  proof['body_configure_POSTs']+=1;reply=api('mode-'+mode+'-one-original-configure','/software/apache-waf/configure',{'settings':settings},202,secrets.token_hex(16));wait_job('mode-'+mode+'-configure',reply['job_id'],'runtime_jobs')
  actual=api('mode-'+mode+'-actual-config','/software/apache-waf/config');expected=copy.deepcopy(settings);expected['policy']['revision']+=1;assert actual['settings']==expected and actual['status']['healthy']
  for port in(19080,front_port):
   for c in cases:request_once(mode,port,c)
  save('mode-'+mode+'-actual-PHP-counter.json',{'rows':counter_rows(),'expected':len(reached)})
 assert proof['synthetic_HTTP_requests']==168 and len(reached)==136
 cfg=api('before-explicit-body-removal','/software/apache-waf/config');restore=copy.deepcopy(original['settings']);restore['policy']['revision']=cfg['settings']['policy']['revision'];restore['body']={'engine_job_id':engine_id,'sites':[]}
 proof['body_configure_POSTs']+=1;reply=api('one-explicit-empty-body-sites-restoration','/software/apache-waf/configure',{'settings':restore},202,secrets.token_hex(16));wait_job('explicit-body-sites-restoration',reply['job_id'],'runtime_jobs')
 final=api('actual-restored-metadata-config','/software/apache-waf/config');expected=copy.deepcopy(restore);expected['policy']['revision']+=1;assert final['settings']==expected and final['status']['healthy']
 log=pathlib.Path('/var/lib/panel-apache-body/events.log');raw=log.read_bytes();s=log.lstat();www=pwd.getpwnam('www-data');assert stat.S_ISREG(s.st_mode)and s.st_nlink==1 and stat.S_IMODE(s.st_mode)==0o600 and s.st_uid==www.pw_uid and s.st_gid==www.pw_gid and 0<len(raw)<=32<<20
 assert body_marker.encode()not in raw and php_marker.encode()not in raw and domain.encode()not in raw
 numeric=[]
 for line in raw.splitlines():
  e=json.loads(line);assert set(e)=={'time_us','engine','site_id','rule_id','phase','severity','mode','blocked'}and e['engine']=='2.9.15-yz5'and e['site_id']==own_site;numeric.append(e)
 assert {'observe','block'}<={v['mode']for v in numeric}
 save('original-numeric-events.json',{'original_hex':raw.hex(),'sha256':hashlib.sha256(raw).hexdigest(),'bytes':len(raw),'events':numeric})
 report=api('actual-numeric-body-report','/software/apache-waf/body-report?site_id='+own_site+'&limit=1000')
 assert report['available']and not report['partial']and report['counting_contract']=='rule_matches_not_unique_requests_or_confirmed_http_blocks'and report['rule_matches']==len(numeric)and report['rejected_lines']==0
 save('actual-nonroot-FPM-processes.json',native_processes)
 fixed={}
 for directory in(module/'config-transactions',module/'config-transaction-archive'):
  if not directory.exists():continue
  st=directory.lstat();assert stat.S_ISDIR(st.st_mode)and st.st_uid==0 and not st.st_mode&0o022
  entries=list(directory.iterdir());assert len(entries)<=64
  for f in entries:
   st=f.lstat();assert re.fullmatch('[a-f0-9]{32}\\.json',f.name)and stat.S_ISREG(st.st_mode)and st.st_uid==0 and st.st_nlink==1 and stat.S_IMODE(st.st_mode)==0o600 and st.st_size<=8<<20
   raw=f.read_bytes();assert len(raw)==st.st_size;fixed[str(f)]={'original_hex':raw.hex(),'sha256':sha(f),'uid':st.st_uid,'gid':st.st_gid,'mode':stat.S_IMODE(st.st_mode)}
 save('original-native-transaction-files.json',fixed)
 save('original-engine-build-unit-resource-status.json',{'raw':command(['systemctl','show','panel-apache-body-build@'+engine_id+'.service','--property=LoadState,ActiveState,Result,ExecMainStatus,MemoryPeak,MemoryMax,MemorySwapMax,CPUUsageNSec,TasksMax,NoNewPrivileges,ProtectSystem,CapabilityBoundingSet'])})
 save('actual-cache-mount.json',{'raw':command(['findmnt','--json','--target','/var/cache/panel-apache-body'])})
 guard('all-operations-completed');save('after-real-body-requests.json',snapshot())

 save('before-numeric-maintenance.json',snapshot())
 before_lifetimes={name:unit(name)for name in('panel.service','panel-executor.service','nginx.service','panel-apache.service')}
 save('before-numeric-maintenance-lifetimes.json',before_lifetimes)
 numeric_log=pathlib.Path('/var/lib/panel-apache-body/events.log');original_log=numeric_log.read_bytes();log_before=numeric_log.lstat();original_digest=hashlib.sha256(original_log).hexdigest()
 inventory=api('numeric-original-empty-inventory','/software/apache-waf/body-log/archives');assert inventory['archives']==inventory['recovery']==inventory['index_stages']==[]and inventory['inventory_complete']and inventory['maintenance_healthy']
 rotated=api('numeric-one-original-rotate','/software/apache-waf/body-log/rotate',{});row=rotated['archive'];assert rotated['same_inode_rotation']and rotated['no_apache_reload']and row['state']=='completed'and row['bytes']==len(original_log)and row['sha256']==original_digest and re.fullmatch('[a-f0-9]{32}',row['id'])
 log_after=numeric_log.lstat();assert log_before.st_ino==log_after.st_ino and log_before.st_dev==log_after.st_dev and log_before.st_mode==log_after.st_mode and log_before.st_uid==log_after.st_uid and log_before.st_gid==log_after.st_gid and log_after.st_size==0
 original_snapshot=pathlib.Path('/var/lib/panel-apache-body/archives')/(row['id']+'.log');original_index=original_snapshot.with_suffix('.json')
 copied=original_snapshot.read_bytes();copy_stat=original_snapshot.lstat();assert copied==original_log and copy_stat.st_uid==0 and stat.S_IMODE(copy_stat.st_mode)==0o600 and copy_stat.st_nlink==1
 save('actual-numeric-original-live-and-copy.json',{'archive':row,'live_before':{'ino':log_before.st_ino,'dev':log_before.st_dev,'uid':log_before.st_uid,'gid':log_before.st_gid,'mode':log_before.st_mode,'bytes':log_before.st_size},'live_after':{'ino':log_after.st_ino,'dev':log_after.st_dev,'uid':log_after.st_uid,'gid':log_after.st_gid,'mode':log_after.st_mode,'bytes':log_after.st_size},'original_hex':copied.hex(),'sha256':original_digest})
 inventory=api('numeric-actual-post-rotate-inventory','/software/apache-waf/body-log/archives');assert inventory['archives']==[row]and inventory['maintenance_healthy']and inventory['inventory_complete']
 exported=api('numeric-one-original-selected-export','/software/apache-waf/body-log/archives/'+row['id']);assert exported['archive']==row and exported['selected_snapshot_digest_verified']and exported['inventory_not_claimed_complete']and exported['metadata']['log_bytes']==len(original_log)and len(exported['metadata']['events'])==len(numeric)and exported['metadata']['rejected_lines']==0 and not exported['metadata']['partial']
 import datetime
 expected_events=[]
 for event in reversed(numeric):
  seconds,micro=divmod(event['time_us'],1000000);stamp=datetime.datetime.fromtimestamp(seconds,datetime.timezone.utc).strftime('%Y-%m-%dT%H:%M:%S')+('.'+str(micro).zfill(6).rstrip('0')if micro else'')+'Z'
  expected_events.append({'time':stamp,'engine_version':event['engine'],'site_id':event['site_id'],'rule_id':event['rule_id'],'phase':event['phase'],'severity':event['severity'],'mode':event['mode'],'intercepted_mark':event['blocked']})
 assert exported['metadata']['events']==expected_events
 index_before=original_index.read_bytes()
 api('numeric-one-wrong-digest-remove','/software/apache-waf/body-log/archives/'+row['id']+'/remove',{'sha256':'0'*64,'confirm_delete':True},409)
 assert original_snapshot.read_bytes()==original_log and original_snapshot.lstat().st_ino==copy_stat.st_ino and original_index.read_bytes()==index_before
 removed=api('numeric-one-original-digest-remove','/software/apache-waf/body-log/archives/'+row['id']+'/remove',{'sha256':original_digest,'confirm_delete':True});assert removed=={'removed':True,'archive_id':row['id'],'sha256':original_digest,'current_log_untouched':True}
 assert not os.path.lexists(original_snapshot)and not os.path.lexists(original_index)
 inventory=api('numeric-actual-final-inventory','/software/apache-waf/body-log/archives');assert inventory['archives']==inventory['recovery']==inventory['index_stages']==[]and inventory['maintenance_healthy']and inventory['inventory_complete']
 final_log=numeric_log.lstat();assert final_log.st_ino==log_before.st_ino and final_log.st_mode==log_before.st_mode and final_log.st_uid==log_before.st_uid and final_log.st_gid==log_before.st_gid and final_log.st_size==0
 after_lifetimes={name:unit(name)for name in before_lifetimes};save('after-numeric-maintenance-lifetimes.json',after_lifetimes);assert before_lifetimes==after_lifetimes
 guard('numeric-maintenance-completed');save('after-numeric-maintenance.json',snapshot())
 proof.update(actual_numeric_rotation_original_digest_export_and_removal=True,numeric_rotation_POSTs=1,numeric_wrong_digest_remove_POSTs=1,numeric_confirmed_remove_POSTs=1,numeric_original_snapshots_retained_in_encrypted_evidence=True,numeric_services_original_lifetimes_unchanged=True,numeric_cold_powerloss_pending=True)
 proof.update(ok=True,normal_original_signed_programme_installed=True,all203_installed_entries_verified=True,legacy_metadata_WAF_version='2.3.0',legacy_install_not_signed_catalogue_claim=True,normal_signed_WAF_update_version='2.4.0',legacy_history_and_installed_at_preserved=True,actual_UID=account.pw_uid,actual_primary_GID=account.pw_gid,PHP_requests_168=True,PHP_reached_136=True,blocked_32_never_reached_PHP=True,explicit_empty_sites_restoration=True,body_engine_job_id=engine_id,numeric_rule_matches=len(numeric),actual_cold_boot_pending=True,full_SQL_row_independent_reconciliation_pending=True)
except BaseException:save('original-failure.json',{'traceback':traceback.format_exc()})
finally:
 if csrf:
  try:api('logout','/logout',{});csrf=''
  except BaseException:proof['logout_unknown_observe_only']=True;proof['ok']=False
 save('HTTP-events.json',events);save('request-summary.json',requests);save('proof.json',proof)
 print(json.dumps({'ok':proof['ok'],'base':str(base),'proof_sha256':sha(evidence/'proof.json'),'source_inputs_sha256':SOURCE,'architecture':'amd64','Main_changed':False,'all50_commercial':False}),flush=True)
sys.exit(0 if proof['ok']else 1)
