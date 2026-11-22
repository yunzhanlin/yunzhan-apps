"""Actual signed WAF store, first account/data task and real Nginx decisions.
Run only in an identified zero-site isolated QA with the normal C29r5 programme.
Never used against Main; no repeat of failed/unknown original requests.
"""
import contextlib,copy,hashlib,http.cookiejar,ipaddress,json,os,pathlib,platform,re,secrets,sqlite3,stat,subprocess,time,urllib.request,urllib.error
SOURCE='b223c28247d9d20e50a356643a9744a9ab174068dd567a2c57f15c342934c15f'
DATA='e9d0ab29314d796c94b73b72355326dd89315d4a6d43862f031aecfd1ffe13f1'
def run(base,architecture,expected_app_sha,owned_site_ids):
    base=pathlib.Path(base);assert os.geteuid()==0 and architecture in('arm64','amd64')
    assert platform.machine()=={'arm64':'aarch64','amd64':'x86_64'}[architecture]
    assert re.fullmatch('/opt/panel-country-native-qa-[a-f0-9]{32}',str(base))and base.is_dir()
    assert json.loads(pathlib.Path('/opt/panel/current/SOURCE_INPUTS.json').read_bytes())['inputs_sha256']==SOURCE
    evidence=base/'evidence';evidence.mkdir(mode=0o700)
    def save(n,v):
        assert re.fullmatch('[A-Za-z0-9._-]+',n)
        with(evidence/n).open('x')as f:json.dump(v,f,sort_keys=True,indent=2);f.write('\n');f.flush();os.fsync(f.fileno())
    def sha(p):return hashlib.sha256(pathlib.Path(p).read_bytes()).hexdigest()
    def row(table,id):
        assert table in('runtime_jobs','jobs')
        with contextlib.closing(sqlite3.connect('file:/var/lib/panel/panel.db?mode=ro',uri=True,timeout=3))as db:
            db.row_factory=sqlite3.Row;db.execute('PRAGMA query_only=ON');v=db.execute('SELECT * FROM '+table+' WHERE id=?',(id,)).fetchone();assert v is not None;return dict(v)
    with contextlib.closing(sqlite3.connect('file:/var/lib/panel/panel.db?mode=ro',uri=True))as db:
        db.execute('PRAGMA query_only=ON');assert db.execute('SELECT count(*) FROM sites').fetchone()[0]==2,'Only the exact prior two owned QA sites are allowed'
        assert db.execute("SELECT count(*) FROM runtime_jobs WHERE state IN ('queued','running','needs_attention')").fetchone()[0]==0
        original_jobs=[list(v)for v in db.execute('SELECT id,state,payload,error FROM runtime_jobs ORDER BY id')]
    origin='http://127.0.0.1:19100';csrf='';opener=None
    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self,*a,**k):raise AssertionError('HTTP redirect refused')
    def api(path,body=None,key=None):
        headers={'Content-Type':'application/json','Origin':origin,'X-CSRF-Token':csrf}
        if key:headers['Idempotency-Key']=key
        raw=None if body is None else json.dumps(body,separators=(',',':')).encode()
        req=urllib.request.Request(origin+'/api'+path,data=raw,headers=headers)
        try:
            with opener.open(req,timeout=45)as r:
                b=r.read((4<<20)+1);assert len(b)<=4<<20;return r.status,json.loads(b)
        except urllib.error.HTTPError as e:
            save('http-error-'+secrets.token_hex(8)+'.json',{'path':path,'status':e.code,'body':e.read(8192).decode('utf8','replace')});raise AssertionError('Original HTTP '+path+' '+str(e.code))from None
    def wait_job(table,job,label,seconds=360):
        end=time.monotonic()+seconds;observed=[]
        while True:
            value=row(table,job);observed.append({'at':time.time(),'row':value})
            if value['state']in('succeeded','failed','cancelled','needs_attention'):break
            assert value['state']in('queued','running')and time.monotonic()+2<end;time.sleep(2)
        save(label+'-original-job.json',observed);assert value['state']=='succeeded'and value.get('error','')=='','Original failed or unknown job retained, never requeued';return value
    proof={'ok':False,'architecture':architecture,'normal_signed_store':False,'country_account_created':False,'original_data_task_passed':False,'real_provider_Nginx_policy':False,'Main_changed':False,'all40_commercial':False,'controls':[]}
    try:
        accessfile=pathlib.Path('/etc/panel/first-login.json');s=accessfile.lstat();assert s.st_uid==0 and s.st_nlink==1 and stat.S_IMODE(s.st_mode)==0o600
        access=json.loads(accessfile.read_bytes());opener=urllib.request.build_opener(urllib.request.ProxyHandler({}),NoRedirect(),urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))
        try:status,value=api('/login',{n:access[n]for n in('username','password')});assert status==200;csrf=value['csrf']
        finally:access.clear()
        status,start_config=api('/software/nginx-waf/config');assert status==200 and start_config['status']['healthy'];original=copy.deepcopy(start_config['settings']);assert original.get('country')is None
        with contextlib.closing(sqlite3.connect('file:/var/lib/panel/panel.db?mode=ro',uri=True))as db:
            db.row_factory=sqlite3.Row;db.execute('PRAGMA query_only=ON');assert db.execute('SELECT count(*) FROM waf_country_requests').fetchone()[0]==db.execute('SELECT count(*) FROM waf_country_results').fetchone()[0]==0
            sites=[dict(db.execute('SELECT * FROM sites WHERE id=?',(id,)).fetchone())for id in owned_site_ids]
        assert [v['id']for v in sites]==owned_site_ids and all(v['status']=='running'and v['domain'].endswith('.example.test')for v in sites)
        status,page=api('/app-registry?refresh=1');assert status==200 and page['source']['stale']is False
        item=next(v for v in page['catalog']['apps']if v['id']=='nginx-waf');current=next(v for v in page['status']if v['id']=='nginx-waf');assert item['version']=='2.6.0'and item['sha256']==expected_app_sha and current['installed']and current['installed_version']=='2.6.0'and not current['update_available'];save('store-after-original-completed-update.json',page)
        status,config=api('/software/nginx-waf/config');assert status==200 and config['settings']==original and config['status']['version']=='2.6.0'and config['implementation_version']=='2.6.0';save('configuration-after-original-store-update.json',config)
        proof.update(normal_signed_store=True,original_store_update_not_replayed=True,current_original_signed_store_receipt_verified=True,both_owned_sites_not_production=True)
        def nss():
            result={}
            for n in('passwd','group','shadow','gshadow'):
                raw=pathlib.Path('/etc/'+n).read_bytes();entries=[v for v in raw.splitlines(keepends=True)if v.startswith(b'panel-country-net:')];assert len(entries)<=1;rest=b''.join(v for v in raw.splitlines(keepends=True)if not v.startswith(b'panel-country-net:'));result[n]={'sha256':hashlib.sha256(raw).hexdigest(),'without_country_sha256':hashlib.sha256(rest).hexdigest(),'country_count':len(entries)}
            return result
        before_nss=nss();assert all(v['country_count']==0 for v in before_nss.values());save('NSS-before-country-account.json',before_nss)
        status,page=api('/software/nginx-waf/country-data');assert status==200 and page['state']['supported']and page['state']['app_version']=='2.6.0'and page['state']['downloads_do_not_activate_policy']
        assert page['available']and page['source_error']==''and re.fullmatch('[a-f0-9]{32}',page['actor_id'])and page['available']['data_manifest_sha256']==DATA
        available=page['available'];assert available['app_manifest_sha256']==expected_app_sha and len(available['files'])==250;save('original-country-available.json',page)
        selection={'action':'download','app_version':'2.6.0','app_manifest_sha256':expected_app_sha,'installation_sha256':page['state']['installation_sha256'],'release':available['release'],'revision':available['revision'],'data_manifest_sha256':DATA,'countries':['CN','US']};key=secrets.token_hex(16);body={'actor_id':page['actor_id'],'selection':selection};save('country-data-once-intent.json',{'body':body,'key':key,'POST_maximum':1});status,reply=api('/software/nginx-waf/country-data',body,key);assert status==202 and reply['data_only']and reply['replayed']is False and reply['request_id']==key;save('country-data-response.json',reply);job=reply['job_id'];wait_job('runtime_jobs',job,'country-data',360)
        status,detail=api('/software/nginx-waf/country-data/jobs/'+job);save('country-original-detail.json',detail);assert status==200 and detail['actor_id']==page['actor_id']and detail['request']['id']==job and detail['request']['state']=='succeeded'and detail['selection']==selection and detail['read_only']is True
        result=detail['result'];entry=result['cache'];assert result['job_id']==job and result['state']=='succeeded'and result['data_only']and not result['automatic_replay_allowed']and entry['published']and not entry['reused']and not entry['activated_nginx_policy']and entry['original_job_id']==job and entry['data_manifest_sha256']==DATA and entry['countries']==['CN','US']and entry['networks']==237408
        after_nss=nss();save('NSS-after-country-account.json',after_nss);assert all(v['country_count']==1 for v in after_nss.values())and all(after_nss[n]['without_country_sha256']==before_nss[n]['sha256']for n in before_nss)
        record=json.loads(pathlib.Path('/etc/panel/security-apps/modules/nginx-waf/country-network-account.json').read_bytes());assert record['format']==1 and 0<record['uid']<1000 and 0<record['gid']<1000
        account=subprocess.run(['getent','passwd','panel-country-net'],capture_output=True,text=True,timeout=5);assert account.returncode==0 and account.stdout==f"panel-country-net:x:{record['uid']}:{record['gid']}:panel-waf-country-network:/nonexistent:/usr/sbin/nologin\n";groups=subprocess.run(['id','-G','panel-country-net'],capture_output=True,text=True,timeout=5);assert groups.returncode==0 and groups.stdout.strip()==str(record['gid']);proof.update(country_account_created=True,dedicated_UID=record['uid'],dedicated_GID=record['gid'],original_data_task_passed=True,original_country_job_id=job)
        dataset=entry['dataset'];assert dataset==DATA+'-'+hashlib.sha256(b'["CN","US"]').hexdigest();root=pathlib.Path('/var/lib/panel-executor/waf-country-data')/dataset;ips={};datafiles={}
        for code in('CN','US'):
            path=root/(code+'.cidr');info=path.lstat();assert stat.S_ISREG(info.st_mode)and info.st_uid==0 and not info.st_mode&0o022;datafiles[code]={'sha256':sha(path),'bytes':info.st_size};expected=next(v for v in available['files']if v['code']==code);assert expected['sha256']==datafiles[code]['sha256']and expected['bytes']==info.st_size
            ips[code]={}
            for line in path.read_text().splitlines():
                if line.startswith('#'):continue
                prefix,label=line[:-1].split(' ');assert label==code;network=ipaddress.ip_network(prefix,strict=True)
                if network.version not in ips[code]:ips[code][network.version]=str(network.network_address+(1 if network.num_addresses>1 else 0))
                if len(ips[code])==2:break
            assert len(ips[code])==2
        save('actual-verified-data-files-and-probe-IPs.json',{'files':datafiles,'IPs':ips,'selected_full_networks':entry['networks'],'not_live_physical_location_claim':True})
        status,unactivated=api('/software/nginx-waf/config');assert status==200 and unactivated['settings']==original,'Downloading data must not modify Nginx policy'
        last=copy.deepcopy(original);responses=[]
        def visit(site,ip,want,label,path='/'):
            req=urllib.request.Request('http://127.0.0.1:19101'+path,headers={'Host':site['domain'],'User-Agent':'YunZhan native country QA','X-Forwarded-For':ip});client=urllib.request.build_opener(urllib.request.ProxyHandler({}),NoRedirect())
            try:
                with client.open(req,timeout=8)as r:status=r.status;raw=r.read(8192)
            except urllib.error.HTTPError as e:status=e.code;raw=e.read(8192)
            assert status==want,label+' unexpected Nginx response '+str(status);responses.append({'phase':label,'site_id':site['id'],'client_IP':ip,'status':status,'body_sha256':hashlib.sha256(raw).hexdigest()})
        for site in sites:visit(site,ips['CN'][4],200,'download-only')
        def apply(settings,label):
            nonlocal last
            status,current=api('/software/nginx-waf/config');assert status==200 and current['settings']==last,'Concurrent or unknown policy; do not adopt or overwrite'
            settings=copy.deepcopy(settings);settings['policy']['revision']=last['policy']['revision'];key='country-policy-'+secrets.token_hex(16);save(label+'-once-intent.json',{'settings':settings,'key':key,'POST_maximum':1});status,reply=api('/software/nginx-waf/configure',{'settings':settings},key);assert status==202;wait_job('runtime_jobs',reply['job_id'],label,180);status,current=api('/software/nginx-waf/config');assert status==200 and current['status']['healthy']and current['settings']['policy']['revision']==last['policy']['revision']+1;last=current['settings'];save(label+'-applied.json',current);proof['controls'].append({'kind':label,'job_id':reply['job_id']});return copy.deepcopy(last)
        draft=copy.deepcopy(original);draft['policy']['cc_enabled']=False;draft['policy']['sites']=[];draft['trusted_proxy']={'enabled':True,'header':'X-Forwarded-For','recursive':True,'trusted_cidrs':['127.0.0.1/32'],'acknowledge_header_control':True};draft['country']={'enabled':True,'data':{'dataset':dataset,'data_manifest_sha256':DATA,'release':entry['release'],'revision':entry['revision'],'countries':['CN','US']},'global':{'mode':'block','list':'deny','countries':['CN']},'sites':[{'site_id':sites[1]['id'],'rule':{'mode':'block','list':'allow','countries':['US']}}]};draft['country']['sites'].sort(key=lambda v:v['site_id']);cfg=apply(draft,'country-block')
        for version in(4,6):
            visit(sites[0],ips['CN'][version],403,'global-CN-deny-IPv'+str(version));visit(sites[0],ips['US'][version],200,'global-US-allow-IPv'+str(version));visit(sites[1],ips['CN'][version],403,'site-CN-nonallow-IPv'+str(version));visit(sites[1],ips['US'][version],200,'site-US-allow-IPv'+str(version))
        visit(sites[0],'203.0.113.10',200,'nonmember-deny-permits');visit(sites[1],'203.0.113.10',403,'nonmember-allow-rejects')
        visit(sites[0],ips['CN'][4],200,'own-bound-health','/__panel_health_'+sites[0]['id']);visit(sites[0],ips['CN'][4],403,'foreign-bound-health','/__panel_health_'+sites[1]['id'])
        cfg['country']['sites']=[{'site_id':sites[1]['id'],'rule':{'mode':'off','list':'','countries':[]}}];cfg=apply(cfg,'country-site-off');visit(sites[0],ips['CN'][4],403,'other-site-remains-blocked');visit(sites[1],ips['CN'][4],200,'site-off-permits')
        cfg['country']['sites']=[];cfg['policy']['mode']='observe';cfg=apply(cfg,'metadata-observe');visit(sites[0],ips['CN'][4],200,'metadata-observe-cannot-be-promoted-to-country-block')
        status,report=api('/software/nginx-waf/report?rule=country&limit=500');save('country-actual-report.json',report);assert status==200 and any(v.get('country')=='CN'and v.get('country_data')==DATA for v in report['events'])
        cfg['policy']['mode']='block';cfg['country']['enabled']=False;cfg=apply(cfg,'country-paused');assert cfg['country']['data']==draft['country']['data']and cfg['country']['global']==draft['country']['global']
        for site in sites:visit(site,ips['CN'][4],200,'master-paused-immediately-permits')
        for code in('CN','US'):assert sha(root/(code+'.cidr'))==datafiles[code]['sha256']
        restored=copy.deepcopy(original);restored['trusted_proxy']=copy.deepcopy(original.get('trusted_proxy')or {'enabled': False, 'header': 'X-Forwarded-For', 'recursive': False, 'trusted_cidrs': [], 'acknowledge_header_control': False});restored['policy']['revision']=last['policy']['revision'];last=apply(restored,'original-policy-restored');expected=copy.deepcopy(restored);expected['policy']['revision']=last['policy']['revision'];assert last==expected
        for site in sites:visit(site,ips['CN'][4],200,'original-policy-restored-no-country')
        with contextlib.closing(sqlite3.connect('file:/var/lib/panel/panel.db?mode=ro',uri=True))as db:
            db.execute('PRAGMA query_only=ON')
            for old in original_jobs:assert list(db.execute('SELECT id,state,payload,error FROM runtime_jobs WHERE id=?',(old[0],)).fetchone())==old
        command=subprocess.run(['/opt/panel/current/bin/panel-executor','--check-program-upgrade-queues'],capture_output=True,timeout=35);assert command.returncode==0 and command.stdout==command.stderr==b''
        save('real-Nginx-responses.json',responses);proof.update(ok=True,source_inputs_sha256=SOURCE,real_provider_Nginx_policy=True,actual_HTTP_responses=len(responses),data_download_did_not_enable_policy=True,IPv4_and_IPv6_from_both_original_signed_country_files=True,global_deny_site_allow_site_off_metadata_observe_master_pause_and_health_scope=True,country_log_country_code_and_original_signature_SHA_verified=True,original_policy_restored=True,original_old_jobs_unchanged=True,full_native_upgrade_queue_guard_exit=0)
    finally:
        if csrf:
            status,_=api('/logout',{});assert status==200;proof['own_session_logged_out']=True
        save('proof.json',proof)
    return proof
