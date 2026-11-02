"""Synthetic owned-site native acceptance; never a commercial acceptance receipt."""
import contextlib,hashlib,hmac,http.client,json,os,pathlib,re,secrets,sqlite3,stat,time,urllib.parse

APP_SHA='7dc753e299b2801066ae6faa36e92d36169ee0bdc5f992192a5f9dd6861b8a8d'
def run_live_case(api,wait_job,save,base,site_id,domain,nonce,continuation=None):
 assert os.geteuid()==0 and re.fullmatch('[a-f0-9]{32}',site_id)and re.fullmatch('[a-f0-9]{32}',nonce)
 base=pathlib.Path(base);requests=[];jobs=[];original_events=None
 def dbrows(sid):
  with contextlib.closing(sqlite3.connect('file:/var/lib/panel/panel.db?mode=ro',uri=True,timeout=5))as db:
   db.execute('PRAGMA query_only=ON')
   return db.execute('SELECT id,data,ip_hash FROM analytics_events WHERE site_id=?ORDER BY id',(sid,)).fetchall()
 def config(label,sid):return api(label,'/analytics/sites/'+sid+'/config')
 def configure(label,sid,enabled):
  old=config(label+'-before',sid)
  reply=api(label+'-one-configure','/analytics/sites/'+sid+'/config',{'enabled':enabled,'clicks':False,'retention_days':30,'revision':old['revision'],'auto_inject_html':False},202,secrets.token_hex(16))
  row=wait_job(label,reply['job_id'],'jobs');jobs.append(row['id'])
  current=config(label+'-after',sid);assert current['enabled']==enabled and current['revision']==old['revision']+1 and re.fullmatch('[a-f0-9]{32}',current['key'])and(not old['key']or current['key']==old['key'])
  return current
 def event(path):return {'id':secrets.token_hex(16),'page_id':secrets.token_hex(16),'visitor':secrets.token_hex(16),'session':secrets.token_hex(16),'kind':'pageview','path':path,'title':'Owned native analytics acceptance'}
 def send(label,sid,host,key,address,body,headers=None,direct_loopback=False):
  conf=pathlib.Path('/etc/panel/sites-enabled')/(sid+'.conf');assert re.search(r'^\s*listen 127\.0\.0\.1:19101;',conf.read_text(),re.M)
  raw=json.dumps(body,separators=(',',':')).encode()
  port=19100 if direct_loopback else 19101
  connection=http.client.HTTPConnection('127.0.0.1',port,source_address=(address,0),timeout=10)
  expected={'Host':host,'Origin':'http://'+host,'Content-Type':'application/json','User-Agent':'Mozilla/5.0 Chrome/123.0 owned native analytics'}
  expected.update(headers or{})
  try:
   endpoint='/collect/analytics/event'if direct_loopback else'/__yunzhan/analytics/event'
   connection.request('POST',endpoint+'?'+urllib.parse.urlencode({'site':sid,'key':key}),raw,expected)
   response=connection.getresponse();data=response.read(8193);status=response.status;rh=response.getheaders()
  finally:connection.close()
  result={'label':label,'event_id':body['id'],'site_id':sid,'source_loopback':address,'synthetic_request_headers':expected,'transport':'direct_loopback_Core'if direct_loopback else'installed_Nginx','HTTP_status':status,'original_request_body_hex':raw.hex(),'body_sha256':hashlib.sha256(raw).hexdigest(),'original_response_hex':data.hex(),'response_headers':rh,'at':time.time()}
  requests.append(result);save('native-http-response-'+str(len(requests)).zfill(4)+'.json',result)
  assert len(data)<=8192 and not any(k.lower()=='set-cookie'for k,v in rh)
  return status
 def require204(*args,**kwargs):
  status=send(*args,**kwargs);assert status==204,('Actual installed collector refused',args[0],status)
 def private_state(sid,phase):
  site=api('identity-site-'+phase+'-'+sid,'/sites/'+sid+'/settings')
  identity=site['settings']['analytics_proxy_identity'];assert re.fullmatch('[a-f0-9]{64}',identity)
  path=pathlib.Path('/etc/panel/analytics-ingress')/(sid+'-'+identity+'.conf')
  parent=path.parent.lstat();s=path.lstat();raw=path.read_bytes()
  assert stat.S_ISDIR(parent.st_mode)and parent.st_uid==0 and stat.S_IMODE(parent.st_mode)==0o700
  assert stat.S_ISREG(s.st_mode)and s.st_uid==0 and s.st_nlink==1 and stat.S_IMODE(s.st_mode)==0o600 and len(raw)<=512
  master=pathlib.Path('/var/lib/panel/credential-key').read_bytes();assert len(master)==32
  token=hmac.new(master,('yunzhan-analytics-ingress-v1\x00'+sid).encode(),hashlib.sha256).hexdigest()
  assert token.encode()in raw and b'$remote_addr;'in raw
  assert hashlib.sha256(('yunzhan-analytics-include-v1\x00'+token).encode()).hexdigest()==identity
  conf=pathlib.Path('/etc/panel/sites-enabled')/(sid+'.conf');assert str(path)in conf.read_text()and token.encode()not in conf.read_bytes()
  cfg=config('identity-public-config-'+phase+'-'+sid,sid)
  tracker=http.client.HTTPConnection('127.0.0.1',19101,timeout=10)
  try:
   tracker.request('GET','/__yunzhan/analytics/tracker.js?'+urllib.parse.urlencode({'site':sid,'key':cfg['key']}),headers={'Host':site['domain']})
   response=tracker.getresponse();body=response.read((2<<20)+1);assert response.status==200 and len(body)<=2<<20
  finally:tracker.close()
  save('public-tracker-'+phase+'-'+sid+'.json',{'HTTP_status':response.status,'bytes':len(body),'sha256':hashlib.sha256(body).hexdigest(),'private_token_or_master_exposed':token.encode()in body or master in body})
  assert token.encode()not in body and master not in body and b'var webVitals='in body and b'const config='in body
  result={'path':str(path),'identity':identity,'mode':s.st_mode,'uid':s.st_uid,'gid':s.st_gid,'ino':s.st_ino,'dev':s.st_dev,'links':s.st_nlink,'bytes':s.st_size,'mtime_ns':s.st_mtime_ns,'ctime_ns':s.st_ctime_ns,'sha256':hashlib.sha256(raw).hexdigest()}
  save('original-private-identity-'+phase+'-'+sid+'.json',result)
  return result
 original_events=dbrows(site_id);assert len(original_events)==2 and all('client_address'not in x[1]for x in original_events)
 oldcfg=config('original231-legacy-config',site_id);assert oldcfg['enabled']and oldcfg['client_address_mode']=='legacy_proxy'
 vhost=pathlib.Path('/etc/panel/sites-enabled')/(site_id+'.conf');original_vhost=vhost.read_bytes();assert b'analytics-ingress'not in original_vhost
 module=pathlib.Path('/etc/panel/security-apps/modules/website-analytics');installed=json.loads((module/'installed.json').read_bytes())
 if continuation is None:
  assert installed['version']=='2.3.1'
  history={n:(module/n).read_bytes()for n in['history.json','history.sqlite','last-report.json']if(module/n).exists()}
  cat=api('signed232-update-offered','/app-registry?refresh=1');assert len(cat['catalog']['apps'])==50 and not cat['source']['stale']
  item=next(x for x in cat['catalog']['apps']if x['id']=='website-analytics');status=next(x for x in cat['status']if x['id']=='website-analytics')
  assert item['version']=='2.3.2'and item['sha256']==APP_SHA and status['state_known']and status['installed_version']=='2.3.1'and status['update_available']
  reply=api('one-signed232-app-update','/app-registry/website-analytics/update',{'expected_version':'2.3.2','expected_sha256':APP_SHA},202,secrets.token_hex(16))
  row=wait_job('signed232-app-update',reply['job_id'],'runtime_jobs');assert row['kind']=='software_update';jobs.append(row['id'])
  current=json.loads((module/'installed.json').read_bytes());assert current['version']=='2.3.2'and current['installed_at']==installed['installed_at']and all((module/n).read_bytes()==raw for n,raw in history.items())
  assert dbrows(site_id)==original_events and vhost.read_bytes()==original_vhost
  cat=api('actual232-no-repeat-update','/app-registry?refresh=1');status=next(x for x in cat['status']if x['id']=='website-analytics');assert status['state_known']and status['installed_version']=='2.3.2'and not status['update_available']
  cfg=config('232-still-legacy-config',site_id);assert cfg['revision']==oldcfg['revision']and cfg['key']==oldcfg['key']and cfg['client_address_mode']=='legacy_proxy'
  host='qa-c53-managed-'+nonce[:12]+'.example.test'
  reply=api('one-managed-control-site-create','/sites',{'name':'C53 managed collector native control','slug':'qa-c53-managed-'+nonce[:12],'domain':host,'php_version_id':''},202,secrets.token_hex(16))
  row=wait_job('managed-control-site-create',reply['job_id'],'jobs');other=row['site_id'];jobs.append(row['id']);assert re.fullmatch('[a-f0-9]{32}',other)
  managed=configure('managed-control-enable',other,True);assert managed['client_address_mode']=='managed_proxy'
 else:
  assert installed['version']=='2.3.2'and set(continuation)=={'control_site_id','control_domain','app_update_job','create_site_job','control_enable_job'}
  originals=[]
  for identity,table,kind in[(continuation['app_update_job'],'runtime_jobs','software_update'),(continuation['create_site_job'],'jobs','create_site'),(continuation['control_enable_job'],'jobs','configure_site')]:
   assert re.fullmatch('[a-f0-9]{32}',identity)
   with contextlib.closing(sqlite3.connect('file:/var/lib/panel/panel.db?mode=ro',uri=True,timeout=5))as db:
    db.row_factory=sqlite3.Row;db.execute('PRAGMA query_only=ON');row=dict(db.execute('SELECT *FROM '+table+' WHERE id=?',(identity,)).fetchone())
   assert row['state']=='succeeded'and not row['error']and row['kind']==kind
   originals.append(row);jobs.append(identity)
  assert originals[0]['target_id']=='website-analytics'and json.loads(originals[0]['payload'])['version']=='2.3.2'
  other=continuation['control_site_id'];host=continuation['control_domain'];assert re.fullmatch('[a-f0-9]{32}',other)and all(x['site_id']==other for x in originals[1:])
  save('successful-original-update-and-control-jobs-reused-without-replay.json',originals)
  cat=api('existing232-no-repeat-update','/app-registry?refresh=1');assert len(cat['catalog']['apps'])==50 and not cat['source']['stale']
  status=next(x for x in cat['status']if x['id']=='website-analytics');item=next(x for x in cat['catalog']['apps']if x['id']=='website-analytics')
  assert status['state_known']and status['installed_version']=='2.3.2'and not status['update_available']and item['version']=='2.3.2'and item['sha256']==APP_SHA
  cfg=config('existing232-primary-still-legacy',site_id);assert cfg==oldcfg
  control=api('existing-owned-control-site','/sites/'+other+'/settings');assert control['domain']==host and control['status']=='running'and control['settings']['web_server']=='nginx'
  managed=config('existing-owned-control-enabled',other);assert managed['enabled']and managed['revision']==1 and managed['client_address_mode']=='managed_proxy'and re.fullmatch('[a-f0-9]{32}',managed['key'])
 other_private=private_state(other,'initial')
 start=time.time()
 if int(start)%60>15:
  delay=61-int(start)%60;save('real-minute-window-wait.json',{'seconds':delay,'bounded':True});time.sleep(delay)
 started=time.time();initial=event('/managed-before-churn')
 require204('managed-before-churn',other,host,managed['key'],'127.0.0.61',initial)
 for i in range(2047):
  delay=started+(i+1)*.015-time.time()
  if delay>0:time.sleep(delay)
  body=event('/legacy-churn');body['visitor']=format(i+1,'032x')
  require204('legacy-churn-'+str(i),site_id,domain,cfg['key'],'127.0.0.51',body,{'User-Agent':'OwnedNativeValidationBot'})
  if(i+1)%256==0:save('live-churn-progress-'+str(i+1)+'.json',{'actual_completed':i+1,'at':time.time()})
 assert int(started)//60==int(time.time())//60
 require204('fresh-other-managed-after-churn',other,host,managed['key'],'127.0.0.62',event('/managed-after-churn'))
 require204('existing-other-managed-after-churn',other,host,managed['key'],'127.0.0.61',event('/managed-existing-after-churn'))
 require204('fresh-other-legacy-after-churn',other,host,managed['key'],'127.0.0.63',event('/unknown-proxy-other-site'),direct_loopback=True)
 assert dbrows(site_id)==original_events
 unverified=event('/current-legacy-coverage');require204('new-legacy-unknown-sample',site_id,domain,cfg['key'],'127.0.0.52',unverified)
 rows=dbrows(site_id);assert len(rows)==3 and next(json.loads(x[1])for x in rows if x[0]==unverified['id'])['client_address_source']=='unknown_proxy'
 cfg=configure('primary-explicit-managed-enable',site_id,True);assert cfg['client_address_mode']=='managed_proxy';private=private_state(site_id,'initial')
 sent=[]
 for i,address in enumerate(['127.0.0.31','127.0.0.32','127.0.0.31']):
  body=event('/managed-'+str(i));body['client_address_hash']='a'*64;body['client_address_source']='direct'
  require204('managed-spoof-isolated-'+str(i),site_id,domain,cfg['key'],address,body,{'X-Yunzhan-Analytics-Proxy':'owned-forged-token','X-Yunzhan-Analytics-Client-IP':'203.0.113.200','X-Forwarded-For':'203.0.113.201','X-Real-IP':'203.0.113.202','Cookie':'owned-never-forward'});sent.append((body['id'],address))
 rows=dbrows(site_id);assert len(rows)==6
 hashes=[]
 for identity,address in sent:
  raw=next(x[1]for x in rows if x[0]==identity);v=json.loads(raw);assert v['client_address_source']=='managed_proxy'and len(v['client_address_hash'])==64 and v['client_address_hash']!='a'*64
  assert all(ip not in raw for ip in['127.0.0.31','127.0.0.32','203.0.113.200','203.0.113.201','203.0.113.202'])
  hashes.append(v['client_address_hash'])
 assert hashes[0]==hashes[2]and hashes[0]!=hashes[1]
 report=api('actual-managed-coverage-report','/analytics/sites/'+site_id+'/report');coverage=report['client_addresses']
 assert report['overview']['pv']==report['overview']['uv']==6 and report['overview']['unique_network_peers']==1
 assert coverage['unique_addresses']==2 and coverage['known_pageviews']==3 and coverage['unknown_pageviews']==3 and coverage['legacy_pageviews']==2
 cfg=configure('primary-one-disable',site_id,False);assert cfg['client_address_mode']=='disabled'and cfg.get('proxy_endpoint','')==''
 assert b'/__yunzhan/analytics/'not in vhost.read_bytes()and pathlib.Path(private['path']).read_bytes()
 s=pathlib.Path(private['path']).lstat();assert s.st_ino==private['ino']and hashlib.sha256(pathlib.Path(private['path']).read_bytes()).hexdigest()==private['sha256']
 cfg=configure('primary-one-reenable',site_id,True);assert private_state(site_id,'reenabled')==private
 cross=event('/same-client-other-site');require204('same-client-address-other-site',other,host,managed['key'],'127.0.0.31',cross)
 cross_value=json.loads(next(x[1]for x in dbrows(other)if x[0]==cross['id']));assert cross_value['client_address_source']=='managed_proxy'and cross_value['client_address_hash']!=hashes[0]
 save('same-client-address-isolated-by-site.json',{'primary_client_address_hash':hashes[0],'other_site_client_address_hash':cross_value['client_address_hash'],'same_actual_client_loopback':'127.0.0.31','site_hashes_differ':True,'request_id':cross['id']})
 cfg=configure('primary-final-disable',site_id,False);configure('control-final-disable',other,False)
 assert send('disabled-Nginx-no-longer-collects',site_id,domain,cfg['key'],'127.0.0.31',event('/disabled-Nginx'))!=204
 assert send('disabled-Core-collector-refused',site_id,domain,cfg['key'],'127.0.0.31',event('/disabled-Core'),direct_loopback=True)==404
 assert len(dbrows(site_id))==6
 before=vhost.read_bytes();sentinel=b'\n# owned C53 manual-edit preservation probe\n';save('owned-manual-config-original.json',{'site_id':site_id,'original_hex':before.hex()})
 try:
  with vhost.open('ab')as f:f.write(sentinel);f.flush();os.fsync(f.fileno())
  changed=vhost.read_bytes();assert changed==before+sentinel
  reply=api('one-manual-edit-refused','/analytics/sites/'+site_id+'/config',{'enabled':True,'clicks':False,'retention_days':30,'revision':cfg['revision'],'auto_inject_html':False},409,secrets.token_hex(16))
  assert vhost.read_bytes()==changed and config('manual-refusal-config-unchanged',site_id)['revision']==cfg['revision']
 finally:
  assert vhost.read_bytes()==before+sentinel
  with vhost.open('wb')as f:f.write(before);f.flush();os.fsync(f.fileno())
  assert vhost.read_bytes()==before
 private_dir=pathlib.Path(private['path']).parent;unknown=private_dir/('owned-c53-unknown-'+nonce+'.keep');assert not os.path.lexists(unknown)
 raw=b'owned unknown inventory retained\n'
 with os.fdopen(os.open(unknown,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600),'wb')as f:f.write(raw);f.flush();os.fsync(f.fileno())
 oldstat=unknown.lstat()
 reply=api('one-unknown-private-inventory-configure','/analytics/sites/'+site_id+'/config',{'enabled':True,'clicks':False,'retention_days':30,'revision':cfg['revision'],'auto_inject_html':False},202,secrets.token_hex(16))
 failed=wait_job('unknown-private-inventory-refused',reply['job_id'],'jobs',wanted='failed');jobs.append(failed['id']);assert failed['error']
 assert unknown.read_bytes()==raw and unknown.lstat().st_ino==oldstat.st_ino and vhost.read_bytes()==before
 actual=config('private-refusal-original-config',site_id);assert not actual['enabled']and actual['revision']==cfg['revision']
 retained=base/unknown.name;assert not retained.exists();os.rename(unknown,retained)
 assert retained.read_bytes()==raw and retained.lstat().st_ino==oldstat.st_ino
 assert all(x in dbrows(site_id)for x in original_events)and len(dbrows(site_id))==6
 save('all-original-live-HTTP-responses.json',requests)
 save('actual-analytics-private-file-metadata.json',{'primary':private,'control':other_private,'unknown_own_sentinel_retained':str(retained)})
 return {'ok':True,'primary_site_id':site_id,'control_site_id':other,'signed_update_from':'2.3.1','signed_update_to':'2.3.2','successful_app_update_and_control_reused_without_replay':continuation is not None,'new_app_update_POSTs':0 if continuation else 1,'new_control_create_and_initial_enable_POSTs':0 if continuation else 2,'normal_installed_Nginx_HTTP_requests':sum(x['transport']=='installed_Nginx'for x in requests),'separate_direct_loopback_Core_HTTP_requests':sum(x['transport']=='direct_loopback_Core'for x in requests),'real_legacy_churn_requests':2047,'actual_other_site_fresh_and_existing_clients_accepted':True,'actual_other_site_headerless_legacy_control_accepted':True,'same_actual_client_address_isolated_between_sites':True,'legacy_events_preserved':2,'final_primary_events':6,'client_address_known':3,'client_address_unknown':3,'client_address_legacy':2,'original_installed_at_and_history_preserved':True,'explicit_disable_removes_site_directive_private_file_retained':True,'disabled_Nginx_and_Core_reject_without_new_events':True,'explicit_reenable_reuses_original_private_identity_inode':True,'manual_edit_refused_without_rewrite':True,'unknown_private_inventory_failed_without_rewrite_or_retry':True,'failed_original_job_retained':failed['id'],'all_jobs':jobs,'both_owned_collectors_finally_disabled':True,'actual_browser_UI_acceptance':False,'Main_changed':False,'all50_commercial':False}

