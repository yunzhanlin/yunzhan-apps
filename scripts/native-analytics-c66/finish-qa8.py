"""Independently reconcile original browser, report and113 tables; encrypt evidence."""
import collections,datetime,hashlib,json,math,os,pathlib,re,runpy,stat,subprocess,sys,tarfile,traceback
os.umask(0o077)
assert os.geteuid()==0 and len(sys.argv)==3
source=pathlib.Path(__file__).resolve().parent;private=pathlib.Path(sys.argv[1]).resolve(strict=True);public=pathlib.Path(sys.argv[2]).resolve(strict=True);owner=public.stat()
assert os.environ.get('GITHUB_ACTIONS')=='true'and os.environ.get('GITHUB_REPOSITORY')=='yunzhanlin/yunzhan-apps'
read=lambda p:json.loads(pathlib.Path(p).read_bytes());sha=lambda p:hashlib.sha256(pathlib.Path(p).read_bytes()).hexdigest()
def save(name,value):
 with(private/name).open('x')as f:json.dump(value,f,indent=2,sort_keys=True);f.write('\n');f.flush();os.fsync(f.fileno())
proof={'ok':False,'all50_commercial':False,'Main_changed':False,'evidence_profile':'fresh full native GitHub Linux host, normal signed programme and app install; separate from retained local production-upgrade witnesses','original_outcomes_replayed':False}
try:
 capture=subprocess.run(['/usr/bin/python3','-I','-B',str(source/'snapshot.py'),str(private/'original-after-browser.json')],capture_output=True,timeout=60)
 save('original-after-browser-capture-outcome.json',{'exit':capture.returncode,'stdout_hex':capture.stdout.hex(),'stderr_hex':capture.stderr.hex()});assert capture.returncode==0
 preparation=read(private/'original-preparation-proof.json');browser=read(private/'browser-original-proof.json');setup=read(private/'browser-setup.json')
 mobile=read(private/'original-mobile133-normal-install-and-report-proof.json');assert mobile['ok']and mobile['architecture']==setup['architecture']and mobile['source_inputs_sha256']==setup['source_inputs_sha256']and mobile['original_install_POSTs']==mobile['original_report_POSTs']==1 and mobile['normal_original_install_version']=='1.3.3'and mobile['all_three_original_native_artifact_links_and_digests_verified']and mobile['source_overlays']==0

 assert preparation['ok']and browser['ok']and browser['actual_BFCache']and browser['actual_narrow_viewport']and browser['BFCache_restored_documents']==2
 assert preparation['source_inputs_sha256']==browser['source_inputs_sha256']==setup['source_inputs_sha256']=='7ae19475cac7a31941533befe97d6288eabcc6f5b8a0ea9b83e3feadc3e8fdda'
 a=read(private/'original-before-browser.json');b=read(private/'original-after-browser.json')
 for key in('schema','boot','files','NSS','units'):assert a[key]==b[key],key
 rows=lambda value,name:[dict(zip(value['tables'][name]['columns'],r))for r in value['tables'][name]['rows']]
 serial=lambda v:json.dumps(v,sort_keys=True,separators=(',',':'))
 def extra(name):
  old=collections.Counter(serial(v)for v in rows(a,name));new=collections.Counter(serial(v)for v in rows(b,name));assert not old-new,name
  return[json.loads(v)for v in(new-old).elements()]
 def stamp(v):return datetime.datetime.fromisoformat(v.replace('Z','+00:00')).timestamp()if isinstance(v,str)else v
 def between(v):assert a['at']-2<=stamp(v)<=b['at']+2
 explicit={'analytics_events','analytics_budget','audit_logs','login_events','sessions','runtime_installations'}
 delta=runpy.run_path(str(source/'background.py'))['qualify_background'](a,b,explicit=explicit)
 events=extra('analytics_events');assert not rows(a,'analytics_events')and len(events)>50 and all(e['site_id']==setup['site']for e in events)
 assert len({v['id']for v in events})==len(events)and len({v['visitor']for v in events})==len({v['session']for v in events})==1
 data=[json.loads(row['data'])for row in events]
 for row,event in zip(events,data):
  between(row['received']);assert event['id']==row['id']and event['kind']==row['kind']and event['path']==row['path']and event['visitor']==row['visitor']and event['session']==row['session']and event['received_at']==row['received']and event['client_address_source']=='managed_proxy'
  assert re.fullmatch('[0-9a-f]{64}',row['visitor'])and re.fullmatch('[0-9a-f]{64}',row['session'])
  assert 'C66_SYNTHETIC_PRIVATE_INPUT_'not in row['data']and 'c66-private-target-'not in row['data']
 requests=read(private/'browser-original-collector-requests.json');sent=[json.loads(v['original_body_utf8'])for v in requests]
 assert len({v['id']for v in sent})==len(sent)==len(events)and {v['id']for v in sent}=={v['id']for v in data}
 for received in data:
  original=next(v for v in sent if v['id']==received['id'])
  for name in('kind','path','page_id'):assert received[name]==original[name]
  assert received.get('navigation_seq',0)==original.get('navigation_seq',0)
  if original['kind']!='pageview':assert 'navigation_seq'not in original and received.get('navigation_seq',0)==0
 pv=sorted((v for v in data if v['kind']=='pageview'),key=lambda v:v['navigation_seq'])
 journey=['/a.html','/b.html','/a.html','/b.html','/a.html']
 assert [v['navigation_seq']for v in pv]==list(range(1,6))and [v['path']for v in pv]==journey and len({v['page_id']for v in pv})==5
 assert all(v['page_id']in{p['page_id']for p in pv}for v in data)
 for restored in(3,4):
  samples=[v for v in data if v['kind']=='performance'and v['page_id']==pv[restored-1]['page_id']];assert samples
  assert all(v['ttfb']==v['fcp']==v['lcp']==0 for v in samples),'Restored visits must not reuse original document load timings'
 states=read(private/'browser-original-visitor-states.json');assert len(states)==5
 for first,restored in((0,2),(1,3)):
  assert states[first]['state']['document_instance']==states[restored]['state']['document_instance']and states[restored]['state']['last_pageshow_persisted']is True and states[restored]['state']['restored_shows']==1
 assert states[4]['state']['document_instance']!=states[0]['state']['document_instance']and states[4]['state']['last_pageshow_persisted']is False
 intents=read(private/'browser-original-pointer-intents.json');planned=collections.Counter()
 for v in intents:
  g=v['geometry'];assert g['width']==g['height']==g['document_width']==g['document_height']==1000
  planned[(g['path'],math.floor((v['x']+g['scroll_x'])/10/5)*5,math.floor((v['y']+g['scroll_y'])/10/5)*5)]+=1
 clicks=collections.Counter((v['path'],math.floor(v['x']/5)*5,math.floor(v['y']/5)*5)for v in data if v['kind']=='click');assert planned==clicks and sum(clicks.values())==len(intents)
 report=read(private/'browser-original-report-0001.json');assert report['status']==200;report=json.loads(report['raw_utf8'])
 assert {key:report['overview'][key]for key in('pv','uv','sessions','clicks')}=={'pv':5,'uv':1,'sessions':1,'clicks':len(intents)}
 assert len(report['sessions'])==1 and report['sessions'][0]['journey']==journey and report['sessions'][0]['page_order_source']=='browser-navigation-sequence'and report['sessions'][0]['page_order_uncertain']is False
 heat=collections.Counter({(v['path'],v['x'],v['y']):v['count']for v in report['heatmap']});assert heat==clicks
 expected=sorted((v for v in report['heatmap']if v['path']=='/a.html'),key=lambda p:(-p['count'],p['x'],p['y']))
 for label,subset in [('desktop-A-first20',expected[:20]),('390-A-first20',expected[:20]),('390-A-second20',expected[20:40]),('390-A-last',expected[40:]),('390-A-path-reset-first20',expected[:20])]:
  dom=read(private/('browser-original-'+label+'-DOM.json'));drawn=collections.Counter({('/a.html',float(v['cx'])-2.5,float(v['cy'])-2.5):int(re.search(r'：([0-9]+) 次点击',v['title']).group(1))for v in dom['circles']});assert drawn==collections.Counter({k:v for k,v in clicks.items()if k[0]=='/a.html'})
  assert dom['rows']==[[str(v['x'])+'–'+str(min(100,v['x']+5))+'%',str(v['y'])+'–'+str(min(100,v['y']+5))+'%',str(v['count'])]for v in subset]
  assert abs(dom['svg']['width']-dom['svg']['height'])<1
  if label.startswith('390-'):
   viewport=dom['viewport'];assert viewport['width']==390 and viewport['height']==844 and 0<viewport['document_width']<=viewport['document_client_width']<=390
   assert dom['workspace']['x']>=0 and dom['workspace']['x']+dom['workspace']['width']<=viewport['document_client_width']+1 and dom['svg']['width']<=viewport['document_client_width']
 invalid=read(private/'browser-original-narrow-invalid-query.json');assert invalid['stale_heatmap_table']==invalid['stale_totals']==invalid['stale_path_selector']==0 and invalid['export_disabled']
 assert rows(a,'analytics_budget')==[{'id':1,'events':0}]and rows(b,'analytics_budget')==[{'id':1,'events':len(events)}]
 audits=extra('audit_logs');logins=extra('login_events');sessions=rows(b,'sessions')
 assert len(audits)==len(logins)==len(sessions)==1 and not rows(a,'sessions')
 assert audits[0]['actor']=='admin'and audits[0]['action']=='auth.login'and audits[0]['result']=='success'and audits[0]['target']=='account';between(audits[0]['created_at'])
 assert logins[0]['username']=='admin'and logins[0]['result']=='success'and logins[0]['ip']=='127.0.0.1';between(logins[0]['created_at'])
 admin_id=next(v['id']for v in rows(a,'users')if v['username']=='admin');session=sessions[0]
 assert session['user_id']==admin_id and re.fullmatch('[0-9a-f]{64}',session['token_hash'])and len(session['csrf'])>=32;between(session['expires_at']-43200);between(session['last_activity_at'])
 old_runtime={v['id']:v for v in rows(a,'runtime_installations')};new_runtime={v['id']:v for v in rows(b,'runtime_installations')};assert old_runtime.keys()==new_runtime.keys()
 for key,v in new_runtime.items():
  original=old_runtime[key];copy=dict(v);copy['detected_at']=original['detected_at'];assert copy==original
  if v!=original:between(v['detected_at'])
 original=setup['stock_Nginx_witness'];retained=pathlib.Path(setup['stock_Nginx_retained']);st=retained.lstat();assert sha(retained)==original['sha256']and st.st_ino==original['inode']and st.st_uid==original['uid']and st.st_gid==original['gid']and st.st_dev==original['dev']and stat.S_IMODE(st.st_mode)==original['mode']
 save('original-independent-reconciliation.json',{'ok':True,'actual_PV':5,'actual_clicks':len(intents),'actual_UV':1,'actual_sessions':1,'actual_new_events':len(events),'journey':journey,'actual_two_document_BFCache_restores':True,'all_pointer_coordinates_equal_raw_rows_report_and_rendered_details':True,'BFCache_new_page_ids_monotonic_sequence_and_no_reused_load_timings':True,'all113_original_tables_schema_protected_files_NSS_and_native_lifetimes_qualified':True,'source_bound_background_delta':delta,'actual_390_by844_and_pagination_and_stale_query_fences':True,'original_distribution_Nginx_bytes_and_inode_preserved':True})
 proof.update(ok=True,architecture=setup['architecture'],version=setup['version'],source_inputs_sha256=setup['source_inputs_sha256'],normal_signed_programme_installs=1,normal_signed_analytics242_installs=1,normal_signed_mobile133_installs=1,actual_mobile133_native_report_and_three_links=True,original_installed_programme_entries=preparation['installed_programme_entries'],actual_BFCache_restores=2,actual_PV=5,actual_UV=1,actual_sessions=1,actual_clicks=len(intents),actual_new_events=len(events),actual_390_by844=True,all113_original_tables_independently_qualified=True,normal_production_upgrade_acceptance=False)
except BaseException:save('original-independent-reconciliation-failure.json',{'traceback':traceback.format_exc()})
finally:
 try:
  cert=source/'recipient.pem';assert sha(cert)=='55ac5d4129117009583d47c47442bd07cc1de997e6a2a10b5652b3cb7fa54495'
  envelope=private/'original-private-evidence.tar.gz';included=[]
  with tarfile.open(envelope,'x:gz')as tar:
   for f in sorted(private.iterdir()):
    if f.name in('browser-credentials.json',envelope.name)or f.suffix not in('.json','.png','.log','.stdout','.stderr'):continue
    st=f.lstat();assert stat.S_ISREG(st.st_mode)and st.st_nlink==1 and stat.S_IMODE(st.st_mode)==0o600 and st.st_size<32<<20
    tar.add(f,arcname=f.name,recursive=False);included.append({'name':f.name,'sha256':sha(f),'bytes':st.st_size})
  encrypted=public/'original-private-evidence.cms'
  r=subprocess.run(['openssl','cms','-encrypt','-binary','-aes-256-gcm','-in',str(envelope),'-outform','DER','-out',str(encrypted),'-recip',str(cert),'-keyopt','rsa_padding_mode:oaep','-keyopt','rsa_oaep_md:sha256'],capture_output=True,timeout=90);assert r.returncode==0
  os.chown(encrypted,owner.st_uid,owner.st_gid);proof['private_evidence']={'encrypted':True,'sha256':sha(encrypted),'bytes':encrypted.stat().st_size,'plaintext_sha256':sha(envelope),'plaintext_bytes':envelope.stat().st_size,'original_files':len(included),'certificate_sha256':sha(cert),'first_login_file_browser_credentials_and_browser_profile_excluded':True}
 except BaseException:proof['ok']=False;proof['private_evidence_encryption_failed']=True;save('original-evidence-encryption-failure.json',{'traceback':traceback.format_exc()})
 with(public/'original-public-proof.json').open('x')as f:json.dump(proof,f,indent=2);f.write('\n')
 os.chown(public/'original-public-proof.json',owner.st_uid,owner.st_gid)
 print(json.dumps(proof))
sys.exit(0 if proof['ok']else 1)
