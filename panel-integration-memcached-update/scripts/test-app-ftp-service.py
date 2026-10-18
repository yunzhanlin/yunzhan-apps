#!/usr/bin/env python3
"""Real FTPS configuration, TLS-data enforcement and failure/recovery proof."""
import copy,hashlib,json,os,pathlib,time,uuid
from panel_client import PanelClient
assert os.environ.get('PANEL_VM') in ('panel-compat-ubuntu24','panel-store-apps-debian13'),'Isolated QA only'
root=pathlib.Path(__file__).resolve().parents[1];state=root/os.environ.get('FTP_QA_STATE','.local/ftp-service-qa.json');assert not state.exists()
p=PanelClient();p.timeout=70
v={'sites':[],'username':'qa-ftp-'+uuid.uuid4().hex[:8],'passed':False,'checks':[]};created=False;original=None
def save():state.write_text(json.dumps(v,indent=2)+'\n');state.chmod(0o600)
def module(action='run',**body):return p.api('/app-modules/pure-ftpd/'+action,body)
def passed(message):v['checks'].append(message);save();print('PASS',message,flush=True)
def rejected(call):
 try:call()
 except RuntimeError as e:assert 'HTTP 409' in str(e),e;return
 raise AssertionError('Unsafe or stale config accepted')
def snapshot():
 return p.vm('sudo','sha256sum','/etc/panel/security-apps/modules/pure-ftpd/server.pem','/etc/panel/security-apps/modules/pure-ftpd/users.passwd','/etc/panel/security-apps/modules/pure-ftpd/users.pdb').stdout
def configure(c,**extra):
 body=copy.deepcopy(c);body['expected_revision']=body.pop('revision');body.update(extra);return module('service-config',**body)
def transfer(c,mode='roundtrip'):
 code="""import ftplib,io,json,ssl,sys
v=json.load(sys.stdin);context=ssl.create_default_context(cafile=v['ca']);mode=v['mode']
f=ftplib.FTP_TLS(context=context);f.connect(v['address'],v['port'],timeout=10);f.host=v['domain'] if mode!='wrong-host' else 'wrong.example.test'
if mode=='wrong-host':
 try:f.auth()
 except ssl.SSLCertVerificationError:print('PASS');sys.exit(0)
 raise AssertionError('Wrong certificate hostname accepted')
f.login(v['username'],v['password'])
if mode=='clear-data':
 try:f.retrbinary('RETR ftp-proof.txt',lambda _:None)
 except ftplib.error_perm as e:assert str(e).startswith(('521','522','550'));print('PASS');sys.exit(0)
 raise AssertionError('Clear data channel accepted')
if mode=='pasv':
 host,port=ftplib.parse227(f.sendcmd('PASV'));assert host==v['advertised'] and v['passive_start']<=port<=v['passive_end'];f.quit();print('PASS');sys.exit(0)
f.prot_p();f.storbinary('STOR ftp-proof.txt',io.BytesIO(b'real-ftps-config-roundtrip'));out=io.BytesIO();f.retrbinary('RETR ftp-proof.txt',out.write);assert out.getvalue()==b'real-ftps-config-roundtrip' and f.pwd()=='/';f.quit();print('PASS')"""
 return p.vm('sudo','python3','-c',code,input=json.dumps({'mode':mode,'ca':os.environ['FTP_QA_CA'],'address':'127.0.0.1' if c['bind_address']=='0.0.0.0' else c['bind_address'],'port':c['port'],'domain':c['domain'],'username':v['username'],'password':secret,'advertised':c['passive_address'],'passive_start':c['passive_start'],'passive_end':c['passive_end']})).stdout
try:
 save();status=p.api('/app-modules/pure-ftpd')['status'];assert status['installed'] and status['healthy']
 original=module()['config'];v['original']=original;save()
 certificate=json.loads(pathlib.Path(os.environ['FTP_QA_CERTIFICATE_FILE']).read_text())
 cert=p.api('/certificates',{'name':'QA FTPS '+uuid.uuid4().hex[:8],'certificate_pem':certificate['certificate_pem'],'private_key_pem':certificate['private_key_pem']})
 slug='ftp-service-'+uuid.uuid4().hex[:8];p.wait(p.api('/sites',{'name':slug,'slug':slug,'domain':slug+'.example.test','php_version_id':''})['job_id'],timeout=180)
 site=next(s['id'] for s in p.api('/sites') if s['slug']==slug);v['sites'].append(site);save();secret='FTPS-'+uuid.uuid4().hex
 module('create',site_id=site,username=v['username'],password=secret);created=True
 c=copy.deepcopy(original);c.update({'bind_address':'127.0.0.1','port':22212,'passive_start':31000,'passive_end':31009,'passive_address':'127.0.0.1','certificate_id':cert['id'],'domain':'ftps-qa.example.test','max_clients':20,'max_per_ip':4,'idle_minutes':15})
 result=configure(c);c=result['config'];assert result['restart_verified'] and result['certificate']['trusted'] and result['firewall_changed'] is False
 assert transfer(c).strip()=='PASS';assert transfer(c,'wrong-host').strip()=='PASS';assert transfer(c,'clear-data').strip()=='PASS'
 assert module('probe')['tls_verified'];passed('actual trusted hostname FTPS upload/download/chroot, wrong-host rejection and mandatory encrypted data channel')
 before=snapshot();rejected(lambda:configure(original));assert snapshot()==before
 public=copy.deepcopy(c);public['bind_address']='0.0.0.0';rejected(lambda:configure(public));assert snapshot()==before
 public=configure(public,confirm='EXPOSE FTPS 0.0.0.0:22212')['config'];assert transfer(public).strip()=='PASS';c=public
 passed('stale/external-without-ack rejection preserves users/certificate; explicit IPv4 wildcard listener and valid trusted certificate actually serve FTPS')
 nat=copy.deepcopy(c);nat['passive_address']='203.0.113.123';c=configure(nat,confirm='EXPOSE FTPS 0.0.0.0:22212')['config'];assert transfer(c,'pasv').strip()=='PASS'
 c['passive_address']='127.0.0.1';c=configure(c,confirm='EXPOSE FTPS 0.0.0.0:22212')['config'];assert transfer(c).strip()=='PASS'
 passed('real PASV reply reflects configured NAT address and exact passive port range; restored local transfer works')
 unit='panel-qa-ftp-conflict-'+uuid.uuid4().hex[:8]
 p.vm('sudo','systemd-run','--unit='+unit,'--property=User=nobody','--property=Group=nogroup','/usr/bin/python3','-c','import socket,time;s=socket.socket();s.bind(("127.0.0.1",22213));s.listen();time.sleep(180)')
 try:
  time.sleep(.5);before=snapshot();bad=copy.deepcopy(c);bad['port']=22213
  rejected(lambda:configure(bad,confirm='EXPOSE FTPS 0.0.0.0:22213'))
  assert module()['config']==c and snapshot()==before and transfer(c).strip()=='PASS'
  assert p.vm('sudo','systemctl','is-active',unit).stdout.strip()=='active'
  passed('real occupied-port start failure restores exact old config/certificate and active FTPS; unrelated listener retained')
 finally:p.vm('sudo','systemctl','stop',unit)
 module('stop');stopped=module();assert not stopped['service_active'] and not stopped['boot_enabled']
 c['bind_address']='127.0.0.1';c['port']=22214;result=configure(c);c=result['config'];assert not result['service_active'] and not result['restart_verified'] and not module()['service_active']
 module('start');assert transfer(c).strip()=='PASS';passed('intentional stop survives configuration save; explicit start uses persisted new settings and retains account')
 # Inject the actual persisted pre-commit boundary, then run the same fixed
 # recovery unit used at boot. No production configuration is touched.
 recovery="""import base64,hashlib,json,pathlib,uuid
p=pathlib.Path('/etc/panel/security-apps/modules/pure-ftpd');old=(p/'service.json').read_bytes();pem=(p/'server.pem').read_bytes();next=json.loads(old);next['revision']+=1;next['port']=22215;raw=json.dumps(next).encode()
job={'id':uuid.uuid4().hex,'state':'applying','old_config':base64.b64encode(old).decode(),'old_config_exists':True,'old_pem':base64.b64encode(pem).decode(),'next_config_sha':hashlib.sha256(raw).hexdigest(),'next_pem_sha':hashlib.sha256(pem).hexdigest(),'was_active':True,'time':'QA pre-commit injection'}
target=p/'pending-service.json';assert not target.exists();target.write_text(json.dumps(job));target.chmod(0o600);(p/'service.json').write_bytes(raw);(p/'service.json').chmod(0o600);print(job['id'])"""
 backup=p.vm('sudo','python3','-c',recovery).stdout.strip();p.vm('sudo','systemctl','restart','panel-pure-ftpd-recover.service');p.vm('sudo','systemctl','restart','panel-pure-ftpd.service')
 assert module()['config']==c and not module()['recovery_pending'] and transfer(c).strip()=='PASS'
 assert p.vm('sudo','test','-f','/etc/panel/security-apps/modules/pure-ftpd/service-transactions/'+backup+'.json').returncode==0
 assert secret not in json.dumps(p.api('/app-modules/pure-ftpd/history'))
 passed('actual fixed boot-recovery unit restores interrupted journal boundary; root-only backups retained and history excludes credentials')
 v['passed']=True;save()
finally:
 if original is not None:
  current=module()['config'];restore=copy.deepcopy(original);restore['revision']=current['revision'];configure(restore,confirm='EXPOSE FTPS '+restore['bind_address']+':'+str(restore['port']) if restore['bind_address']!='127.0.0.1' else '')
 if created:module('delete',username=v['username'])
 for id in v['sites']:
  own=next((s for s in p.api('/sites') if s['id']==id),None)
  if own:assert own['slug'].startswith('ftp-service-');p.wait(p.api('/sites/'+id,{'confirm_domain':own['domain']},method='DELETE')['job_id'],timeout=180)
 v['cleaned_up']=True;save();p.close()
