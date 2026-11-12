import hashlib
import http.client
import http.cookiejar
import http.server
import json
import os
from pathlib import Path
import platform
import re
import secrets
import shutil
import subprocess
import sys
import tempfile
import threading
import time
import urllib.request

os.umask(0o077)
assert os.geteuid()==0 and os.environ['GITHUB_ACTIONS']=='true' and os.environ['GITHUB_REPOSITORY']=='yunzhanlin/yunzhan-apps'
directory=Path(__file__).resolve().parent
plan=json.loads((directory/'cohort.json').read_bytes())
arch={'x86_64':'amd64','aarch64':'arm64'}[platform.machine()]
assert json.loads(Path('/opt/panel/current/SOURCE_INPUTS.json').read_bytes())['inputs_sha256']==plan['source_inputs_sha256']
out=Path(sys.argv[1])/'business-phase1'
out.mkdir(mode=0o700)
module='/app-modules/network-threat-detection'
registry='/app-registry/network-threat-detection'
feed_api='/software/network-threat-detection/rule-feeds'
origin='http://127.0.0.1:19100'
runtime_path=Path('/etc/panel/security-apps/modules/network-threat-detection/native-runtime.json')
configuration=Path('/etc/panel/network-ids/suricata.yaml')
service='panel-network-ids.service'
helper='panel-app-dependencies@network-threat-detection.service'
proof={'ok':False,'architecture':arch,'source_inputs_sha256':plan['source_inputs_sha256'],'Main_changed':False}
csrf=''

class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self,*args,**kwargs):
        raise RuntimeError('Unexpected local redirect')

client=urllib.request.build_opener(urllib.request.ProxyHandler({}),NoRedirect(),
                                   urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))

def save(name,value):
    with (out/name).open('x') as f:
        json.dump(value,f,indent=2)
        f.write('\n')

def api(path,data=None,expected=200,key=None):
    headers={'Origin':origin,'Content-Type':'application/json','X-CSRF-Token':csrf}
    if key is not None:
        headers['Idempotency-Key']=key
    body=None if data is None else json.dumps(data).encode()
    with client.open(urllib.request.Request(origin+'/api'+path,body,headers),timeout=85) as response:
        assert response.status==expected,(path,response.status)
        return json.loads(response.read(6<<20))

def wait(read,ready,timeout):
    until=time.monotonic()+timeout
    while time.monotonic()<until:
        value=read()
        if ready(value):
            return value
        time.sleep(2)
    raise TimeoutError('Original operation did not settle')

def job(label,path,body,timeout=650):
    key=secrets.token_hex(16)
    save(label+'-submitted.json',{'route':path,'request':body,'key':key,'max_posts':1})
    result=api(path,body,202,key)
    save(label+'-accepted.json',result)
    native=path.startswith(module+'/ids-')
    identity=result['id' if native else 'job_id']
    assert re.fullmatch('[a-f0-9]{32}',identity)
    resource=module+'/operations/' if native else '/jobs/'
    row=wait(lambda:api(resource+identity),lambda v:v['state'] in ('succeeded','failed','needs_attention','needs-attention','canceled'),timeout)
    save(label+'-original-result.json',row)
    assert row['state']=='succeeded',label
    if native:
        assert result['action']==row['action']==path.rsplit('/',1)[1] and result['input']==row['input']==body
    return row

def report(data=None):
    return api(module+'/ids-report',data or {})

def revision():
    return (report().get('configuration') or {}).get('revision',0)

def unit(name):
    return subprocess.check_output(['systemctl','show',name,'-p','Result','-p','ActiveState','-p','MainPID','-p','ExecMainStatus',
                                   '-p','ExecMainStartTimestampMonotonic','-p','SubState','-p','LoadState'],
                                   text=True,timeout=12)

def catalogue():
    result=wait(lambda:api('/app-registry?refresh=1'),lambda row:not row['source']['stale'],130)
    assert result['source']['resolved_commit']==plan['served_head']
    assert result['host']=={'platform':'ubuntu-24.04','architecture':arch}
    item=next(row for row in result['catalog']['apps'] if row['id']=='network-threat-detection')
    assert item==plan['items']['network-threat-detection']
    return item,next(row for row in result['status'] if row['id']=='network-threat-detection')

def ensure_vendor_engine():
    before=report()
    assert before['process_verified'] is False and not runtime_path.exists()
    original=unit(helper)
    start_line=lambda value:next(line for line in value.splitlines() if line.startswith('ExecMainStartTimestampMonotonic='))
    save('native-dependency-unit-before.json',{'systemd':original})
    prepare=api(module+'/ids-prepare',{'prepare_ids':True})
    assert prepare['state']=='preparing' and prepare['capture_started'] is False
    save('original-prepare-response.json',prepare)
    try:
        settled=wait(lambda:unit(helper),lambda value: 'ActiveState=failed' in value or
            ('ActiveState=inactive' in value and (runtime_path.is_file() or start_line(value)!=start_line(original))),1250)
    finally:
        final=unit(helper)
        save('native-dependency-unit.json',{'systemd':final,'runtime_record_exists':runtime_path.is_file()})
        with (out/'native-dependency-journal.stdout').open('xb') as stdout, (out/'native-dependency-journal.stderr').open('xb') as stderr:
            subprocess.run(['journalctl','--no-pager','-b','-u',helper,'-n','100','-o','cat'],
                           stdout=stdout,stderr=stderr,timeout=15)
        if not runtime_path.is_file():
            candidates=Path('/opt/panel/app-modules/network-threat-detection')
            files={str(path.relative_to(candidates)): oct(path.lstat().st_mode) for path in
                   sorted(candidates.glob('.prepare-*/candidate/*/*'))[:30]}
            save('native-dependency-candidate-inventory.json',files)
    assert 'Result=success' in settled and 'ExecMainStatus=0' in settled and runtime_path.is_file()
    status=report()
    engine=status['engine_support']
    assert status['runtime_ready'] and engine['supported'] and engine['minimum_engine_version']=='8.0.8'
    assert re.fullmatch(r'1:8\.0\.8-[0-9A-Za-z.+~_-]+',engine['package_version'])
    assert status['process_verified'] is False and 'MainPID=0' in unit(service)
    boot = subprocess.run(['systemctl','is-enabled',service],capture_output=True,text=True,timeout=12)
    assert boot.stdout.strip() in ('disabled','static')
    native=json.loads(runtime_path.read_bytes())
    assert native['package']['version']==engine['package_version'] and native['package']['architecture']==arch
    assert native['source']['repository_url']=='https://ppa.launchpadcontent.net/oisf/suricata-stable/ubuntu' and native['source']['suite']=='noble'
    proof['engine_package']=engine['package_version']
    proof['vendor_source_pinned']=True
    return native

class Marker(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header('Content-Length','2')
        self.end_headers()
        self.wfile.write(b'OK')

    do_TRACE=do_GET

    def log_message(self,*args):
        pass

def test_capture():
    config=job('native-config',module+'/ids-config',{'expected_revision':revision(),'network_interface':'lo',
               'home_networks':['127.0.0.1/32','::1/128']})
    assert config['action']=='ids-config'
    started=job('native-start',module+'/ids-start',{'expected_revision':revision()})
    try:
        wait(report,lambda r:r['process_verified'],65)
        server=http.server.ThreadingHTTPServer(('127.0.0.1',0),Marker)
        thread=threading.Thread(target=server.serve_forever,daemon=True)
        thread.start()
        try:
            for method in ('GET','GET','TRACE','TRACE'):
                session=http.client.HTTPConnection('127.0.0.1',server.server_port,timeout=5)
                try:
                    session.request(method,'/owned-ids-fixture')
                    reply=session.getresponse()
                    assert reply.status==200 and reply.read()==b'OK'
                finally:
                    session.close()
            result=wait(lambda:report({'search':'TRACE method observed'}),
                        lambda v:any(a['signature_id']==9000004 and a['destination_port']==server.server_port
                                     for a in v['events']['alerts']),95)
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=3)
        assert result['process_verified'] and result['passive_only']
        proof['native_start_job']=started['id']
        proof['original_alert_sid']=9000004
        proof['real_loopback_http_and_passive_alert']=True
    finally:
        stopped=job('native-stop',module+'/ids-stop',{'expected_revision':revision()})
        assert 'ActiveState=inactive' in unit(service) and 'MainPID=0' in unit(service)
        retained=report({'search':'TRACE method observed'})
        assert retained['process_verified'] is False and retained['boot_enabled'] is False
        assert any(a['signature_id']==9000004 for a in retained['events']['alerts'])
        proof['native_stop_job']=stopped['id']

def syntax(native):
    bundle=directory/'rules-data'
    expected=plan['offline_rule_manifest_sha256']
    manifest=json.loads((bundle/'manifest.json').read_bytes())
    assert hashlib.sha256((bundle/'manifest.json').read_bytes()).hexdigest()==expected
    for name,digest in manifest['files_sha256'].items():
        assert hashlib.sha256((bundle/name).read_bytes()).hexdigest()==digest
    fixture=Path(tempfile.mkdtemp(prefix='panel-ids-qa-',dir='/run'))
    fixture.chmod(0o755)
    try:
        for name in ('et-open.rules','classification.config','reference.config'):
            target=fixture/name
            shutil.copyfile(bundle/name,target)
            target.chmod(0o644)
        prefix=Path('/opt/panel/app-modules/network-threat-detection')/native['prefix']
        assert re.fullmatch(r'apt-[a-f0-9]{16}',native['prefix'])
        command=['/usr/sbin/runuser','-u','panel-network-ids','--','/usr/bin/env','-i','PATH=/usr/sbin:/usr/bin:/sbin:/bin',
                 'LANG=C','LD_LIBRARY_PATH='+str(prefix/'libraries'),str(prefix/'bin/suricata'),'-T',
                 '--init-errors-fatal','--strict-rule-keywords','--set','outputs.0.eve-log.enabled=no',
                 '--set','classification-file='+str(fixture/'classification.config'),
                 '--set','reference-config-file='+str(fixture/'reference.config'),'-l','/tmp',
                 '-c',str(configuration),'-S',str(fixture/'et-open.rules')]
        with (out/'native-rules-syntax.stdout').open('xb') as stdout,(out/'native-rules-syntax.stderr').open('xb') as stderr:
            result=subprocess.run(command,stdout=stdout,stderr=stderr,timeout=180)
        assert result.returncode==0
        assert manifest['enabled_rule_count']==1516 and manifest['dependency_rule_count']==2
        proof.update(offline_rules_native_syntax=True,offline_rule_manifest_sha256=expected,rule_count=1516)
    finally:
        shutil.rmtree(fixture)

try:
    auth=json.loads(Path('/etc/panel/first-login.json').read_bytes())
    csrf=api('/login',{key:auth[key] for key in ('username','password')})['csrf']
    auth.clear()
    item,baseline=catalogue()
    assert baseline['state_known'] and baseline['supported'] and not baseline['installed']
    update=plan['mode']=='signed-engine-app-update'
    if update:
        old=job('direct-old-app','/software/network-threat-detection/install',{})
    else:
        assert plan['mode']=='native-vendor-engine' and item['version']=='1.3.1'
        old=job('signed-old-app',registry+'/install',{'expected_version':item['version'],'expected_sha256':item['sha256']})
    assert api(module)['status']['version']=='1.3.1'
    proof['baseline_job']=old['id']
    native=ensure_vendor_engine()
    test_capture()
    syntax(native)
    if update:
        assert item['version']=='1.3.2'
        status=catalogue()[1]
        assert status['update_available'] and status['update_supported']
        preserved={str(p):hashlib.sha256(p.read_bytes()).hexdigest() for p in (configuration,runtime_path)}
        app_job=job('signed-update',registry+'/update',{'expected_version':item['version'],'expected_sha256':item['sha256']})
        assert api(module)['status']['version']=='1.3.2'
        assert preserved=={str(p):hashlib.sha256(p.read_bytes()).hexdigest() for p in (configuration,runtime_path)}
        assert any(a['signature_id']==9000004 for a in report({'search':'TRACE method observed'})['events']['alerts'])
        info=api(feed_api+'?refresh=1')
        row,=info['available']
        assert row['supported']
        selection=row['selection']
        assert selection['app_version']=='1.3.2' and selection['app_manifest_sha256']==item['sha256']
        assert selection['rule_manifest_sha256']==plan['offline_rule_manifest_sha256']
        data=job('signed-open-rule-download',feed_api+'/install',selection)
        assert 'ActiveState=inactive' in unit(service)
        selected=job('signed-open-rule-select',module+'/ids-rules',{'expected_revision':revision(),
                     'rule_profile':{'source':'verified-feed','selection':selection}})
        current=report()
        assert current['rule_profile']['source']=='verified-feed' and current['rule_profile']['selection']==selection
        assert current['process_verified'] is False and current['boot_enabled'] is False
        assert any(a['signature_id']==9000004 for a in report({'search':'TRACE method observed'})['events']['alerts'])
        proof.update(signed_update=app_job['id'],signed_rule_download=data['id'],signed_rule_selection=selected['id'],
                     retained_configuration_runtime_and_alert=True)
    proof['ok']=True
finally:
    try:
        if csrf:
            api('/logout',{})
    finally:
        save('original-proof.json',proof)
