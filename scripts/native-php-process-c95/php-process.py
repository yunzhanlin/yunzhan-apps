"""Exercise signed Load Balance 1.9.0 and site settings through ordinary panel APIs."""
from pathlib import Path
import contextlib
import hashlib
import http.client
import http.cookiejar
import http.server
import json
import os
import platform
import re
import secrets
import socket
import sqlite3
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request

os.umask(0o077)
assert os.geteuid() == 0 and os.environ['GITHUB_ACTIONS'] == 'true'
assert os.environ['GITHUB_REPOSITORY'] == 'yunzhanlin/yunzhan-apps'
evidence = Path(sys.argv[1])/'business-phase1'
evidence.mkdir(mode=0o700)
plan = json.loads((Path(__file__).resolve().parent/'cohort.json').read_bytes())
source = json.loads(Path('/opt/panel/current/SOURCE_INPUTS.json').read_bytes())['inputs_sha256']
assert source == plan['source_inputs_sha256']
arch = {'x86_64':'amd64', 'aarch64':'arm64'}[platform.machine()]
origin = 'http://127.0.0.1:19100'
module = '/app-modules/load-balance'
csrf = ''
proof = {'ok':False, 'architecture':arch, 'source_inputs_sha256':source, 'Main_changed':False, 'all50_commercial':False}

def save(name, value):
    with (evidence/name).open('x') as f:
        json.dump(value,f,indent=2)
        f.write('\n')

class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self,*args,**kwargs):
        raise RuntimeError('unexpected control redirect')

client = urllib.request.build_opener(urllib.request.ProxyHandler({}),NoRedirect(),
    urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))

def api(route, body=None, status=200, key=None):
    headers = {'Origin':origin, 'Content-Type':'application/json','X-CSRF-Token':csrf}
    if key:
        headers['Idempotency-Key'] = key
    request = urllib.request.Request(origin+'/api'+route, None if body is None else json.dumps(body).encode(), headers)
    try:
        with client.open(request,timeout=60) as response:
            assert response.status == status, (route, response.status)
            return json.loads(response.read(8<<20))
    except urllib.error.HTTPError as exc:
        raw = exc.read(4096)
        assert exc.code == status, (route, exc.code, raw)
        return json.loads(raw)

def job(label, route, body, status='succeeded', timeout=180):
    key = secrets.token_hex(16)
    save(label+'-intent.json',{'route':route,'body':body,'idempotency_key':key})
    jid = api(route,body,202,key)['job_id']
    assert re.fullmatch('[a-f0-9]{32}', jid)
    deadline = time.monotonic()+timeout
    while time.monotonic()<deadline:
        row = api('/jobs/'+jid)
        if row['state'] in ('succeeded','failed','needs_attention','cancelled'):
            save(label+'-outcome.json',row)
            assert row['id']==jid and row['state']==status, (label,row['state'],row.get('error'))
            return row
        time.sleep(2)
    raise TimeoutError(jid)

def catalogue():
    data=api('/app-registry?refresh=1')
    assert data['source']['resolved_commit']==plan['served_head'] and not data['source']['stale']
    assert data['host']['architecture']==arch and len(data['catalog']['apps'])==50
    assert {row['id']:row for row in data['catalog']['apps'] if row['id'] in plan['items']}==plan['items']
    return {row['id']:row for row in data['status']}

def receipts():
    with sqlite3.connect('file:/var/lib/panel/panel.db?mode=ro',uri=True) as db:
        return db.execute("SELECT app_id,scope,version,sha256 FROM app_registry_receipts ORDER BY 1,2").fetchall()

class Backend(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        data=self.rfile.read(int(self.headers.get('Content-Length','0')))
        payload=json.dumps({
            'node':self.server.label, 'method':self.command, 'path':self.path, 'body':data.decode(),
            'host':self.headers.get('Host'), 'real_ip':self.headers.get('X-Real-IP'),
            'forwarded_for':self.headers.get('X-Forwarded-For'), 'forwarded':self.headers.get('Forwarded'),
            'forwarded_host':self.headers.get('X-Forwarded-Host'),
        }).encode()
        self.send_response(200)
        self.send_header('Content-Type','application/json')
        self.send_header('Content-Length',str(len(payload)))
        self.send_header('X-Panel-Config','spoofed-by-backend')
        self.end_headers()
        self.wfile.write(payload)

    do_POST=do_GET

    def log_message(self,*args):
        pass

def start(label):
    server=http.server.ThreadingHTTPServer(('127.0.0.1',0),Backend)
    server.label=label
    thread=threading.Thread(target=server.serve_forever,daemon=True)
    thread.start()
    return server

def request(host, source_ip='127.0.0.1', method='GET', path='/', body=None):
    conn=http.client.HTTPConnection('127.0.0.1',19101,timeout=5,source_address=(source_ip,0))
    try:
        conn.request(method,path,body,{
            'Host':host,'X-Real-IP':'203.0.113.200','X-Forwarded-For':'203.0.113.201',
            'X-Forwarded-Host':'other.example.test','Forwarded':'for=203.0.113.202',
        })
        result=conn.getresponse()
        data=result.read(100000)
        return result.status, result.getheader('X-Panel-Config'), data
    finally:
        conn.close()

def set_site(site_id,label,modify,expected='succeeded'):
    route='/sites/'+site_id+'/settings'
    site=api(route)
    settings=site['settings']
    modify(settings)
    edit={'settings':settings,'expected_revision':site['settings_revision']}
    preview=api(route+'/preview',edit)
    assert preview['revision']==site['settings_revision'] and len(preview['config_sha'])==64
    save(label+'-preview.json',preview)
    edit['expected_config_sha']=preview['config_sha']
    if 'candidate_sha' in preview:
        edit['expected_candidate_sha']=preview['candidate_sha']
    return job(label,route,edit,expected)

servers = []
try:
    login=json.loads(Path('/etc/panel/first-login.json').read_bytes())
    csrf=api('/login',{k:login[k] for k in ('username','password')})['csrf']
    login.clear()
    status = catalogue()
    items = plan['items']
    assert items['nginx']['version']=='1.30.6-compat1' and items['load-balance']['version']=='1.9.0'
    assert not status['nginx']['installed'] and not status['load-balance']['installed']
    before=receipts()
    for name, max_wait in (('nginx',3100),('load-balance',550)):
        app=items[name]
        operation=job('signed-'+name,'/app-registry/'+name+'/install',
            {'expected_version':app['version'],'expected_sha256':app['sha256']},timeout=max_wait)
        registered=catalogue()[name]
        assert registered['installed'] and registered['installed_version']==app['version']
        assert any(row[0]==name and row[2:]==(app['version'],app['sha256']) for row in receipts())
        proof[name+'_install_job']=operation['id']
    nginx=Path('/opt/panel/runtimes/nginx/1.30.6/sbin/nginx')
    assert nginx.is_file() and not nginx.is_symlink()
    build=subprocess.run([str(nginx),'-V'],capture_output=True,text=True,check=True,timeout=12)
    assert {'--with-stream','--with-stream_ssl_module'} <= set(build.stderr.split())
    save('nginx-build.json',{'version_and_features':build.stderr,'sha256':hashlib.sha256(nginx.read_bytes()).hexdigest()})
    assert api(module+'/run',{})['transport']=='HTTP loopback'
    prior=api('/sites')
    slug='c160-balance-'+secrets.token_hex(5)
    host=slug+'.example.test'
    site=job('new-site','/sites',{'name':'C160 load balance QA', 'slug':slug,'domain':host})['site_id']
    conf=Path('/etc/panel/sites-enabled')/(site+'.conf')
    assert conf.is_file() and not conf.is_symlink()
    original_config=conf.read_bytes()
    original_status, original_header, original_page=request(host)
    assert original_status==200 and original_header and len(original_page)>100
    for label in ('first','second'):
        servers.append(start(label))
    with socket.socket() as port_check:
        for _ in range(25):
            candidate=30000+secrets.randbelow(18000)
            try:
                port_check.bind(('127.0.0.1',candidate))
                pool_port=port_check.getsockname()[1]
                break
            except OSError:
                continue
        else:
            raise RuntimeError('no isolated load-balance ingress port')
    entry={'domain':host,'port':pool_port,'sticky':True,'expected_revision':0,
           'nodes':[{'address':f'127.0.0.1:{s.server_port}','weight':1} for s in servers]}
    added=api(module+'/save',entry)
    assert added['revision']==1
    route='/sites/'+site+'/settings'
    choices=api(route+'/load-balancers')
    assert choices['installed'] and {'domain':host,'sticky':True,'tls':False} in choices['entries']
    set_site(site,'bind-verified-pool',lambda s:s.update(load_balance_domain=host))
    saved=conf.read_bytes()
    assert saved!=original_config and ('# panel-load-balance: '+host).encode() in saved
    request_path='/path%2Fpart?q=%23x'
    peers={}
    for n in range(1,16):
        ip=f'127.0.{n}.5'
        status, header, raw=request(host,ip,'POST',request_path,'payload kept')
        record=json.loads(raw)
        assert status==200 and header not in (None,'spoofed-by-backend',original_header)
        assert record=={'node':record['node'],'method':'POST','path':request_path,'body':'payload kept',
            'host':host,'real_ip':ip,'forwarded_for':ip,'forwarded':None,'forwarded_host':host}
        peers[ip]=record['node']
    assert set(peers.values())=={'first','second'}
    ip=next(iter(peers))
    assert all(json.loads(request(host,ip)[2])['node']==peers[ip] for _ in range(4))
    lost=next(s for s in servers if s.label==peers[ip])
    lost.shutdown()
    lost.server_close()
    servers.remove(lost)
    assert json.loads(request(host,ip)[2])['node']==servers[0].label
    refused=api(module+'/remove',{'domain':host,'expected_revision':1},409)
    assert '绑定' in refused['error'] and conf.read_bytes()==saved
    job('stop-bound-site','/sites/'+site+'/disable',{})
    assert request(host)[0]==404 and ('# panel-load-balance: '+host).encode() in conf.read_bytes()
    refused=api(module+'/remove',{'domain':host,'expected_revision':1},409)
    assert '绑定' in refused['error']
    set_site(site,'detach-stopped-site',lambda s:s.pop('load_balance_domain'))
    assert b'panel-load-balance' not in conf.read_bytes()
    job('restore-original-website','/sites/'+site+'/enable',{})
    assert conf.read_bytes()==original_config and request(host)==(original_status,original_header,original_page)
    removed=api(module+'/remove',{'domain':host,'expected_revision':1})
    assert removed['revision']==2
    assert all(row in receipts() for row in before)
    assert [row for row in api('/sites') if row['id']!=site]==prior
    save('site-proxy-business.json',{'site_id':site,'peer_distribution':peers,'headers_preserved':True,
        'failed_node_replaced':True,'pool_removal_refused_while_bound':True,'stopped_site_detached':True,
        'original_conf_sha256':hashlib.sha256(original_config).hexdigest(),'same_config_bytes_after_restore':True})
    proof.update(ok=True, release_signature_installed=True, load_balance_signed_catalogue_install=True,
        site_effective_ip_routing=True, site_original_config_and_response_restored=True,
        original_sites_and_receipts_preserved=True)
finally:
    for server in servers:
        with contextlib.suppress(Exception):
            server.shutdown()
            server.server_close()
    save('original-proof.json',proof)
