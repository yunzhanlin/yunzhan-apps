import hashlib
import http.cookiejar
import json
import os
from pathlib import Path
import re
import secrets
import sys
import time
import urllib.request
import urllib.error

os.umask(0o077)
assert os.geteuid()==0 and os.environ.get('GITHUB_ACTIONS')=='true'
assert os.environ.get('GITHUB_REPOSITORY')=='yunzhanlin/yunzhan-apps'
private=Path(sys.argv[1])
output=private/'business-phase1'
output.mkdir(mode=0o700)
plan=json.loads((Path(__file__).resolve().parent/'cohort.json').read_bytes())
plan['arch']={'x86_64':'amd64','aarch64':'arm64'}[os.uname().machine]
assert json.loads(Path('/opt/panel/current/SOURCE_INPUTS.json').read_bytes())['inputs_sha256']==plan['source_inputs_sha256']
app = plan['app']
origin = 'http://127.0.0.1:19100'
module = '/app-registry/load-balance/stream'



class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        raise RuntimeError('Unexpected redirect')


session = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect(),
    urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))
csrf = ''


def api(path, body=None, status=200, key=None):
    headers = {'Origin': origin, 'Content-Type': 'application/json', 'X-CSRF-Token': csrf}
    if key:
        headers['Idempotency-Key'] = key
    raw = None if body is None else json.dumps(body,separators=(',',':')).encode()
    try:
        with session.open(urllib.request.Request(origin + '/api' + path, raw, headers), timeout=55) as response:
            assert response.status == status
            result = response.read((8 << 20) + 1)
            assert len(result) <= 8 << 20
            return json.loads(result)
    except urllib.error.HTTPError as error:
        if path != '/login':
            evidence('http-error',path=path,status=error.code,body=error.read(8192).decode(errors='replace'))
        raise



def evidence(event, **fields):
    value={'event':event,**fields}
    print(json.dumps(value,sort_keys=True),flush=True)
    if event=='verified':
        with (output/'original-proof.json').open('x') as f:
            json.dump(value,f,indent=2)


def wait(read, ready, timeout):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        observed = read()
        if ready(observed):
            return observed
        time.sleep(1.2)
    raise TimeoutError('Original load-balance operation did not settle')


def post_job(label, endpoint, request, timeout=330):
    key = secrets.token_hex(16)
    evidence('intent', label=label, key=key, request=request)
    job = api(endpoint, request, 202, key)['job_id']
    assert re.fullmatch('[a-f0-9]{32}', job)
    evidence('accepted', label=label, job=job)
    result = wait(lambda: api('/jobs/' + job),
        lambda row: row['state'] in ('succeeded', 'failed', 'needs_attention', 'cancelled'), timeout)
    assert result['state'] == 'succeeded', (label, result['state'], result['error'])
    return result


import socket
import subprocess
import socketserver
import sqlite3
import threading

def snapshot():
    with sqlite3.connect('file:/var/lib/panel/panel.db?mode=ro',uri=True) as db:
        rows=db.execute("SELECT app_id,scope,version,sha256 FROM app_registry_receipts WHERE app_id<>'load-balance' ORDER BY 1,2").fetchall()
        sites=db.execute('SELECT id,domain,status FROM sites ORDER BY id').fetchall()
        return {'other_receipts':rows,'sites':sites}

def registry():
    cat=api('/app-registry?refresh=1')
    assert not cat['source']['stale'] and cat['source']['resolved_commit']==plan['catalogue']
    assert cat['host']['architecture']==plan['arch'] and len(cat['catalog']['apps'])==50
    assert next(row for row in cat['catalog']['apps'] if row['id']==app['id'])==app
    return next(row for row in cat['status'] if row['id']==app['id'])

class TCPBackend(socketserver.BaseRequestHandler):
    def handle(self):
        self.request.settimeout(5)
        parts=[]
        while True:
            raw=self.request.recv(1024)
            if not raw:
                break
            parts.append(raw)
        self.request.sendall(self.server.identity+b':'+b''.join(parts))
        self.request.shutdown(socket.SHUT_WR)

class UDPBackend(socketserver.BaseRequestHandler):
    def handle(self):
        data, reply=self.request
        reply.sendto(self.server.identity+b':'+data,self.client_address)

def backend(server_type, handler, identity):
    server=server_type(('127.0.0.1',0),handler)
    server.identity=identity
    thread=threading.Thread(target=server.serve_forever,daemon=True)
    thread.start()
    return server

def vacant(protocol):
    kind=socket.SOCK_STREAM if protocol=='tcp' else socket.SOCK_DGRAM
    with socket.socket(socket.AF_INET,kind) as s:
        for _ in range(25):
            port=31000+secrets.randbelow(7000)
            try:
                s.bind(('127.0.0.1',port))
                return port
            except OSError:
                pass
    raise RuntimeError('No available isolated fixture port')

def submit(mutation):
    identity=secrets.token_hex(16)
    route=module+'/controls/'+identity
    evidence('control-intent',id=identity,mutation=mutation)
    original=api(route,mutation,202,identity)
    assert original['operation']['request_id']==identity and original['operation']['mutation']==mutation
    evidence('control-accepted',id=identity,state=original['state'])
    ended=wait(lambda:api(route),lambda row:row['state'] in ('completed','unknown'),220)
    evidence('control-terminal',id=identity,state=ended['state'],result=ended.get('result'))
    assert ended['state']=='completed' and ended['result']['state']=='committed', ended.get('result')
    return identity

def entry_fingerprint(entry):
    keys=('format','revision','name','protocol','port','probe_port','nodes','method','connect_milliseconds',
          'session_seconds','max_sessions','udp_requests','udp_responses','removed')
    assert set(entry)==set(keys)
    raw=json.dumps({k:entry[k] for k in keys},ensure_ascii=False,separators=(',',':')).encode()
    name=hashlib.sha256(entry['name'].encode()).hexdigest()[:20]
    return f"{name}:{entry['revision']}:{hashlib.sha256(raw).hexdigest()[:24]}"

def endpoint(protocol, servers, test_id):
    return {'format':1,'action':'create','name':protocol+'-'+test_id+'.example.test',
            'expected_revision':0,'expected_fingerprint':'',
            'policy':{'protocol':protocol,'port':vacant(protocol),'nodes':[
                {'address':f'127.0.0.1:{server.server_address[1]}','weight':1,'backup':False} for server in servers],
                'method':'round-robin','connect_milliseconds':1000,'session_seconds':6,'max_sessions':16,
                'udp_requests':1 if protocol=='udp' else 0,'udp_responses':1 if protocol=='udp' else 0}}

def traffic(protocol, port):
    results=set()
    kind=socket.SOCK_STREAM if protocol=='tcp' else socket.SOCK_DGRAM
    for index in range(12):
        payload=bytes([index,0,255,19])+secrets.token_bytes(64)
        with socket.socket(socket.AF_INET,kind) as client:
            client.settimeout(8)
            client.connect(('127.0.0.1',port))
            client.sendall(payload)
            if protocol=='tcp':
                client.shutdown(socket.SHUT_WR)
                parts=[]
                while True:
                    raw=client.recv(1024)
                    if not raw:
                        break
                    parts.append(raw)
                answer=b''.join(parts)
            else:
                answer=client.recv(1024)
        identity,sep,received=answer.partition(b':')
        assert identity in (b'A',b'B') and sep==b':' and received==payload
        results.add(identity)
    assert results=={b'A',b'B'}
    return 12

auth=json.loads(Path('/etc/panel/first-login.json').read_bytes())
csrf=api('/login',{key:auth[key] for key in ('username','password')})['csrf']
auth.clear()
servers=[]
try:
    assert app['id']=='load-balance' and app['version']=='1.9.0'
    before_refusal=snapshot()
    assert not any((Path('/opt/panel/runtimes/nginx')/v).exists() for v in ('1.30.6','1.31.5'))
    original_state=registry()
    assert original_state['state_known'] and original_state['supported'] and not original_state['installed']
    request={'expected_version':app['version'],'expected_sha256':app['sha256']}
    denied_key=secrets.token_hex(16)
    evidence('refused-original-intent',key=denied_key,request=request)
    denied=api('/app-registry/load-balance/install',request,202,denied_key)['job_id']
    evidence('refused-original-accepted',job=denied)
    refusal=wait(lambda:api('/jobs/'+denied),
        lambda row:row['state'] in ('failed','needs_attention','succeeded'),240)
    evidence('refused-original-outcome',job=denied,state=refusal['state'],detail=refusal['error'])
    assert refusal['state']=='failed' and '原生交接前已拒绝' in refusal['error'] and 'Nginx' in refusal['error']
    refreshed=registry()
    assert not refreshed['installed'] and snapshot()==before_refusal
    with sqlite3.connect('file:/var/lib/panel/panel.db?mode=ro',uri=True) as db:
        assert db.execute('SELECT count(*) FROM app_registry_pending WHERE job_id=?',(denied,)).fetchone()==(0,)
        assert db.execute('SELECT count(*) FROM load_balance_stream_install_requests WHERE job_id=?',(denied,)).fetchone()==(1,)
    nginx=plan['nginx_app']
    assert nginx['id']=='nginx' and nginx['version']=='1.30.6-compat1'
    cat=api('/app-registry?refresh=1')
    assert not cat['source']['stale'] and cat['source']['resolved_commit']==plan['catalogue']
    assert next(row for row in cat['catalog']['apps'] if row['id']=='nginx')==nginx
    runtime=post_job('native-nginx-build','/app-registry/nginx/install',
        {'expected_version':nginx['version'],'expected_sha256':nginx['sha256']},3100)
    assert runtime['target_id']=='nginx-1.30.6'
    binary=Path('/opt/panel/runtimes/nginx/1.30.6/sbin/nginx')
    assert binary.is_file() and not binary.is_symlink()
    build=subprocess.run([str(binary),'-V'],capture_output=True,text=True,check=True,timeout=12)
    assert {'--with-stream','--with-stream_ssl_module'} <= set(build.stderr.split())
    state=registry()
    assert state['state_known'] and state['supported'] and not state['installed']
    before=snapshot()
    assert any(row[0]=='nginx' and row[2]==nginx['version'] and row[3]==nginx['sha256'] for row in before['other_receipts'])
    install=post_job('signed-stream-app','/app-registry/load-balance/install',
        {'expected_version':app['version'],'expected_sha256':app['sha256']})['id']
    state=registry()
    assert state['installed'] and state['installed_version']==app['version']
    evidence('signed-install-verified',app=app['id'],version=app['version'],job=install)
    with sqlite3.connect('file:/var/lib/panel/panel.db?mode=ro',uri=True) as db:
        assert db.execute("SELECT version,sha256 FROM app_registry_receipts WHERE app_id='load-balance' AND scope='load-balance'").fetchone()==(app['version'],app['sha256'])
    original=api(module+'/workspace')
    assert original['available'] and original['state']=='empty' and not original['entries']
    test_id=secrets.token_hex(4)
    ports={}
    receipts={}
    for protocol, server_type, handler in (('tcp',socketserver.ThreadingTCPServer,TCPBackend),('udp',socketserver.ThreadingUDPServer,UDPBackend)):
        targets=[backend(server_type,handler,marker) for marker in (b'A',b'B')]
        servers.extend(targets)
        mutation=endpoint(protocol,targets,test_id)
        port=mutation['policy']['port']
        assert port not in ports.values()
        receipts[protocol]=submit(mutation)
        workspace=api(module+'/workspace')
        assert workspace['state']=='running' and workspace['configuration_verified'] and workspace['bind_address']=='127.0.0.1'
        entry=next(row for row in workspace['entries'] if row['name']==mutation['name'])
        assert entry['protocol']==protocol and entry['port']==port and not entry['removed']
        ports[protocol]=port
    samples={protocol:traffic(protocol,port) for protocol,port in ports.items()}
    evidence('actual-binary-traffic',verified_payloads=samples,two_backends_each=True,tcp_half_close=True)
    for entry in reversed(workspace['entries']):
        submit({'format':1,'action':'remove','name':entry['name'],'expected_revision':entry['revision'],
                'expected_fingerprint':entry_fingerprint(entry),'policy':None})
    stopped=wait(lambda:api(module+'/workspace'),
        lambda row:row['state']=='stopped' and row['configuration_verified'],140)
    assert all(row['removed'] for row in stopped['entries'])
    after=snapshot()
    assert after==before, {'before':before,'after':after}
    same=api('/jobs/'+denied)
    assert same['state']=='failed' and same['error']==refusal['error']
    evidence('verified',ok=True,architecture=plan['arch'],catalogue=plan['catalogue'],signed_install=install,original_refusal_job=denied,original_refusal_preserved=True,
             nginx_runtime_job=runtime['id'],native_transactions=receipts,verified_payloads=samples,two_backends_each=True,tcp_half_close=True,
             original_sites_and_other_app_receipts_unchanged=True,removed_entries_retained=stopped['entries'])
finally:
    for server in servers:
        server.shutdown()
        server.server_close()
    api('/logout',{})
