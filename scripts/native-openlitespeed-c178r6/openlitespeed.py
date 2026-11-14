"""Validate the current signed OpenLiteSpeed application and simultaneous legacy project."""
import base64
import urllib.parse
import ssl
import socket
import http.cookies
import http.client
import contextlib
import hashlib
import http.cookiejar
import json
import os
from pathlib import Path
import platform
import pwd
import re
import secrets
import subprocess
import sys
import time
import traceback
import urllib.error
import urllib.request

os.umask(0o077)
root=Path(sys.argv[1]).resolve(strict=True)
assert os.geteuid()==0 and len(sys.argv)==2
plan=json.loads((root/'assets.json').read_bytes())
arch={'x86_64':'amd64','aarch64':'arm64'}[platform.machine()]
case=plan['OS_case']
assert arch==plan['architecture']
host_os=dict(line.partition('=')[::2] for line in Path('/etc/os-release').read_text().splitlines() if '=' in line)
assert host_os['ID'].strip('"')==case['os_id'] and host_os['VERSION_ID'].strip('"')==case['version_id']
assert case['platform']==case['os_id']+'-'+case['version_id']
assert Path('/etc/hostname').read_text().strip()==plan['OS_case']['hostname']
assert not Path('/opt/panel').exists() and not Path('/var/lib/panel').exists()
base=Path('/opt/panel-elastic-c174-qa-'+secrets.token_hex(16))
base.mkdir(mode=0o700)
private=base/'verified'
private.mkdir(mode=0o700)
out=base/'evidence'
out.mkdir(mode=0o700)
def sha(path):
    hashed=hashlib.sha256()
    with path.open('rb') as f:
        for block in iter(lambda:f.read(1<<20),b''):
            hashed.update(block)
    return hashed.hexdigest()
def keep(name,obj):
    with (out/(name+'.json')).open('x') as f:
        json.dump(obj,f,indent=2);f.write('\n');f.flush();os.fsync(f.fileno())
def command(name,args,limit=150):
    with (out/(name+'.stdout')).open('xb') as a,(out/(name+'.stderr')).open('xb') as b:
        p=subprocess.run(args,stdin=subprocess.DEVNULL,stdout=a,stderr=b,timeout=limit)
    assert p.returncode==0,name
def stage(path,artifact):
    owner=pwd.getpwnam('panel')
    path.parent.mkdir(mode=0o700,parents=True,exist_ok=True)
    for d in path.parents:
        if d==Path('/var/lib/panel'):break
        assert not d.is_symlink()
        os.chown(d,owner.pw_uid,owner.pw_gid)
    temp=path.with_suffix('.new')
    temp.open('xb').write(artifact.read_bytes())
    os.chown(temp,owner.pw_uid,owner.pw_gid)
    os.replace(temp,path)
def wait(check,accept,seconds):
    deadline=time.monotonic()+seconds
    while time.monotonic()<deadline:
        got=check()
        if accept(got):return got
        time.sleep(2)
    state=got.get('state','unknown') if isinstance(got,dict) else 'unknown'
    raise TimeoutError('Original native operation did not reach the expected state: '+str(state))
opener=urllib.request.build_opener(urllib.request.ProxyHandler({}),urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))
elastic=urllib.request.build_opener(urllib.request.ProxyHandler({}))
panel_origin='http://127.0.0.1:19100'
csrf=''
def api(path,body=None,status=200,key=None,method=None):
    headers={'Origin':panel_origin,'Content-Type':'application/json','X-CSRF-Token':csrf}
    if key:headers['Idempotency-Key']=key
    return request_json(opener,panel_origin+'/api'+path,body,status,headers,method)
def request_json(client,url,body,status,headers,method):
    req=urllib.request.Request(url,None if body is None else json.dumps(body).encode(),headers,method=method)
    try:
        with client.open(req,timeout=80) as res:
            assert res.url==url
            code,raw=res.status,res.read(5<<20)
    except urllib.error.HTTPError as err:
        code,raw=err.code,err.read(5<<20)
    parsed=json.loads(raw)
    error=parsed.get('error','') if isinstance(parsed,dict) else ''
    if isinstance(error,dict):
        error=error.get('type','')
    assert status is None or code==status,(req.get_method(),url,code,status,str(error)[:260])
    return code,parsed
def job(accepted):
    job_id,project=accepted['job_id'],accepted['project_id']
    def observed():
        code,item=api('/docker/job-observations/'+job_id,status=None)
        if code==409:return {'state':'unknown'}
        assert code==200 and item['job_id']==job_id and item['project_id']==project
        return item
    reply=wait(observed,lambda v:v['state'] in ('succeeded','failed'),900)
    keep('original-job-'+job_id,reply)
    assert reply['state']=='succeeded' and not reply.get('error')
    return project
def docker(*args, data=None):
    return subprocess.run(['/usr/bin/docker',*args],input=data,check=True,capture_output=True,timeout=60).stdout

def inspect(project, image, web):
    id = docker('ps', '-aq', '--filter', 'label=com.docker.compose.project=' + project['engine_name']).decode().strip()
    assert re.fullmatch('[a-f0-9]{12,64}', id)
    record, = json.loads(docker('inspect', id))
    assert record['Config']['Image'] == image and not record['HostConfig']['Privileged']
    assert docker('image', 'inspect', '-f', '{{.Os}}/{{.Architecture}}', record['Image']).strip() == ('linux/' + arch).encode()
    assert record['HostConfig']['PortBindings'] == {
        '8088/tcp': [{'HostIp': '127.0.0.1', 'HostPort': str(web)}],
        '7080/tcp': [{'HostIp': '127.0.0.1', 'HostPort': str(web + 1)}],
    }
    assert {mount['Destination'] for mount in record['Mounts']} == {
        '/usr/local/lsws/conf', '/usr/local/lsws/admin/conf', '/var/www/vhosts',
    }
    assert all(mount['Type'] == 'volume' for mount in record['Mounts'])
    return record


def file(container, name):
    return docker('exec', container, '/bin/cat', '/usr/local/lsws/admin/conf/' + name)


def webadmin(container, port, password, expect=True):
    pem = file(container, 'webadmin.crt').decode('ascii')
    subject = subprocess.check_output(['/usr/bin/openssl', 'x509', '-noout', '-subject', '-nameopt', 'RFC2253'],
                                      input=pem.encode(), timeout=10).decode()
    host = re.search(r'(?:^|[=,])\s*CN=([A-Za-z0-9.-]+)(?:,|\s|$)', subject)[1]
    tls = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    tls.load_verify_locations(cadata=pem)
    cert = ssl.PEM_cert_to_DER_cert(pem)

    class HTTPS(http.client.HTTPSConnection):
        def connect(self):
            raw = socket.create_connection(('127.0.0.1', self.port), timeout=10)
            self.sock = tls.wrap_socket(raw, server_hostname=host)
            assert self.sock.getpeercert(binary_form=True) == cert

    jar = http.cookies.SimpleCookie()
    referer = f'https://{host}:{port}/login.php'

    def request(method, path, data=None):
        headers = {'Referer': referer, 'Host': f'{host}:{port}'}
        if data is not None:
            headers['Content-Type'] = 'application/x-www-form-urlencoded'
        if jar:
            headers['Cookie'] = '; '.join(f'{key}={value.coded_value}' for key, value in jar.items())
        with contextlib.closing(HTTPS(host, port, timeout=10, context=tls)) as conn:
            conn.request(method, path, data, headers)
            r = conn.getresponse()
            for key, value in r.getheaders():
                if key.lower() == 'set-cookie':
                    jar.load(value)
            return r.status, r.getheader('Location'), r.read(1 << 20)

    code, _, body = request('GET', '/login.php')
    assert code == 200 and b'name="userid"' in body
    data = urllib.parse.urlencode({'userid': 'admin', 'pass': password}).encode()
    code, destination, body = request('POST', '/login.php', data)
    if expect:
        assert code in (301, 302, 303)
        assert urllib.parse.urljoin(referer, destination) == f'https://{host}:{port}/index.php'
        code, _, index = request('GET', '/index.php')
        assert code == 200 and b'name="userid"' not in index
    else:
        assert code == 200 and b'name="userid"' in body
    return hashlib.sha256(cert).hexdigest()


def configure_site(container, path, content):
    docker('exec', '-i', container, '/bin/sh', '-c', 'umask 022; cat > "$1"', '--',
           '/var/www/vhosts/cloudstack/html' + path, data=content)


def site(port, path, content):
    with opener.open(f'http://127.0.0.1:{port}{path}', timeout=20) as response:
        assert response.status == 200 and response.read(1 << 20) == content



def checked_api(path, data=None, status=200):
    key=secrets.token_hex(16) if data is not None else None
    return api(path,data,status,key)[1]

def checked_job(path,body):
    response=checked_api(path,body,202)
    project_id=job(response)
    assert project_id==response['project_id']
    return response

def project_ready(pid):
    return wait(lambda:next((x for x in checked_api('/docker/projects')['projects'] if x['id']==pid),{}),
                lambda p:p.get('state')=='running' and p.get('services')==p.get('healthy')==p.get('running')==1,400)

report={'ok':False,'architecture':arch,'platform':case['platform'],'base':str(base),'Main_changed':False,'all50_commercial':False}
try:
    for name,digest in plan['files'].items():
        assert re.fullmatch(r'[a-zA-Z0-9._-]+',name)
        data=(root/name).read_bytes()
        assert 0<len(data)<64<<20 and hashlib.sha256(data).hexdigest()==digest
        (private/name).open('xb').write(data)
    archive=private/('panel-'+plan['version']+'-linux-'+arch+'.tar.gz')
    key=['--public-key',str(private/'release-signing-dev.pub')]
    signer=[sys.executable,'-I','-B',str(private/'signed-release.py')]
    command('archive-verify',signer+['verify',str(archive)]+key)
    command('archive-preflight',signer+['install',str(archive)]+key+['--preflight-only'],600)
    command('programme-install',signer+['install',str(archive)]+key,1800)
    assert json.loads(Path('/opt/panel/current/SOURCE_INPUTS.json').read_bytes())['inputs_sha256']==plan['source_inputs_sha256']
    creds=json.loads(Path('/etc/panel/first-login.json').read_bytes())
    csrf=api('/login',{k:creds[k] for k in ('username','password')})[1]['csrf'];creds.clear()

    assert sha(private/'catalogue.pub.pem')=='659ea4edcecaf23a586e2ff371616fde5f6ee7c219fb70fa978816e2b10acf75'
    command('catalogue-verify',['openssl','pkeyutl','-verify','-pubin','-inkey',str(private/'catalogue.pub.pem'),
            '-rawin','-in',str(private/'catalogue.json'),'-sigfile',str(private/'catalogue.sig.bin')])
    bundle=json.loads((private/'catalogue.bundle.json').read_bytes())
    assert base64.b64decode(bundle['signature'])==(private/'catalogue.sig.bin').read_bytes()
    assert bundle['catalog'].encode()==(private/'catalogue.json').read_bytes()
    item=plan['application']
    assert item['id']=='openlitespeed' and item['version']=='1.9.4-compat2'
    assert sha(private/'openlitespeed.manifest.json')==item['sha256']
    cache=Path('/var/lib/panel/app-registry')
    stage(cache/'catalog'/'catalog-v1.bundle.json',private/'catalogue.bundle.json')
    stage(cache/'packages'/'openlitespeed'/item['version']/'manifest.json',private/'openlitespeed.manifest.json')
    engine,=[row for row in json.loads(bundle['catalog'])['apps'] if row['id']=='docker-manager']
    assert sha(private/'docker.manifest.json')==engine['sha256']
    stage(cache/'packages'/'docker-manager'/engine['version']/'manifest.json',private/'docker.manifest.json')
    catalogue=checked_api('/app-registry')
    assert len(catalogue['catalog']['apps'])==50 and item in catalogue['catalog']['apps']
    assert not next(v for v in catalogue['status'] if v['id']=='openlitespeed')['installed']
    submitted=checked_api('/app-registry/docker-manager/install',{'expected_version':engine['version'],'expected_sha256':engine['sha256']},202)
    installed=wait(lambda:checked_api('/jobs/'+submitted['job_id']),
                   lambda row:row['state'] in ('succeeded','failed','needs_attention'),900)
    keep('docker-manager-original-job',installed)
    assert installed['state']=='succeeded'
    report['signed_cache_validated']=True
    report['docker_engine_installed_via_store']=True
    old_job = checked_job('/docker/projects', {'name': 'c92-original', 'template_id': 'openlitespeed', 'host_port': 27180, 'compose': ''})
    old_project = project_ready(old_job['project_id'])
    old = inspect(old_project, plan['previous_image'], 27180)
    old_credential = hashlib.sha256(file(old['Id'], 'htpasswd')).hexdigest()
    configure_site(old['Id'], '/retained.html', b'original-site\n')
    site(27180, '/retained.html', b'original-site\n')
    catalogue=checked_api('/app-registry')
    state=next(v for v in catalogue['status'] if v['id']=='openlitespeed')
    assert state['state_known'] and state['supported'] and state['installed']
    assert state['update_available'] and state['update_kind']=='compose-parallel'
    assert state['latest_version']==item['version']
    new_job=checked_job('/app-registry/openlitespeed/install',{'name':'commercial-ols-current','host_port':27182,
                        'expected_version':item['version'],'expected_sha256':item['sha256']})
    new = project_ready(new_job['project_id'])
    assert new['template_id'] == 'openlitespeed-194'
    current = inspect(new, plan['image'], 27182)
    paths = [set(m['Name'] for m in record['Mounts']) for record in (old, current)]
    assert len(paths[0]) == len(paths[1]) == 3 and paths[0].isdisjoint(paths[1])
    credential = checked_api('/docker/projects/' + new['id'] + '/credentials', {})['credentials']['CLOUDSTACK_ADMIN_PASSWORD']
    assert re.fullmatch('[0-9a-f]{64}', credential)
    cert = webadmin(current['Id'], 27183, credential)
    webadmin(current['Id'], 27183, secrets.token_urlsafe(25), False)
    assert docker('exec', current['Id'], 'sha256sum', '/usr/local/lsws/admin/fcgi-bin/admin_php').split()[0].decode() == plan['admin_sha256'][arch]
    assert file(current['Id'], 'enable_webadmin') == b''
    new_credential = hashlib.sha256(file(current['Id'], 'htpasswd')).hexdigest()
    configure_site(current['Id'], '/native.php', b'<?php echo PHP_VERSION."|".PHP_SAPI;')
    site(27182, '/native.php', b'8.3.36|litespeed')
    domain = 'c92-openlitespeed.example.test'
    binding = checked_api('/docker/projects/' + new['id'] + '/sites',
                  {'name': domain, 'slug': 'c92-openlitespeed', 'domain': domain}, 202)
    bound = wait(lambda: checked_api('/jobs/' + binding['job_id']),
                 lambda x: x['state'] in ('succeeded', 'failed', 'needs_attention'),400)
    assert bound['state'] == 'succeeded' and bound['kind'] == 'create_site'
    site_request = urllib.request.Request('http://127.0.0.1:19101/native.php', headers={'Host': domain})
    with opener.open(site_request, timeout=20) as response:
        assert response.status == 200 and response.read(1 << 20) == b'8.3.36|litespeed'
    def mount_identity(container):
        result = {m['Destination']: m for m in container['Mounts']}
        assert len(result) == len(container['Mounts'])
        return result

    restarted = checked_job('/docker/projects/' + new['id'] + '/restart', {})
    after = inspect(project_ready(new['id']), plan['image'], 27182)
    identity = {
        'container_preserved': after['Id'] == current['Id'],
        'mounts_preserved': mount_identity(after) == mount_identity(current),
        'only_mount_order_differs': after['Mounts'] != current['Mounts'] and mount_identity(after) == mount_identity(current),
        'restart_observed': after['State']['StartedAt'] != current['State']['StartedAt'],
    }
    keep('original-restart-identity',identity)
    assert identity['container_preserved'] and identity['mounts_preserved'] and identity['restart_observed']
    assert hashlib.sha256(file(after['Id'], 'htpasswd')).hexdigest() == new_credential
    assert webadmin(after['Id'], 27183, credential) == cert
    site(27182, '/native.php', b'8.3.36|litespeed')
    retained = inspect(project_ready(old_project['id']), plan['previous_image'], 27180)
    assert retained['Id'] == old['Id'] and retained['State']['StartedAt'] == old['State']['StartedAt']
    assert mount_identity(retained) == mount_identity(old) and hashlib.sha256(file(retained['Id'], 'htpasswd')).hexdigest() == old_credential
    site(27180, '/retained.html', b'original-site\n')
    state=next(v for v in checked_api('/app-registry')['status'] if v['id']=='openlitespeed')
    assert state['installed'] and state['installed_version']==item['version']
    report.update(ok=True, source_inputs_sha256=plan['source_inputs_sha256'], signed_app_version=item['version'],
                  old_job=old_job['job_id'],new_job=new_job['job_id'],restart_job=restarted['job_id'],
                  official_admin_binary=True,actual_php_site=True,actual_https_webadmin=True,
                  actual_managed_domain_php=True,binding_job=binding['job_id'],
                  restart_retained_new_site_and_credentials=True,original_project_retained=True,signed_store_install=True)
except BaseException:
    report['failure']=traceback.format_exc()
finally:
    keep('result',report)
    print(json.dumps(report),flush=True)
sys.exit(0 if report['ok'] else 1)
