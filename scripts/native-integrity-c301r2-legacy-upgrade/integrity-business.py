import errno
import platform
import pwd
import stat
import contextlib
import base64
import traceback
import hashlib
import http.cookiejar
import json
import os
from pathlib import Path
import re
import secrets
import subprocess
import sys
import time
import urllib.request
import urllib.error

os.umask(0o077)
assert os.geteuid()==0 and len(sys.argv)==2
assert Path('/etc/hostname').read_text().strip().startswith('c294-integrity-'), 'Owned isolated guest hostname required'
private=Path(sys.argv[1]).resolve(strict=True);out=private/'business-phase1';out.mkdir(mode=0o700)
plan=json.loads((Path(__file__).resolve().parent/'cohort.json').read_bytes());plan['arch']={'x86_64':'amd64','aarch64':'arm64'}[platform.machine()]
plan['boot']=Path('/proc/sys/kernel/random/boot_id').read_text().strip()
assert json.loads(Path('/opt/panel/current/SOURCE_INPUTS.json').read_bytes())['inputs_sha256']==plan['source_inputs_sha256']
apps=plan['items'];event_count=0
def save(name,value):
 with(out/name).open('x')as f:json.dump(value,f,indent=2);f.write('\n');f.flush();os.fsync(f.fileno())
origin = 'http://127.0.0.1:19100'
slug = 'tamper-proof-qa-' + secrets.token_hex(5)
domain = slug + '.localhost'


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        raise RuntimeError('Unexpected redirect')


session = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect(),
    urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))
csrf = ''


request_count=0
def api(path, body=None, status=200, key=None):
    global request_count
    headers={'Origin':origin,'Content-Type':'application/json','X-CSRF-Token':csrf}
    raw=None if body is None else json.dumps(body).encode()
    if key:headers['Idempotency-Key']=key
    label=None
    if body is not None:
        request_count+=1;label='api-%04d'%request_count
        save(label+'-intent.json',{'path':path,'body_sha256':hashlib.sha256(raw).hexdigest(),'idempotency_key':key,'maximum_submissions':1})
    try:
        with session.open(urllib.request.Request(origin+'/api'+path,raw,headers),timeout=55)as response:
            code=response.status;result=response.read((8<<20)+1)
    except urllib.error.HTTPError as response:code=response.code;result=response.read((8<<20)+1)
    assert len(result)<=8<<20
    value=json.loads(result)
    if label:save(label+'-outcome.json',{'status':code,'body_sha256':hashlib.sha256(result).hexdigest(),'response':{'redacted':True}if path=='/login'else value})
    assert code==status,(path,code,status,value.get('error'))
    return value
def evidence(event, **fields):
    global event_count
    row={'event':event,**fields};save('event-%04d.json'%event_count,row);event_count+=1
    print(json.dumps({'event':event,'ok':fields.get('ok')}),flush=True)
def wait(read, ready, timeout):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        observed = read()
        if ready(observed):
            return observed
        time.sleep(1.2)
    raise TimeoutError('Original tamper protection operation did not settle')


def post_job(label, endpoint, request):
    key = secrets.token_hex(16)
    evidence('intent', label=label, key=key, request=request)
    job = api(endpoint, request, 202, key)['job_id']
    assert re.fullmatch('[a-f0-9]{32}', job)
    evidence('accepted', label=label, job=job)
    result = wait(lambda: api('/jobs/' + job),
        lambda row: row['state'] in ('succeeded', 'failed', 'needs_attention', 'cancelled'), 330)
    assert result['state'] == 'succeeded', (label, result['state'], result['error'])
    return result


applications = ('website-tamper-proof', 'enterprise-tamper-proof')
assert set(apps) == set(applications)
auth = json.loads(Path('/etc/panel/first-login.json').read_bytes())
csrf = api('/login', {key: auth[key] for key in ('username', 'password')})['csrf']
auth.clear()
child = None
held = None
try:
    before_sites = sorted(api('/sites'), key=lambda row: row['id'])
    catalogue = api('/app-registry?refresh=1')
    assert not catalogue['source']['stale'] and len(catalogue['catalog']['apps']) == 40 and catalogue['source']['resolved_commit']==plan['served_head']
    receipts = {}
    for name in applications:
        item = next(row for row in catalogue['catalog']['apps'] if row['id'] == name)
        status = next(row for row in catalogue['status'] if row['id'] == name)
        assert item == apps[name] and item['version'] == '1.5.0'
        assert status['state_known'] and status['supported'] and not status['installed']
        installed = post_job(name, '/app-registry/' + name + '/install',
            {'expected_version': item['version'], 'expected_sha256': item['sha256']})
        receipts[name] = installed['id']
    catalogue = api('/app-registry?refresh=1')
    for row in catalogue['status']:
        if row['id'] in applications:
            assert row['installed'] and row['installed_version'] == '1.5.0'
    created = post_job('owned-static-site', '/sites', {'name': 'Tamper proof QA', 'slug': slug, 'domain': domain})
    site = created['site_id']
    assert re.fullmatch('[a-f0-9]{32}', site)
    folder = Path('/srv/panel/sites') / site
    assert json.loads((folder / '.panel-site.json').read_bytes())['id'] == site
    public = folder / 'public'
    assert public.is_dir() and not public.is_symlink()
    static = public / 'static-qa.txt'
    uploads = public / 'uploads-qa'
    dynamic = uploads / 'dynamic-qa.txt'
    uploads.mkdir(mode=0o755)
    original = b'A managed static file\n'
    with static.open('xb') as stream:
        stream.write(original)
    dynamic.write_bytes(b'B writable upload\n')
    original_public=public.stat();assert original_public.st_uid==0 and stat.S_IMODE(original_public.st_mode)==0o755
    evidence('owned-fixture-writer-selection',public_uid=original_public.st_uid,public_gid=original_public.st_gid,public_inode=original_public.st_ino,existing_public_owner_and_mode_unchanged=True)
    owner = pwd.getpwnam('www-data')
    assert owner.pw_uid != 0 and owner.pw_gid != 0
    for item in (static, uploads, dynamic):
        os.chown(item, owner.pw_uid, owner.pw_gid)
    static.chmod(0o644)
    uploads.chmod(0o755)
    dynamic.chmod(0o644)
    inode = static.stat().st_ino
    immutable = lambda file: 'i' in subprocess.check_output(['/usr/bin/lsattr', '-d', str(file)], text=True, timeout=10).split()[0]
    assert not immutable(static) and not immutable(dynamic)

    def endpoint(name):
        return '/app-modules/' + name + '/kernel'

    def status(name):
        state = api(endpoint(name) + '?site_id=' + site)
        assert state['site_id'] == site and state['app_version'] == '1.5.0'
        assert state['cap_linux_immutable'] and state['app_sha'] == apps[name]['sha256']
        return state

    for name in applications:
        baseline, = api('/app-modules/' + name + '/baseline',
            {'site_id': site, 'excludes': ['uploads-qa'], 'interval': 3600, 'realtime': False})['sites']
        assert baseline['site_id'] == site and not baseline['auto_restore']
        current = status(name)
        assert current['state'] == 'ready' and current['baseline_sha'] == baseline['signature']
        assert current['baseline_files'] >= 1

    held = os.open(static, os.O_RDWR | os.O_NOFOLLOW)
    child_code = r"""
import errno
import platform
import stat
import contextlib
import traceback,json,os,sys
fd, target, dynamic = int(sys.argv[1]),sys.argv[2],sys.argv[3]
assert os.geteuid()!=0
for line in sys.stdin:
    step=line.strip()
    if step=='exit':
        break
    result={}
    for label in ('held','open','dynamic'):
        try:
            if label=='held':
                os.pwrite(fd,b'A',0);os.fsync(fd)
            else:
                path, value = (target,b'A') if label=='open' else (dynamic,b'B')
                stream=os.open(path,os.O_WRONLY|os.O_NOFOLLOW)
                try:
                    os.pwrite(stream,value,0);os.fsync(stream)
                finally:
                    os.close(stream)
            result[label]=0
        except OSError as error:
            result[label]=error.errno
    print(json.dumps(result),flush=True)
"""
    def drop_privileges():
        os.setgroups([])
        os.setgid(owner.pw_gid)
        os.setuid(owner.pw_uid)
    child = subprocess.Popen(['/usr/bin/python3', '-I', '-B', '-c', child_code, str(held), str(static), str(dynamic)],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
        pass_fds=(held,), preexec_fn=drop_privileges)
    def writer(step, expected):
        child.stdin.write(step + '\n')
        child.stdin.flush()
        assert json.loads(child.stdout.readline()) == {'held': expected, 'open': expected, 'dynamic': 0}
    writer('before', 0)

    def request(name, action, current):
        base = {'site_id': site, 'expected_revision': current['revision'], 'expected_app_version': '1.5.0',
                'baseline_sha': '', 'source_operation': '', 'source_sha': '', 'confirm': ''}
        if action == 'enable':
            base.update(baseline_sha=current['baseline_sha'], confirm='PROTECT SITE ' + site)
        else:
            base.update(source_operation=current['latest']['request']['id'],
                        source_sha=current['latest']['request_sha256'], confirm='RELEASE SITE ' + site)
        key = secrets.token_hex(16)
        evidence('kernel-intent', application=name, action=action, key=key, request=base)
        accepted = api(endpoint(name) + '/' + action, base, 202, key)
        job = accepted['request']['id']
        assert re.fullmatch('[a-f0-9]{32}', job) and accepted['request']['input'] == base
        evidence('kernel-accepted', application=name, action=action, job=job)
        finished = wait(lambda: status(name), lambda v: v.get('latest') is not None and v['latest']['request']['id'] == job
            and v['latest']['state'] not in ('queued', 'running'), 150)
        assert finished['latest']['state'] == 'succeeded', (name, action, finished['latest']['error'])
        assert finished['state'] == ('enabled' if action == 'enable' else 'released')
        return finished

    def record_snapshot():
        root=Path('/etc/panel/security-apps/modules/website-tamper-proof/kernel-protection');rows={}
        assert root.is_dir()and not root.is_symlink()
        for p in sorted(root.rglob('*')):
            s=p.lstat();assert not stat.S_ISLNK(s.st_mode)
            if stat.S_ISDIR(s.st_mode):continue
            assert stat.S_ISREG(s.st_mode)and s.st_uid==0 and s.st_nlink==1 and stat.S_IMODE(s.st_mode)==0o600 and s.st_size<16<<20
            raw=p.read_bytes();rows[str(p)]={'sha256':hashlib.sha256(raw).hexdigest(),'bytes':len(raw),'uid':s.st_uid,'gid':s.st_gid,'mode':stat.S_IMODE(s.st_mode),'inode':s.st_ino,'content_base64':base64.b64encode(raw).decode()}
        assert rows;return rows
    def service_identities():
        return {n:subprocess.check_output(['/usr/bin/systemctl','show',n,'--property=MainPID,InvocationID'],text=True,timeout=15).strip()for n in('panel.service','panel-executor.service')}
    def restart_owned_services(name):
        before=service_identities();records=record_snapshot();save(name+'-before-service-restart-private-records.json',records)
        evidence('owned-service-restart-intent',application=name,maximum_submissions=1,services=before,boot=plan['boot'])
        r=subprocess.run(['/usr/bin/systemctl','restart','panel.service','panel-executor.service'],capture_output=True,timeout=90)
        save(name+'-service-restart-outcome.json',{'exit':r.returncode,'stdout_sha256':hashlib.sha256(r.stdout).hexdigest(),'stderr_sha256':hashlib.sha256(r.stderr).hexdigest()});assert r.returncode==0
        for _ in range(90):
            try:
                with urllib.request.urlopen(origin+'/api/ready',timeout=2)as response:
                    if response.status==200:break
            except Exception:pass
            time.sleep(1)
        else:raise TimeoutError('Owned services not ready; no mutation replay')
        after=service_identities();assert all(after[n]!=before[n]for n in before)
        assert Path('/proc/sys/kernel/random/boot_id').read_text().strip()==plan['boot']
        assert record_snapshot()==records
        save(name+'-after-service-restart-preservation.json',{'ok':True,'new_process_identities':after,'all_original_private_bytes_UID_GID_mode_inode_preserved':True,'records':len(records),'whole_machine_power_loss_not_claimed':True})
    journeys = {}
    for name in applications:
        other = next(value for value in applications if value != name)
        protected = request(name, 'enable', status(name))
        assert status(other)['state'] == 'other-application'
        assert immutable(static) and not immutable(dynamic)
        writer('protected', errno.EPERM)
        restart_owned_services(name)
        assert status(name)['state']=='enabled'and status(other)['state']=='other-application'
        writer('protected-after-service-restart',errno.EPERM)
        assert static.read_bytes() == original
        released = request(name, 'release', protected)
        assert not immutable(static) and not immutable(dynamic)
        writer('released', 0)
        assert static.stat().st_ino == inode and static.read_bytes() == original
        journeys[name] = {'enable': protected['latest']['request']['id'], 'release': released['latest']['request']['id']}
    assert sorted((row for row in api('/sites') if row['id'] != site), key=lambda row: row['id']) == before_sites
    result={'ok':True,'architecture':plan['arch'],'source_inputs_sha256':plan['source_inputs_sha256'],'app_versions':{n:apps[n]['version']for n in apps},'site':site,'journeys':journeys,'retained_old_handle_refused':True,'excluded_upload_writable':True,'same_inode_and_data_preserved':True,'cross_app_isolation':True,'actual_new_Core_executor_PIDs_and_private_records_preserved':True,'whole_machine_power_loss_not_claimed':True,'Main_changed':False,'all40_commercial':False}
    save('original-proof.json',result)
    evidence('verified', ok=True, architecture=plan['arch'], catalogue=catalogue['source']['resolved_commit'],
             site=site, signed_installs=receipts, journeys=journeys, retained_old_handle_refused=True,
             excluded_upload_writable=True, same_inode_and_data_preserved=True, cross_app_isolation=True)
except BaseException:
    save('original-proof.json',{'ok':False,'architecture':plan['arch'],'source_inputs_sha256':plan['source_inputs_sha256'],'failure':traceback.format_exc(),'Main_changed':False,'all40_commercial':False})
    raise
finally:
    if held is not None:
        os.close(held)
    if child is not None:
        child.terminate()
        child.wait(timeout=10)
    with contextlib.suppress(Exception):api('/logout', {})
