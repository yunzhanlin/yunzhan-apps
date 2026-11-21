import errno
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

os.umask(0o077)
plan = json.loads(sys.argv[1])
assert os.geteuid() == 0 and Path('/proc/sys/kernel/random/boot_id').read_text().strip() == plan['boot']
assert json.loads(Path('/opt/panel/current/SOURCE_INPUTS.json').read_bytes())['inputs_sha256'] == plan['programme']
apps = plan['apps']
origin = 'http://127.0.0.1:19100'
slug = 'tamper-proof-qa-' + secrets.token_hex(5)
domain = slug + '.localhost'


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
    raw = None if body is None else json.dumps(body).encode()
    with session.open(urllib.request.Request(origin + '/api' + path, raw, headers), timeout=55) as response:
        assert response.status == status
        result = response.read((8 << 20) + 1)
        assert len(result) <= 8 << 20
        return json.loads(result)


def evidence(event, **fields):
    print(json.dumps({'event': event, **fields}, sort_keys=True), flush=True)


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


def prepare_owned_writer_public(site, public):
    import pwd
    old=public.stat()
    original_index=public/'index.html'
    witness=None
    if original_index.exists():
        st=original_index.stat();witness=(original_index.read_bytes(),st.st_ino,st.st_uid,st.st_gid,st.st_mode)
    import grp
    panel_gid=grp.getgrnam('panel').gr_gid
    evidence('actual-original-static-public-identity',site=site,UID=old.st_uid,GID=old.st_gid,panel_GID=panel_gid)
    assert old.st_uid==0 and old.st_gid==panel_gid
    evidence('owned-site-account-prepare-intent',site=site,maximum_submissions=1,original_static_public_UID=old.st_uid,original_static_public_GID=old.st_gid)
    subprocess.run(['/usr/bin/systemctl','start','panel-site-user@'+site+'.service'],check=True,timeout=45)
    account=pwd.getpwnam('ps'+site[:24]);assert account.pw_uid!=0 and account.pw_gid!=0 and account.pw_gecos=='panel-managed-'+site
    os.chown(public,account.pw_uid,account.pw_gid)
    if witness:
        st=original_index.stat();assert witness==(original_index.read_bytes(),st.st_ino,st.st_uid,st.st_gid,st.st_mode)
    evidence('owned-static-public-writer-fixture',site=site,UID=account.pw_uid,GID=account.pw_gid,original_index_preserved=True,original_public_mode_preserved=public.stat().st_mode==old.st_mode)

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
    assert not catalogue['source']['stale'] and len(catalogue['catalog']['apps']) == 40
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
    prepare_owned_writer_public(site,public)
    owner = public.stat()
    assert owner.st_uid != 0 and owner.st_gid != 0
    for item in (static, uploads, dynamic):
        os.chown(item, owner.st_uid, owner.st_gid)
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

    preexisting = public / 'preexisting-immutable.txt'
    preexisting.write_bytes(b'Original preexisting inode flag\n')
    os.chown(preexisting, owner.st_uid, owner.st_gid)
    preexisting.chmod(0o644)
    subprocess.run(['/usr/bin/chattr','+i',str(preexisting)],check=True,timeout=10)
    preexisting_inode=preexisting.stat().st_ino
    assert immutable(preexisting)

    for name in applications:
        baseline, = api('/app-modules/' + name + '/baseline',
            {'site_id': site, 'excludes': ['uploads-qa'], 'interval': 3600, 'realtime': False})['sites']
        assert baseline['site_id'] == site and not baseline['auto_restore']
        current = status(name)
        assert current['state'] == 'ready' and current['baseline_sha'] == baseline['signature']
        assert current['baseline_files'] >= 1

    held = os.open(static, os.O_RDWR | os.O_NOFOLLOW)
    child_code = r"""
import errno,json,os,sys
fd, target, dynamic = int(sys.argv[1]),sys.argv[2],sys.argv[3]
assert os.geteuid()!=0
for line in sys.stdin:
    step=line.strip()
    if step=='exit':
        break
    result={}
    for label in ('held','open','dynamic','truncate'):
        try:
            if label=='truncate':
                os.ftruncate(fd,0) if step=='protected' else None
            elif label=='held':
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
    if step=='protected':
        for label in ('create','rename','unlink','external-hardlink'):
            try:
                if label=='create':
                    n=os.open(target+'.new',os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600);os.close(n)
                elif label=='rename':os.rename(target,target+'.moved')
                elif label=='unlink':os.unlink(target)
                else:os.link(target,dynamic+'.hardlink')
                result[label]=0
            except OSError as error:result[label]=error.errno
    print(json.dumps(result),flush=True)
"""
    def drop_privileges():
        os.setgroups([])
        os.setgid(owner.st_gid)
        os.setuid(owner.st_uid)
    child = subprocess.Popen(['/usr/bin/python3', '-I', '-B', '-c', child_code, str(held), str(static), str(dynamic)],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
        pass_fds=(held,), preexec_fn=drop_privileges)
    def writer(step, expected):
        child.stdin.write(step + '\n')
        child.stdin.flush()
        value=json.loads(child.stdout.readline())
        wanted={'held':expected,'open':expected,'dynamic':0,'truncate':expected if step=='protected'else 0}
        if step=='protected':wanted.update({k:errno.EPERM for k in ('create','rename','unlink','external-hardlink')})
        evidence('actual-UID-owned-writer',step=step,observed=value)
        assert value==wanted,(step,value,wanted)
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

    journeys = {}
    for name in applications:
        other = next(value for value in applications if value != name)
        protected = request(name, 'enable', status(name))
        assert status(other)['state'] == 'other-application'
        assert immutable(static) and not immutable(dynamic) and immutable(preexisting)
        writer('protected', errno.EPERM)
        assert static.read_bytes() == original
        released = request(name, 'release', protected)
        assert not immutable(static) and not immutable(dynamic) and immutable(preexisting) and preexisting.stat().st_ino==preexisting_inode
        writer('released', 0)
        assert static.stat().st_ino == inode and static.read_bytes() == original
        journeys[name] = {'enable': protected['latest']['request']['id'], 'release': released['latest']['request']['id']}
    # An independent owned site exercises real enterprise inotify restoration;
    # the long scheduled interval excludes a timer check as the explanation.
    realtime_slug='live-qa-'+secrets.token_hex(5)
    assert re.fullmatch('[a-z][a-z0-9-]{2,31}',realtime_slug)
    live=post_job('owned-realtime-site','/sites',{'name':'Enterprise live restoration QA','slug':realtime_slug,'domain':realtime_slug+'.localhost'})['site_id']
    live_public=Path('/srv/panel/sites')/live/'public'
    prepare_owned_writer_public(live,live_public)
    live_owner=live_public.stat()
    watched=live_public/'watched-qa.txt';watched.write_bytes(b'Original live restoration bytes\n');os.chown(watched,live_owner.st_uid,live_owner.st_gid);watched.chmod(0o644)
    original_live=watched.read_bytes()
    baseline,=api('/app-modules/enterprise-tamper-proof/baseline',{'site_id':live,'auto_restore':True,'realtime':True,'interval':86400})['sites']
    assert baseline['auto_restore'] and baseline['realtime']
    def live_policy():
        return next(x for x in api('/app-modules/enterprise-tamper-proof/policies',{})['policies']if x['site_id']==live)
    active=wait(live_policy,lambda x:x['watcher_state']=='active'and x['signature_verified']and x['enabled'],150)
    def own_write(value):
        def drop_live():
            os.setgroups([]);os.setgid(live_owner.st_gid);os.setuid(live_owner.st_uid)
        r=subprocess.run(['/usr/bin/python3','-I','-B','-c','import os,sys;f=os.open(sys.argv[1],os.O_WRONLY|os.O_TRUNC|os.O_NOFOLLOW);os.write(f,sys.argv[2].encode());os.fsync(f);os.close(f)',str(watched),value],preexec_fn=drop_live,capture_output=True,timeout=10)
        assert r.returncode==0,r.stderr[-500:]
    own_write('Owned changed live bytes\n')
    wait(lambda:watched.read_bytes(),lambda x:x==original_live,120)
    observed=wait(live_policy,lambda x:x['last_trigger']=='inotify'and x['last_state']=='succeeded',60)
    assert watched.stat().st_uid==live_owner.st_uid and watched.stat().st_gid==live_owner.st_gid
    paused=api('/app-modules/enterprise-tamper-proof/pause',{'site_id':live,'expected_revision':observed['revision']})
    assert not paused['enabled']
    own_write('Owned paused data remains\n');time.sleep(3)
    assert watched.read_bytes()==b'Owned paused data remains\n'
    resumed=api('/app-modules/enterprise-tamper-proof/resume',{'site_id':live,'expected_revision':paused['revision']});assert resumed['enabled']
    wait(live_policy,lambda x:x['watcher_state']=='active'and x['enabled'],120)
    own_write('Owned resumed change\n');wait(lambda:watched.read_bytes(),lambda x:x==original_live,120)
    assert immutable(preexisting) and static.stat().st_ino==inode and static.read_bytes()==original
    owned={site,live}
    assert sorted((row for row in api('/sites')if row['id']not in owned),key=lambda row:row['id'])==before_sites
    evidence('verified',ok=True,architecture=plan['arch'],catalogue=catalogue['source']['resolved_commit'],site=site,realtime_site=live,signed_installs=receipts,journeys=journeys,retained_old_handle_refused=True,truncate_create_rename_unlink_external_hardlink_refused=True,excluded_upload_writable=True,same_inode_and_data_preserved=True,preexisting_immutable_inode_flag_preserved=True,cross_app_isolation=True,actual_enterprise_inotify_restoration=True,new_owned_static_public_writer_fixture=True,pause_preserved_owned_changes=True,resume_restored_owned_change=True,source_inputs_sha256=plan['programme'],hard_cold_or_browser_claim=False,all40_commercial=False)

finally:
    if held is not None:
        os.close(held)
    if child is not None:
        child.terminate()
        child.wait(timeout=10)
    api('/logout', {})
