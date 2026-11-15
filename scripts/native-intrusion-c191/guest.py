"""Verify the current signed intrusion application against Ubuntu 24.04 Fail2ban and reboot."""
from pathlib import Path
import contextlib
import hashlib
import http.cookiejar
import json
import os
import platform
import re
import secrets
import sqlite3
import stat
import subprocess
import sys
import time
import traceback
import urllib.error
import urllib.request

os.umask(0o077)
architecture={'x86_64':'amd64','aarch64':'arm64'}[platform.machine()]
assert os.geteuid()==0 and len(sys.argv) in (2,3)
inputs=Path(sys.argv[1]).resolve(strict=True)
pins=json.loads((inputs/'assets.json').read_text())
os_identity=dict(line.split('=',1) for line in Path('/etc/os-release').read_text().splitlines() if '=' in line and not line.startswith('#'))
case=pins['OS_case']
assert os_identity['ID']=='ubuntu' and os_identity['VERSION_ID'].strip('"')=='24.04'
assert case['platform']=='ubuntu-24.04' and case['architecture']==pins['architecture']==architecture
assert Path('/etc/hostname').read_text().strip()==pins['OS_case']['hostname']
recovering=len(sys.argv)==3
base=Path(sys.argv[2]).resolve(strict=True) if recovering else Path('/opt/panel-intrusion-c191-qa-'+secrets.token_hex(16))
assert base.parent==Path('/opt') and re.fullmatch(r'panel-intrusion-c191-qa-[a-f0-9]{32}',base.name)
out=base/'evidence'
if not recovering:out.mkdir(mode=0o700,parents=True)
assert base.stat().st_uid==out.stat().st_uid==0 and stat.S_IMODE(out.stat().st_mode)==0o700
boot=Path('/proc/sys/kernel/random/boot_id').read_text().strip()
proof={'ok':False,'base':str(base),'boot':boot,'platform':'ubuntu-24.04','architecture':architecture,
       'source_inputs_sha256':pins['source_inputs_sha256'],'Main_changed':False,'all50_commercial':False}
client=urllib.request.build_opener(urllib.request.ProxyHandler({}),urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))
local=urllib.request.build_opener(urllib.request.ProxyHandler({}))
origin='http://127.0.0.1:19100'
csrf=''
def sha(x):return hashlib.sha256(x).hexdigest()
def save(path,v):
    with path.open('x') as f:json.dump(v,f,indent=2);f.write('\n');f.flush();os.fsync(f.fileno())
def api(path,body=None,status=200,key=None):
    headers={'Origin':origin,'Content-Type':'application/json','X-CSRF-Token':csrf}
    if key:headers['Idempotency-Key']=key
    req=urllib.request.Request(origin+'/api'+path,None if body is None else json.dumps(body).encode(),headers)
    with client.open(req,timeout=90)as res:
        assert res.status==status and res.url==req.full_url
        return json.load(res)
def wait_job(table,job,seconds):
    assert table in ('jobs','runtime_jobs') and re.fullmatch('[a-f0-9]{32}',job)
    end=time.monotonic()+seconds
    while time.monotonic()<end:
        with contextlib.closing(sqlite3.connect('file:/var/lib/panel/panel.db?mode=ro',uri=True)) as db:
            db.row_factory=sqlite3.Row;db.execute('PRAGMA query_only=ON')
            row=db.execute('SELECT * FROM '+table+' WHERE id=?',(job,)).fetchone()
        if row is not None and row['state'] not in ('queued','running'):
            assert row['state']=='succeeded' and not row['error'],row['error']
            return dict(row)
        time.sleep(1)
    raise TimeoutError(table)
def command(label,args,timeout=120):
    with(out/(label+'.stdout')).open('xb') as stdout,(out/(label+'.stderr')).open('xb') as stderr:
        result=subprocess.run(args,stdin=subprocess.DEVNULL,stdout=stdout,stderr=stderr,timeout=timeout)
    assert result.returncode==0,label
def sign_input_copy():
    dest=base/'verified-input';dest.mkdir(mode=0o700)
    for name,digest in pins['files'].items():
        assert re.fullmatch(r'[A-Za-z0-9._-]+',name) and re.fullmatch('[a-f0-9]{64}',digest)
        with os.fdopen(os.open(inputs/name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC),'rb') as f:
            st=os.fstat(f.fileno())
            assert stat.S_ISREG(st.st_mode) and st.st_nlink==1 and 0<st.st_size<=64<<20
            raw=f.read((64<<20)+1)
        assert len(raw)==st.st_size and sha(raw)==digest
        with(dest/name).open('xb') as f:f.write(raw);f.flush();os.fsync(f.fileno())
    assert sha((dest/'release-signing-dev.pub').read_bytes())=='4ccfcc861d56a41e3ba7f7ace7e2432c815f366c58448d783df92c6632f01339'
    return dest
settings={'max_retry':6,'find_time_minutes':9,'ban_time_minutes':30}
native_limits={'maxretry':6,'findtime':540,'bantime':1800}
firewall_ip='198.51.100.43'
scope=('/etc/panel/security-apps/intrusion-configuration.lock','/etc/panel/security-apps/intrusion-prevention.json',
       '/etc/panel/security-apps/intrusion-policy.json','/etc/fail2ban/jail.d/panel-intrusion.local',
       '/etc/fail2ban/jail.d/panel-sshd.local')

def ff(*args):
    return subprocess.check_output(['/usr/bin/fail2ban-client',*args],text=True,timeout=12).strip()

def package():
    page=api('/app-registry?refresh=1')
    assert page['source']['resolved_commit']==pins['served_head'] and not page['source']['stale']
    assert page['host']=={'platform':'ubuntu-24.04','architecture':architecture}
    entry,=[value for value in page['catalog']['apps'] if value['id']=='anti-intrusion']
    status,=[value for value in page['status'] if value['id']=='anti-intrusion']
    assert entry==pins['intrusion'] and entry['version']=='1.1.2' and status['supported'] and status['state_known']
    return entry,status

def note_daemons():
    for _ in range(60):
        services=('panel.service','panel-executor.service','fail2ban.service','ssh.service')
        if all(subprocess.run(['/usr/bin/systemctl','is-active','--quiet',service],timeout=8).returncode==0 for service in services):
            return
        time.sleep(2)
    raise RuntimeError('Native services not ready')

def snapshot(entry,job,configured):
    note_daemons()
    data=api('/software/intrusion-prevention/workspace')
    current=data['current']
    assert data['state_known'] and data['pending'] is None and current['installed'] and current['version']==entry['version']
    assert current['settings']==settings and current['runtime_settings']==native_limits
    assert current['ssh_ports_match'] and current['active_bans_known'] and current['active_bans']==0
    assert current['ssh_effective_ports']==current['ssh_listening_ports']
    committed={r['id'] for r in data['history'] if r['state']=='committed'}
    assert {job,configured}<=committed
    assert {name:int(ff('get','sshd',name)) for name in native_limits}==native_limits
    assert not os.path.lexists('/etc/panel/security-apps/intrusion.pending.json')
    files={}
    for name in scope:
        p=Path(name)
        info=p.lstat()
        assert stat.S_ISREG(info.st_mode) and info.st_uid==0 and info.st_nlink==1
        files[name]=[info.st_ino,info.st_size,info.st_mode,info.st_uid,info.st_gid,sha(p.read_bytes())]
    with contextlib.closing(sqlite3.connect('file:/var/lib/panel/panel.db?mode=ro',uri=True)) as db:
        db.execute('PRAGMA query_only=ON')
        assert db.execute('PRAGMA quick_check').fetchone()==('ok',)
        assert db.execute("SELECT version,sha256 FROM app_registry_receipts WHERE app_id='anti-intrusion'").fetchall()==[(entry['version'],entry['sha256'])]
        assert db.execute("SELECT state FROM runtime_jobs WHERE id IN (?,?)",(job,configured)).fetchall()==[('succeeded',),('succeeded',)]
        rows={table:sha(json.dumps(db.execute('SELECT * FROM '+table+' ORDER BY 1').fetchall(),separators=(',',':')).encode())
              for table in ('runtime_jobs','app_registry_install_requests','app_registry_receipts','sites')}
    return {'files':files,'rows':rows,'settings':current['settings'],'limits':native_limits,'ssh_ports':current['ssh_effective_ports']}

def banned():
    return re.search(r'(?<![.0-9])'+re.escape(firewall_ip)+r'(?![.0-9])',ff('get','sshd','banip')) is not None

def check_unban():
    # Exercise one documentation-range address in this temporary guest only.
    assert not banned()
    ff('set','sshd','banip',firewall_ip)
    assert banned()
    state=api('/software/intrusion-prevention/workspace')['current']
    assert state['active_bans_known'] and state['active_bans']==1
    ack=api('/security/fail2ban/unban',{'jail':'sshd','ip':firewall_ip})
    assert not banned() and ack.get('ok',True)
    state=api('/software/intrusion-prevention/workspace')['current']
    assert state['active_bans_known'] and state['active_bans']==0

try:
    if not recovering:
        assert not any(os.path.lexists(p) for p in ('/opt/panel','/etc/panel','/var/lib/panel'))
        copy=sign_input_copy()
        archive=copy/('panel-'+pins['version']+'-linux-'+architecture+'.tar.gz')
        signer=['python3','-I','-B',str(copy/'signed-release.py')]
        trust=['--public-key',str(copy/'release-signing-dev.pub')]
        command('signed-verify',signer+['verify',str(archive)]+trust)
        command('signed-preflight',signer+['install',str(archive)]+trust+['--preflight-only'],900)
        command('signed-install',signer+['install',str(archive)]+trust,1800)
    else:
        note_daemons()
    assert json.loads(Path('/opt/panel/current/SOURCE_INPUTS.json').read_text())['inputs_sha256']==pins['source_inputs_sha256']
    creds=json.loads(Path('/etc/panel/first-login.json').read_text())
    try:
        csrf=api('/login',{key:creds[key] for key in ('username','password')})['csrf']
    finally:
        creds.clear()
    entry,status=package()
    if not recovering:
        assert not status['installed']
        install_key=secrets.token_hex(16)
        request={'expected_version':entry['version'],'expected_sha256':entry['sha256'],
                 'settings':{'max_retry':5,'find_time_minutes':10,'ban_time_minutes':60}}
        install=api('/app-registry/anti-intrusion/install',request,202,install_key)['job_id']
        wait_job('runtime_jobs',install,900)
        principals=api('/software/intrusion-prevention/requests')
        configure=api('/software/intrusion-prevention/configure',
                      {'actor_id':principals['actor_id'],'settings':settings},202,secrets.token_hex(16))['job_id']
        wait_job('runtime_jobs',configure,420)
        check_unban()
        baseline=snapshot(entry,install,configure)
        save(out/'before-reboot.json',{'boot':boot,'install':install,'configured':configure,
            'snapshot':baseline,'package_sha256':entry['sha256']})
        proof.update(ok=True,powerloss_ready=True,phase='before-reboot',signed_intrusion_version=entry['version'],
            actual_fail2ban_configure_and_unban=True,normal_store_install=True)
    else:
        assert status['installed'] and status['installed_version']==entry['version'] and not status['update_available']
        baseline=json.loads((out/'before-reboot.json').read_bytes())
        assert baseline['boot']!=boot and baseline['package_sha256']==entry['sha256']
        observed=snapshot(entry,baseline['install'],baseline['configured'])
        assert observed==baseline['snapshot']
        proof.update(ok=True,phase='after-reboot',prior_boot=baseline['boot'],signed_intrusion_version=entry['version'],
            version_sha256=entry['sha256'],actual_fail2ban_configure_and_unban=True,normal_store_install=True,
            real_kernel_and_service_reboot=True,verified_original_files_and_job_rows=True)
except BaseException:
    proof['failure']=traceback.format_exc()
finally:
    if csrf:
        try:
            api('/logout',{})
        except Exception:
            proof['ok']=False
    save(out/('phase2.json' if recovering else 'phase1.json'),proof)
    print(json.dumps(proof),flush=True)
sys.exit(0 if proof['ok'] else 1)
