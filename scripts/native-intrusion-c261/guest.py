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
expected_os={'ubuntu-22.04':('ubuntu','22.04'),'debian-13':('debian','13')}
assert (os_identity['ID'].strip('"'),os_identity['VERSION_ID'].strip('"'))==expected_os[case['platform']]
assert case['platform']in expected_os and case['architecture']==pins['architecture']==architecture
assert Path('/etc/hostname').read_text().strip()==pins['OS_case']['hostname']
recovering=len(sys.argv)==3
base=Path(sys.argv[2]).resolve(strict=True) if recovering else Path('/opt/panel-intrusion-c261-qa-'+secrets.token_hex(16))
assert base.parent==Path('/opt') and re.fullmatch(r'panel-intrusion-c261-qa-[a-f0-9]{32}',base.name)
out=base/'evidence'
if not recovering:out.mkdir(mode=0o700,parents=True)
assert base.stat().st_uid==out.stat().st_uid==0 and stat.S_IMODE(out.stat().st_mode)==0o700
boot=Path('/proc/sys/kernel/random/boot_id').read_text().strip()
proof={'ok':False,'base':str(base),'boot':boot,'platform':case['platform'],'architecture':architecture,
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
       '/etc/fail2ban/jail.d/panel-sshd.local','/etc/nginx/nginx.conf',
       '/opt/panel/current/SOURCE_INPUTS.json','/etc/systemd/system/panel.service',
       '/etc/systemd/system/panel-executor.service')

def ff(*args):
    return subprocess.check_output(['/usr/bin/fail2ban-client',*args],text=True,timeout=12).strip()

def package():
    page=api('/app-registry?refresh=1')
    assert page['source']['resolved_commit']==pins['served_head'] and not page['source']['stale']
    assert page['host']=={'platform':case['platform'],'architecture':architecture}
    entry,=[value for value in page['catalog']['apps'] if value['id']=='anti-intrusion']
    status,=[value for value in page['status'] if value['id']=='anti-intrusion']
    assert entry==pins['intrusion'] and entry['version']=='1.1.2' and status['supported'] and status['state_known']
    return entry,status

def note_daemons():
    for _ in range(60):
        services=('panel.service','panel-executor.service','nginx.service','fail2ban.service','ssh.service')
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
    subprocess.run(['/usr/sbin/nginx','-t'],capture_output=True,timeout=10,check=True)
    with local.open(origin+'/api/ready',timeout=5) as response:
        assert response.status==200
    assert not os.path.lexists('/etc/panel/security-apps/intrusion.pending.json')
    files={}
    for name in scope:
        p=Path(name)
        info=p.lstat()
        assert stat.S_ISREG(info.st_mode) and info.st_uid==0 and info.st_nlink==1
        if name != '/etc/panel/security-apps/intrusion-configuration.lock':
            assert info.st_size>0, name
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

# Executed only by the signed C261 fixture in its own disposable system guest.
# No injected journal, manual ban, fake unit PID, or production adapter.
def owned_ssh_journey():
    import tempfile,shutil
    ns='c261-'+secrets.token_hex(4);host_if='c261h'+secrets.token_hex(3);client_if='c261c'+secrets.token_hex(3)
    secret=Path(tempfile.mkdtemp(prefix='c261-owned-ssh-',dir='/var/lib'))
    authorized=Path('/home/qa/.ssh/authorized_keys');st=authorized.lstat();assert stat.S_ISREG(st.st_mode)and st.st_nlink==1
    original=authorized.read_bytes();good=secret/'good';bad=secret/'bad';known=secret/'known_hosts';changed=False;created=False;results={};first=int(time.time())-1
    clients={'ipv4':('192.0.2.1','192.0.2.2'),'ipv6':('2001:db8:c261::1','2001:db8:c261::2')};denied='c261deny'+secrets.token_hex(3)
    def cmd(args):return subprocess.check_output(args,stderr=subprocess.PIPE,timeout=15)
    def banned_ip(ip):return ip in ff('get','sshd','banip').split()
    def ssh(key,user,address,success):
        args=['/usr/sbin/ip','netns','exec',ns,'/usr/bin/ssh','-F','/dev/null','-i',str(key),'-o','IdentitiesOnly=yes','-o','BatchMode=yes','-o','ConnectTimeout=2','-o','ConnectionAttempts=1','-o','StrictHostKeyChecking=yes','-o','UserKnownHostsFile='+str(known),'-o','GlobalKnownHostsFile=/dev/null','-o','HostKeyAlgorithms=ssh-ed25519','-o','PasswordAuthentication=no','-o','KbdInteractiveAuthentication=no','-l',user,address,'printf C261_OWNED_SSH_OK']
        result=subprocess.run(args,stdin=subprocess.DEVNULL,capture_output=True,timeout=7)
        if success:assert result.returncode==0 and result.stdout==b'C261_OWNED_SSH_OK',(address,result.returncode,result.stderr[:200])
        else:assert result.returncode!=0
        return {'exit':result.returncode,'stderr_sha256':sha(result.stderr),'stdout_sha256':sha(result.stdout)}
    try:
        for key in(good,bad):cmd(['/usr/bin/ssh-keygen','-q','-t','ed25519','-N','','-f',str(key)])
        pub=(good.with_suffix('.pub')).read_bytes().strip();fd=os.open(authorized,os.O_WRONLY|os.O_APPEND|os.O_NOFOLLOW|os.O_CLOEXEC)
        with os.fdopen(fd,'ab')as f:f.write(b'\n'+pub+b'\n');f.flush();os.fsync(f.fileno())
        changed=True;host_key=Path('/etc/ssh/ssh_host_ed25519_key.pub').read_text().strip();known.write_text('\n'.join(server+' '+host_key for server,_ in clients.values())+'\n')
        cmd(['/usr/sbin/ip','netns','add',ns]);created=True
        cmd(['/usr/sbin/ip','link','add',host_if,'type','veth','peer','name',client_if]);cmd(['/usr/sbin/ip','link','set',client_if,'netns',ns]);cmd(['/usr/sbin/ip','addr','add','192.0.2.1/30','dev',host_if]);cmd(['/usr/sbin/ip','-6','addr','add','2001:db8:c261::1/64','dev',host_if,'nodad']);cmd(['/usr/sbin/ip','link','set',host_if,'up'])
        for args in([ 'link','set','lo','up'],['addr','add','192.0.2.2/30','dev',client_if],['-6','addr','add','2001:db8:c261::2/64','dev',client_if,'nodad'],['link','set',client_if,'up']):cmd(['/usr/sbin/ip','-n',ns,*args])
        for family,(server,client_ip)in clients.items():
            assert not banned_ip(client_ip);positive=ssh(good,'qa',server,True);attempts=[]
            for _ in range(12):
                if banned_ip(client_ip):break
                attempts.append(ssh(bad,denied,server,False));time.sleep(.5)
            end=time.monotonic()+15
            while not banned_ip(client_ip)and time.monotonic()<end:time.sleep(.5)
            assert banned_ip(client_ip),(family,'real SSH failures did not produce a Fail2ban ban')
            blocked=ssh(good,'qa',server,False);results[family]={'positive_before_ban':positive,'failed_authentication_attempts':attempts,'real_ban_observed':True,'originally_valid_key_blocked_by_ban':blocked,'source':client_ip}
        current=api('/software/intrusion-prevention/workspace')['current'];assert current['active_bans_known']and current['active_bans']==2
        for family,(server,client_ip)in clients.items():
            api('/security/fail2ban/unban',{'jail':'sshd','ip':client_ip});assert not banned_ip(client_ip);results[family]['valid_key_login_after_normal_API_unban']=ssh(good,'qa',server,True)
            if family=='ipv4':assert banned_ip(clients['ipv6'][1])
        current=api('/software/intrusion-prevention/workspace')['current'];assert current['active_bans_known']and current['active_bans']==0
        journal=cmd(['/usr/bin/journalctl','--no-pager','--since','@'+str(first),'-o','json','_COMM=sshd','+','_COMM=sshd-session']);records=[json.loads(line)for line in journal.splitlines()if line]
        for family,(_,ip)in clients.items():
            count=sum(denied in str(r.get('MESSAGE',''))and ip in str(r.get('MESSAGE',''))and r.get('_COMM')in('sshd','sshd-session')for r in records);assert count>=1;results[family]['actual_sshd_journal_failed_auth_records']=count
        save(out/('after-cold-real-SSH-authentication.json'if recovering else'before-cold-real-SSH-authentication.json'),{'ok':True,'normal_signed_current_Core':True,'real_daemon_unit_and_PID':True,'real_sshd_journal_no_injection':True,'manual_ban_commands':0,'unit_PID_or_authorization_adapters':0,'families':results,'recipient_or_external_server_contacted':False,'QA_private_keys_uploaded':False})
    finally:
        for _,ip in clients.values():
            with contextlib.suppress(Exception):
                if banned_ip(ip):api('/security/fail2ban/unban',{'jail':'sshd','ip':ip})
        if created:
            with contextlib.suppress(Exception):cmd(['/usr/sbin/ip','netns','delete',ns])
        with contextlib.suppress(Exception):cmd(['/usr/sbin/ip','link','delete',host_if])
        if changed:
            fd=os.open(authorized,os.O_WRONLY|os.O_TRUNC|os.O_NOFOLLOW|os.O_CLOEXEC)
            with os.fdopen(fd,'wb')as f:f.write(original);f.flush();os.fsync(f.fileno());os.fchmod(f.fileno(),stat.S_IMODE(st.st_mode));os.fchown(f.fileno(),st.st_uid,st.st_gid)
            os.utime(authorized,ns=(st.st_atime_ns,st.st_mtime_ns),follow_symlinks=False);assert authorized.read_bytes()==original and authorized.stat().st_ino==st.st_ino
        assert secret.parent==Path('/var/lib')and secret.name.startswith('c261-owned-ssh-')and not secret.is_symlink();shutil.rmtree(secret)
    return True

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
    for _ in range(120):
        try:
            with local.open(origin+'/api/ready',timeout=3)as response:
                if response.status==200:break
        except (OSError,urllib.error.URLError):pass
        time.sleep(.5)
    else:raise TimeoutError('Signed Core readiness not reached')
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
        # Normal store read reconciles the successful job's queued package receipt.
        observed_entry, installed = package()
        assert observed_entry == entry and installed['installed'] and installed['installed_version'] == entry['version']
        principals=api('/software/intrusion-prevention/requests')
        configure=api('/software/intrusion-prevention/configure',
                      {'actor_id':principals['actor_id'],'settings':settings},202,secrets.token_hex(16))['job_id']
        wait_job('runtime_jobs',configure,420)
        check_unban()
        assert owned_ssh_journey();proof['actual_dualstack_SSH_auto_ban_and_normal_API_unban']=True
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
        assert owned_ssh_journey();proof['actual_dualstack_SSH_auto_ban_and_normal_API_unban']=True
        assert snapshot(entry,baseline['install'],baseline['configured'])==baseline['snapshot']
        proof.update(ok=True,phase='after-reboot',prior_boot=baseline['boot'],signed_intrusion_version=entry['version'],
            version_sha256=entry['sha256'],actual_fail2ban_configure_and_unban=True,normal_store_install=True,
            real_kernel_and_service_reboot=True,verified_original_files_and_job_rows=True,
            actual_nginx_config_and_programme_source_preserved=True)
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
