"""Verify current signed Pure-FTPd soft quotas and actual encrypted bandwidth limits."""
from pathlib import Path
import contextlib
import ftplib
import io
import socket
import ssl
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
actual_platform=os_identity['ID']+'-'+os_identity['VERSION_ID'].strip('"')
assert actual_platform in ('debian-12','ubuntu-24.04')
assert case['platform']==actual_platform and case['architecture']==pins['architecture']==architecture
assert Path('/etc/hostname').read_text().strip()==pins['OS_case']['hostname']
recovering=len(sys.argv)==3
base=Path(sys.argv[2]).resolve(strict=True) if recovering else Path('/opt/panel-ftp-c194-qa-'+secrets.token_hex(16))
assert base.parent==Path('/opt') and re.fullmatch(r'panel-ftp-c194-qa-[a-f0-9]{32}',base.name)
out=base/'evidence'
if not recovering:out.mkdir(mode=0o700,parents=True)
assert base.stat().st_uid==out.stat().st_uid==0 and stat.S_IMODE(out.stat().st_mode)==0o700
boot=Path('/proc/sys/kernel/random/boot_id').read_text().strip()
proof={'ok':False,'base':str(base),'boot':boot,'platform':actual_platform,'architecture':architecture,
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
    try:
        with client.open(req,timeout=90) as res:
            assert res.status==status and res.url==req.full_url
            return json.load(res)
    except urllib.error.HTTPError as error:
        if error.code==status:
            return json.loads(error.read(8192))
        raise

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
module='/app-modules/pure-ftpd'
private=Path('/etc/panel/security-apps/modules/pure-ftpd')
unit='panel-pure-ftpd.service'
statefile=base/'owned-credentials.json'
port=2121


def package(installed):
    page=api('/app-registry?refresh=1')
    assert not page['source']['stale'] and page['source']['resolved_commit']==pins['served_head']
    assert page['host']=={'platform':actual_platform,'architecture':architecture}
    entry,=[item for item in page['catalog']['apps'] if item['id']=='pure-ftpd']
    status,=[item for item in page['status'] if item['id']=='pure-ftpd']
    assert entry==pins['ftp'] and entry['version']=='1.0.54-compat7'
    assert status['supported'] and status['state_known'] and bool(status['installed'])==installed
    if installed:
        assert status['installed_version']==entry['version'] and not status['update_available']
    return entry


def report(active=True):
    out=api(module+'/run',{})
    assert out['tls_required'] and out['data_tls_required'] and out['account_limits_ready']
    assert out['service_active']==active and out['boot_enabled']==active and not out['recovery_pending']
    assert out['runtime_binary']=='/opt/panel/app-modules/pure-ftpd/1.0.54-yz1/pure-ftpd'
    public=json.dumps(out,separators=(',',':'))
    for row in out['users']:
        assert not set(row)&{'password','hash','password_hash','shadow'}
        assert row['site_id'] and re.fullmatch('[a-f0-9]{64}',row['expected_sha'])
    for line in (private/'users.passwd').read_text().splitlines():
        secret_hash=line.split(':')[1]
        assert len(secret_hash)>12 and secret_hash not in public
    return out


def site(index):
    slug='ftp-c194-'+str(index)
    job=api('/sites',{'name':'FTPS account fixture '+str(index),'slug':slug,'domain':slug+'.example.test'},
            status=202,key=secrets.token_hex(16))['job_id']
    return wait_job('jobs',job,240)['site_id']


def tls():
    pem,=re.findall(r'-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----',(private/'server.pem').read_text())
    return ssl.create_default_context(cadata=pem)


@contextlib.contextmanager
def connected(user,password,*,source='127.0.0.1'):
    with ftplib.FTP_TLS(context=tls(),timeout=20,source_address=(source,0)) as ftp:
        ftp.connect('127.0.0.1',port)
        ftp.login(user,password)
        ftp.prot_p()
        assert ftp.pwd()=='/'
        yield ftp


def denied(user,password,*,source='127.0.0.1',code='530',reason=None):
    with ftplib.FTP_TLS(context=tls(),timeout=20,source_address=(source,0)) as ftp:
        ftp.connect('127.0.0.1',port)
        try:
            ftp.login(user,password)
        except (ftplib.error_perm,ftplib.error_temp) as error:
            assert str(error).startswith(code),str(error)
            if reason is not None:
                assert reason in str(error),str(error)
        else:
            raise AssertionError('Denied account unexpectedly logged in')


def retrieve(ftp,path):
    data=io.BytesIO()
    assert ftp.retrbinary('RETR '+path,data.write).startswith('226')
    return data.getvalue()


def assert_hidden(ftp,path):
    data=io.BytesIO()
    try:
        ftp.retrbinary('RETR '+path,data.write)
    except ftplib.error_perm as err:
        assert str(err).startswith('550'),str(err)
    else:
        raise AssertionError('Other site accessible in jailed session')
    assert not data.getvalue()


def account_bytes():
    return {name:sha((private/name).read_bytes()) for name in ('users.passwd','users.pdb')}


def snapshot(entry,sites,files):
    out=report()
    directory=Path('/srv/panel/sites')
    witness={name:sha((private/name).read_bytes()) for name in ('users.passwd','users.pdb','server.pem','runtime.json')}
    for ident,filename in zip(sites,files):
        item=directory/ident/'public'/filename
        st=item.lstat()
        assert stat.S_ISREG(st.st_mode) and st.st_uid!=0
        witness[filename]={'sha256':sha(item.read_bytes()),'uid':st.st_uid,'gid':st.st_gid,'inode':st.st_ino}
    with contextlib.closing(sqlite3.connect('file:/var/lib/panel/panel.db?mode=ro',uri=True)) as db:
        assert db.execute('PRAGMA quick_check').fetchone()==('ok',)
        rows=db.execute("SELECT version,sha256 FROM app_registry_receipts WHERE app_id='pure-ftpd'").fetchall()
        assert rows==[(entry['version'],entry['sha256'])]
    return {'files':witness,'config':out['config'],'registered_accounts':[[v['username'],v['site_id']] for v in out['users']]}

def account(user,active=True):
    row,=[u for u in report(active)['users'] if u['username']==user]
    return row


def change_limits(user,**limits):
    row=account(user)
    result=api(module+'/account-limits',{'username':user,'expected_sha':row['expected_sha'],**limits})
    assert result['ok'] and result['new_connections_only']


def recount(user,code=200,active=False):
    row=account(user,active)
    return api(module+'/recount-quota',{'username':user,'expected_sha':row['expected_sha']},status=code)


def counter(path):
    raw=path.read_bytes()
    assert len(raw)<128
    entries,size=map(int,raw.split())
    return entries,size


def quantity(root):
    entries,size=0,0
    for item in root.rglob('*'):
        if item.name=='.ftpquota' or item.is_symlink():
            continue
        info=item.lstat()
        assert info.st_nlink==1 or stat.S_ISDIR(info.st_mode)
        entries+=1
        if stat.S_ISREG(info.st_mode):
            size+=info.st_size
    return entries,size


def refused_store(ftp,name,payload):
    reply=None
    try:
        ftp.storbinary('STOR '+name,io.BytesIO(payload),blocksize=4096)
    except (ftplib.error_perm,ftplib.error_temp) as error:
        reply=str(error)
    except (BrokenPipeError,ConnectionResetError,ssl.SSLError):
        # A server may close the data socket first. Still require its FTP reply.
        try:
            ftp.voidresp()
        except (ftplib.error_perm,ftplib.error_temp) as error:
            reply=str(error)
    assert reply is not None and reply.startswith(('452','552')),reply
    return reply[:3]


def transfer_time(user,password,limit):
    payload=(b"Signed FTPS limit fixture: "+str(limit).encode()+b"\n")*5000
    payload=payload[:limit*1024*8]
    assert len(payload)==limit*1024*8
    name='rate-'+str(limit)+'.bin'
    with connected(user,password) as ftp:
        start=time.monotonic()
        store=ftp.storbinary('STOR '+name,io.BytesIO(payload),blocksize=1024)
        upload=time.monotonic()-start
        assert store.startswith('226')
    with connected(user,password) as ftp:
        start=time.monotonic()
        copied=retrieve(ftp,name)
        download=time.monotonic()-start
        assert copied==payload
        ftp.delete(name)
    assert 5.0<=upload<=27.0 and 5.0<=download<=27.0,(limit,round(upload,2),round(download,2))
    return {'upload_elapsed_s':round(upload,3),'download_elapsed_s':round(download,3),'bytes_each':len(payload)}


try:
    if not recovering:
        assert not any(os.path.lexists(p) for p in ('/opt/panel','/etc/panel','/var/lib/panel'))
        staged=sign_input_copy()
        archive=staged/('panel-'+pins['version']+'-linux-'+architecture+'.tar.gz')
        signer=['python3','-I','-B',str(staged/'signed-release.py')]
        trust=['--public-key',str(staged/'release-signing-dev.pub')]
        command('signed-verify',signer+['verify',str(archive)]+trust)
        command('signed-install-preflight',signer+['install',str(archive)]+trust+['--preflight-only'],900)
        command('signed-install',signer+['install',str(archive)]+trust,1800)
    else:
        for _ in range(65):
            if not subprocess.run(['/usr/bin/systemctl','is-active','--quiet',unit],timeout=5).returncode:
                break
            time.sleep(2)
        else:
            raise RuntimeError('FTPS service inactive after boot')
    assert json.loads(Path('/opt/panel/current/SOURCE_INPUTS.json').read_text())['inputs_sha256']==pins['source_inputs_sha256']
    creds=json.loads(Path('/etc/panel/first-login.json').read_text())
    try:
        csrf=api('/login',{key:creds[key] for key in ('username','password')})['csrf']
    finally:
        creds.clear()

    if not recovering:
        entry=package(False)
        job=api('/app-registry/pure-ftpd/install',{'expected_version':entry['version'],'expected_sha256':entry['sha256']},
                status=202,key=secrets.token_hex(16))['job_id']
        wait_job('runtime_jobs',job,1900)
        assert package(True)==entry
        ident=site(1)
        user='ftp-quota-'+secrets.token_hex(4)
        password='C194-'+secrets.token_urlsafe(26)
        filename='ftps-baseline.bin'
        original=b'owned signed bytes\n'*232
        api(module+'/create',{'site_id':ident,'username':user,'password':password})
        with connected(user,password) as ftp:
            ftp.storbinary('STOR '+filename,io.BytesIO(original))
            assert retrieve(ftp,filename)==original
        root=Path('/srv/panel/sites')/ident/'public'
        counter_path=root/'.ftpquota'
        assert recount(user,409,active=True)['error']
        stopped=api(module+'/stop',{})
        assert stopped['ok'] and stopped['accounts_retained']
        initial=quantity(root)
        recounted=recount(user)
        assert recounted['ok'] and recounted['soft_quota'] and recounted['shared_home_counter']
        assert recounted['service_active'] is False
        assert (recounted['quota_usage_files'],recounted['quota_usage_bytes'])==initial==counter(counter_path)
        initial_counter=counter_path.read_bytes()
        old_inode=counter_path.stat().st_ino
        os.link(root/filename,root/'owned-hardlink.bin')
        try:
            assert '硬链接' in recount(user,409)['error']
        finally:
            (root/'owned-hardlink.bin').unlink()
        assert counter_path.read_bytes()==initial_counter and counter_path.stat().st_ino==old_inode
        recounted_again=recount(user)
        assert recounted_again['ok'] and recounted_again['backup_id']!=recounted['backup_id']
        assert counter_path.read_bytes()==initial_counter and counter_path.stat().st_ino!=old_inode
        assert not report(False)['boot_enabled']
        assert api(module+'/start',{})['tls_verified']

        change_limits(user,quota_files=initial[0]+1)
        accepted=b'one additional object\n'
        with connected(user,password) as ftp:
            ftp.storbinary('STOR accepted.bin',io.BytesIO(accepted))
            assert retrieve(ftp,'accepted.bin')==accepted
            file_reply=refused_store(ftp,'over-count.bin',b'above file limit')
        assert counter(counter_path)==(initial[0]+1,initial[1]+len(accepted))
        assert not (root/'over-count.bin').exists()

        change_limits(user,quota_mb=1)
        with connected(user,password) as ftp:
            size_reply=refused_store(ftp,'over-size.bin',b'q'*(1024*1024+1024))
        assert not (root/'over-size.bin').exists()
        assert counter(counter_path)==(initial[0]+1,initial[1]+len(accepted))
        change_limits(user)
        with connected(user,password) as ftp:
            ftp.storbinary('STOR unblocked.bin',io.BytesIO(b'limits removed'))
            assert retrieve(ftp,'unblocked.bin')==b'limits removed'
            ftp.delete('unblocked.bin')
            assert retrieve(ftp,filename)==original

        measurements={}
        for limit in (1,8):
            change_limits(user,upload_kb=limit,download_kb=limit)
            measurements[str(limit)]=transfer_time(user,password,limit)
        change_limits(user,quota_files=initial[0]+1,quota_mb=1)
        snapshot_before=snapshot(entry,[ident],[filename])
        counts=counter(counter_path)
        assert counts==quantity(root)
        save(statefile,{'user':user,'password':password,'site':ident,'file':filename})
        save(out/'before-reboot.json',{'boot':boot,'snapshot':snapshot_before,'manifest_sha256':entry['sha256'],
                                      'counter':list(counts),'counter_sha256':sha(counter_path.read_bytes())})
        proof.update(ok=True,powerloss_ready=True,phase='before-reboot',signed_ftp_version=entry['version'],
                     active_recount_denied=True,atomic_stopped_recount=True,unsafe_hardlink_rejected=True,
                     actual_file_overlimit_code=file_reply,actual_byte_overlimit_code=size_reply,
                     removal_of_limits_confirmed=True,duplex_bandwidth=measurements)
    else:
        entry=package(True)
        assert stat.S_IMODE(statefile.stat().st_mode)==0o600
        state=json.loads(statefile.read_bytes())
        before=json.loads((out/'before-reboot.json').read_bytes())
        assert before['boot']!=boot and before['manifest_sha256']==entry['sha256']
        countfile=Path('/srv/panel/sites')/state['site']/'public'/'.ftpquota'
        assert list(counter(countfile))==before['counter'] and sha(countfile.read_bytes())==before['counter_sha256']
        assert snapshot(entry,[state['site']],[state['file']])==before['snapshot']
        with connected(state['user'],state['password']) as ftp:
            data=retrieve(ftp,state['file'])
            assert sha(data)==before['snapshot']['files'][state['file']]['sha256']
            assert refused_store(ftp,'reboot-over-count.bin',b'again')
        proof.update(ok=True,phase='after-reboot',prior_boot=before['boot'],signed_ftp_version=entry['version'],
                     version_sha256=entry['sha256'],actual_ftps_reconnected=True,
                     original_file_and_soft_counters_preserved=True,actual_limits_enforced_after_boot=True)
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
