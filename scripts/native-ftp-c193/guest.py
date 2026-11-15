"""Verify the signed Pure-FTPd account lifecycle and committed files across a cold boot."""
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
assert actual_platform in ('debian-13','ubuntu-22.04')
assert case['platform']==actual_platform and case['architecture']==pins['architecture']==architecture
assert Path('/etc/hostname').read_text().strip()==pins['OS_case']['hostname']
recovering=len(sys.argv)==3
base=Path(sys.argv[2]).resolve(strict=True) if recovering else Path('/opt/panel-ftp-c193-qa-'+secrets.token_hex(16))
assert base.parent==Path('/opt') and re.fullmatch(r'panel-ftp-c193-qa-[a-f0-9]{32}',base.name)
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


def report():
    out=api(module+'/run',{})
    assert out['tls_required'] and out['data_tls_required'] and out['account_limits_ready']
    assert out['service_active'] and out['boot_enabled'] and not out['recovery_pending']
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
    slug='ftp-c193-'+str(index)
    job=api('/sites',{'name':'FTPS account fixture '+str(index),'slug':slug,'domain':slug+'.example.test'},
            status=202,key=secrets.token_hex(16))['job_id']
    return wait_job('jobs',job,240)['site_id']


def tls():
    pem,=re.findall(r'-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----',(private/'server.pem').read_text())
    return ssl.create_default_context(cadata=pem)


@contextlib.contextmanager
def connected(user,password,*,source='127.0.0.1'):
    with ftplib.FTP_TLS(context=tls(),timeout=12,source_address=(source,0)) as ftp:
        ftp.connect('127.0.0.1',port)
        ftp.login(user,password)
        ftp.prot_p()
        assert ftp.pwd()=='/'
        yield ftp


def denied(user,password,*,source='127.0.0.1',codes=('530',)):
    with ftplib.FTP_TLS(context=tls(),timeout=20,source_address=(source,0)) as ftp:
        ftp.connect('127.0.0.1',port)
        try:
            ftp.login(user,password)
        except ftplib.error_perm as error:
            assert str(error).startswith(codes),str(error)
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
            raise RuntimeError('Original FTPS service inactive after reboot')
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
        wait_job('runtime_jobs',job,2500)
        assert package(True)==entry
        a,b=site(1),site(2)
        one,two='ftp-a-'+secrets.token_hex(4),'ftp-b-'+secrets.token_hex(4)
        old,new,other=tuple('C193-'+secrets.token_urlsafe(26) for _ in range(3))
        first='c193-first.txt';second='c193-second.txt'
        payload_a=b'Owned protected FTPS payload A\n'*400
        payload_b=b'Independent FTPS payload B\n'*339
        module_before=report()
        assert module_before['config']['port']==port
        api(module+'/create',{'site_id':a,'username':one,'password':old})
        api(module+'/create',{'site_id':b,'username':two,'password':other})
        with connected(two,other) as ftp:
            ftp.storbinary('STOR '+second,io.BytesIO(payload_b))
            assert retrieve(ftp,second)==payload_b
            assert_hidden(ftp,first)
        with connected(one,old) as ftp:
            ftp.storbinary('STOR '+first,io.BytesIO(payload_a))
            assert retrieve(ftp,first)==payload_a
            assert_hidden(ftp,second)
            assert_hidden(ftp,'/../'+b+'/public/'+second)
            pin=account_bytes()
            assert api(module+'/create',{'site_id':b,'username':one,'password':new},status=409)['error']
            assert api(module+'/password',{'username':one,'password':'short'},status=409)['error']
            assert account_bytes()==pin
            change=api(module+'/password',{'username':one,'password':new})
            assert change['ok'] and change['new_connections_only']
            assert retrieve(ftp,first)==payload_a
        denied(one,old)
        with connected(one,new) as ftp:
            assert retrieve(ftp,first)==payload_a
            try:
                ftp.prot_c()
                ftp.retrbinary('RETR '+first,lambda _: None)
            except ftplib.error_perm as exc:
                assert str(exc).startswith(('521','534','550')),str(exc)
            else:
                raise AssertionError('Cleartext data transfer accepted')
        with ftplib.FTP_TLS(context=tls(),timeout=12) as ftp:
            ftp.connect('127.0.0.1',port)
            ftp.host='wrong-c193.example.test'
            try:
                ftp.auth()
            except ssl.SSLCertVerificationError as exc:
                assert exc.verify_code in (62,64), exc.verify_code
            else:
                raise AssertionError('Unmatched TLS name accepted')
        before=report()
        account,=[row for row in before['users'] if row['username']==one]
        stale={'username':one,'expected_sha':'f'*64,'max_sessions':1}
        pin=account_bytes()
        assert api(module+'/account-limits',stale,status=409)['error'] and account_bytes()==pin
        invalid={'username':one,'expected_sha':account['expected_sha'],'client_allow':['not-an-ip.example']}
        assert api(module+'/account-limits',invalid,status=409)['error'] and account_bytes()==pin
        limits={'username':one,'expected_sha':account['expected_sha'],'client_allow':['127.0.0.0/8'],
                'client_deny':['127.0.0.2'],'max_sessions':1}
        assert api(module+'/account-limits',limits)['ok']
        denied(one,new,source='127.0.0.2')
        with connected(one,new) as ftp:
            denied(one,new,codes=('421','530'))
            assert retrieve(ftp,first)==payload_a
        config=report()['config']
        service_pem=sha((private/'server.pem').read_bytes())
        with socket.socket() as listener:
            listener.bind(('127.0.0.1',0))
            listener.listen(5)
            proposal={k:v for k,v in config.items() if k!='revision'}
            proposal['expected_revision']=config['revision']
            proposal['port']=listener.getsockname()[1]
            assert api(module+'/service-config',proposal,status=409)['error']
        assert report()['config']==config and sha((private/'server.pem').read_bytes())==service_pem
        with connected(one,new) as ftp:
            assert retrieve(ftp,first)==payload_a
        result=api(module+'/delete',{'username':one})
        assert result['ok'] and result['new_connections_only']
        denied(one,new)
        kept=report()['users']
        assert len(kept)==1 and kept[0]['username']==two and kept[0]['site_id']==b
        with connected(two,other) as ftp:
            assert retrieve(ftp,second)==payload_b
        snapshot_before=snapshot(entry,[a,b],[first,second])
        assert snapshot_before['files'][first]['sha256']==sha(payload_a)
        assert snapshot_before['files'][second]['sha256']==sha(payload_b)
        save(statefile,{'deleted':one,'deleted_password':new,'remaining':two,'remaining_password':other,'sites':[a,b],'files':[first,second]})
        save(out/'before-reboot.json',{'boot':boot,'snapshot':snapshot_before,'manifest_sha256':entry['sha256']})
        proof.update(ok=True,powerloss_ready=True,phase='before-reboot',signed_ftp_version=entry['version'],
                     actual_tls_and_chroot=True,rotation_preserved_active_connection=True,wrong_dns_and_clear_data_refused=True,
                     failed_mutations_preserved_account_files=True,client_ip_and_session_enforced=True,
                     port_collision_restored_previous_service=True,deletion_preserved_both_sites=True)
    else:
        entry=package(True)
        assert stat.S_IMODE(statefile.stat().st_mode)==0o600
        state=json.loads(statefile.read_bytes())
        before=json.loads((out/'before-reboot.json').read_bytes())
        assert before['boot']!=boot and before['manifest_sha256']==entry['sha256']
        current=snapshot(entry,state['sites'],state['files'])
        assert current==before['snapshot']
        denied(state['deleted'],state['deleted_password'])
        with connected(state['remaining'],state['remaining_password']) as ftp:
            payload=retrieve(ftp,state['files'][1])
            assert sha(payload)==before['snapshot']['files'][state['files'][1]]['sha256']
            assert_hidden(ftp,state['files'][0])
        proof.update(ok=True,phase='after-reboot',prior_boot=before['boot'],signed_ftp_version=entry['version'],
                     version_sha256=entry['sha256'],actual_ftps_reconnected=True,removed_account_still_refused=True,
                     original_files_config_and_auth_database_preserved=True)
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
