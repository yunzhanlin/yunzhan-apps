"""Verify per-site compressed archive inventory using real Nginx request logs."""
from pathlib import Path
import contextlib
import gzip
import hashlib
import http.client
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
assert os.geteuid()==0 and len(sys.argv)==2
inputs=Path(sys.argv[1]).resolve(strict=True)
pins=json.loads((inputs/'plan.json').read_text())
case=pins['OS_case']
identity=dict(line.split('=',1) for line in Path('/etc/os-release').read_text().splitlines() if line and not line.startswith('#') and '=' in line)
assert identity['ID']=='ubuntu' and identity['VERSION_ID'].strip('"')=='24.04'
assert case['platform']=='ubuntu-24.04' and case['architecture']==pins['architecture']==architecture
assert json.loads(Path('/opt/panel/current/SOURCE_INPUTS.json').read_bytes())['inputs_sha256']==pins['source_inputs_sha256']
base=Path(pins['case_base'])
assert base.parent==Path('/opt') and re.fullmatch(r'panel-statistics-c643-qa-[a-f0-9]{32}',base.name)
out=base/'evidence'
out.mkdir(mode=0o700,parents=True)
assert base.stat().st_uid==out.stat().st_uid==0 and stat.S_IMODE(out.stat().st_mode)==0o700
boot=Path('/proc/sys/kernel/random/boot_id').read_text().strip()
proof={'ok':False,'base':str(base),'boot':boot,'platform':'ubuntu-24.04','architecture':architecture,
       'source_inputs_sha256':pins['source_inputs_sha256'],'Main_changed':False,'all40_commercial':False}
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


def new_site(number):
    slug='c189-'+str(number)+'-'+secrets.token_hex(5)
    domain=slug+'.example.test'
    job=api('/sites',{'name':'C189 statistics fixture '+str(number),'slug':slug,'domain':domain},202,secrets.token_hex(16))
    site_id=wait_job('jobs',job['job_id'],180)['site_id']
    page=slug+'.txt'
    created=api('/sites/'+site_id+'/files/action',{'action':'create','path':page,'content':'C189 original Nginx content\n'})
    assert created['sha256']==sha(b'C189 original Nginx content\n')
    vhost=Path('/etc/panel/sites-enabled')/(site_id+'.conf')
    assert re.search(r'^\s*listen 127\.0\.0\.1:19101;',vhost.read_text(),re.M)
    return site_id,domain,'/'+page,vhost

def request(site):
    site_id,domain,path,_=site
    conn=http.client.HTTPConnection('127.0.0.1',19101,timeout=8)
    try:
        conn.request('GET',path+'?fixture-token=owned-c189-never-export',headers={'Host':domain,'User-Agent':'C189 owned browser'})
        reply=conn.getresponse()
        assert reply.status==200 and reply.read(256)==b'C189 original Nginx content\n'
    finally:
        conn.close()
    file=Path('/var/log/nginx')/('panel-'+site_id+'.access.log')
    end=time.monotonic()+10
    while time.monotonic()<end:
        if file.is_file():
            for line in reversed(file.read_bytes().splitlines()):
                request=json.loads(line)
                if request.get('path')==path:
                    assert re.fullmatch('[0-9a-f]{32}',request['request_id'])
                    assert b'owned-c189-never-export' not in line
                    return file,line+b'\n'
        time.sleep(.1)
    raise TimeoutError('Actual Nginx request ID was not recorded')

def archive(path,suffix,contents):
    target=path.with_name(path.name+suffix+'.gz')
    with os.fdopen(os.open(target,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600),'wb') as f:
        f.write(contents)
        f.flush()
        os.fsync(f.fileno())
    timestamp=time.time()-25
    os.utime(target,(timestamp,timestamp),follow_symlinks=False)
    return target

def inspect(site):
    site_id,_,path,_=site
    data=api('/app-modules/website-statistics-v2/run',{'site_id':site_id,'search':path})
    assert data['site_id']==site_id and data['history_gzip_import_enabled'] and data['history_persistent']
    inventory=data['history_archive_inventory']
    assert inventory['site_id']==site_id and inventory['checked_at']==data['history_checked_at']
    assert not inventory['omitted']
    prefix='panel-'+site_id+'.access.log'
    assert all(row['name'].startswith(prefix) for row in inventory['sources'])
    assert 'owned-c189-never-export' not in json.dumps(inventory) and '/var/log' not in json.dumps(inventory)
    return data,{row['name']:row for row in inventory['sources']}

def wait_inventory(site,expected):
    for _ in range(7):
        data,rows=inspect(site)
        if {name:row['state'] for name,row in rows.items()}==expected:
            return data,rows
        time.sleep(1)
    raise AssertionError('Archive states did not settle: '+repr({name:row['state'] for name,row in rows.items()}))

try:
    assert json.loads(Path('/opt/panel/current/SOURCE_INPUTS.json').read_text())['inputs_sha256']==pins['source_inputs_sha256']
    credentials=json.loads(Path('/etc/panel/first-login.json').read_text())
    csrf=api('/login',{key:credentials[key] for key in ('username','password')})['csrf']
    credentials.clear()
    catalog=api('/app-registry?refresh=1')
    assert catalog['host']=={'platform':'ubuntu-24.04','architecture':architecture}
    assert not catalog['source']['stale'] and catalog['source']['resolved_commit']==pins['served_head']
    item,=[row for row in catalog['catalog']['apps'] if row['id']=='website-statistics-v2']
    assert item==pins['statistics'] and item['version']=='2.6.0'
    job=api('/app-registry/website-statistics-v2/install',{'expected_version':item['version'],'expected_sha256':item['sha256']},202,secrets.token_hex(16))
    wait_job('runtime_jobs',job['job_id'],900)
    catalog=api('/app-registry?refresh=1')
    installed,=[row for row in catalog['status'] if row['id']==item['id']]
    assert installed['installed'] and installed['installed_version']==item['version'] and not installed['update_available']
    primary,neighbor=new_site(1),new_site(2)
    primary_log,primary_row=request(primary)
    neighbor_log,neighbor_row=request(neighbor)
    primary_original=primary_log.read_bytes()
    neighbor_original=neighbor_log.read_bytes()
    configs={p:sha(p.read_bytes()) for p in (primary[3],neighbor[3])}
    compressed=gzip.compress(primary_row,mtime=0)
    plain_neighbor=gzip.compress(neighbor_row,mtime=0)
    good=archive(primary_log,'.1',compressed)
    broken=archive(primary_log,'.2',b'owned corrupt gzip fixture')
    foreign=archive(neighbor_log,'.1',plain_neighbor)
    prior_good=good.lstat()
    data,live=wait_inventory(primary,{good.name:'complete',broken.name:'unreadable'})
    accepted=live[good.name]
    assert data['requests']==1 and accepted['compressed_bytes']==len(compressed)
    assert accepted['verified']=={'read_bytes':len(primary_row),'expanded_bytes':len(primary_row),'sha256':sha(compressed),'skipped_lines':0}
    assert 'verified' not in live[broken.name]
    other,other_rows=wait_inventory(neighbor,{foreign.name:'complete'})
    assert other['requests']==1 and other_rows[foreign.name]['verified']['sha256']==sha(plain_neighbor)
    anon=urllib.request.Request(origin+'/api/app-modules/website-statistics-v2/run',b'{}',{'Origin':origin,'Content-Type':'application/json'})
    try:
        local.open(anon,timeout=10)
    except urllib.error.HTTPError as error:
        assert error.code==401
    else:
        raise AssertionError('Unauthenticated request accessed archive inventory')
    with os.fdopen(os.open(good,os.O_RDWR|os.O_NOFOLLOW|os.O_NONBLOCK),'r+b') as f:
        assert os.path.samestat(prior_good,os.fstat(f.fileno()))
        f.write(plain_neighbor)
        f.truncate()
        f.flush()
        os.fsync(f.fileno())
    timestamp=time.time()-25
    os.utime(good,(timestamp,timestamp),follow_symlinks=False)
    broken.unlink()
    data,changed=wait_inventory(primary,{good.name:'changed',broken.name:'missing'})
    assert data['requests']==1 and all('verified' not in entry for entry in changed.values())
    assert 'compressed_bytes' not in changed[broken.name]
    assert good.read_bytes()==plain_neighbor and foreign.read_bytes()==plain_neighbor
    assert primary_log.read_bytes()==primary_original and neighbor_log.read_bytes()==neighbor_original
    assert configs=={p:sha(p.read_bytes()) for p in configs}
    save(out/'verified-archive-inventory.json',{'primary_url':primary[2],'original':live,'after_rewrite':changed,'neighbor':other_rows})
    data_page=api('/software/website-statistics-v2/geodata');save(out/'original-geodata-before.json',data_page)
    state=data_page['state'];available=data_page['available'];manifest=available['manifest'];assert state['installed']and state['app_version']=='2.6.0'and not state['selected']and not state['stored']and not data_page['jobs']and not data_page['source_error'];assert manifest['release']=='2026-11'and manifest['sha256']=='5f64491f77c2c78b56cd83a88db4ea6c4666874322da38805498bbb754ccc735'and available['manifest_sha256']=='3a54ed412fd91d7dc514a4d8cae37ee6b9541c160e41c38c3fd0c77cb3e62874'
    selection={'action':'install','app_version':'2.6.0','app_manifest_sha256':available['app_manifest_sha256'],'installation_id':state['installation_id'],'release':manifest['release'],'data_manifest_sha256':available['manifest_sha256']};data_job=api('/software/website-statistics-v2/geodata',selection,202,secrets.token_hex(16));assert not data_job['replayed'];wait_job('runtime_jobs',data_job['job_id'],1800)
    for _ in range(60):
        loaded=api('/software/website-statistics-v2/geodata');meta=loaded['state']['metadata']
        if meta['available']and not loaded['state']['loading']:break
        time.sleep(1)
    assert meta['available']and meta['release']=='2026-11'and meta['sha256']==manifest['sha256']and not meta['stale']and len(loaded['state']['stored'])==1
    selected=loaded['state']['selected'];assert re.fullmatch('dbip-city-lite-v1-2026-11-[a-f0-9]{64}',selected);packed=Path('/var/lib/panel-executor/statistics-geodata')/selected/'database.mmdb.gz';st=packed.lstat();assert stat.S_ISREG(st.st_mode)and st.st_uid==0 and stat.S_IMODE(st.st_mode)==0o600 and st.st_nlink==1 and st.st_size==manifest['compressed_bytes']
    h=hashlib.sha256()
    with packed.open('rb')as f:
        for block in iter(lambda:f.read(1<<20),b''):h.update(block)
    assert h.hexdigest()==manifest['compressed_sha256'];expanded=0;h=hashlib.sha256()
    with gzip.open(packed,'rb')as f:
        for block in iter(lambda:f.read(1<<20),b''):expanded+=len(block);assert expanded<=manifest['bytes'];h.update(block)
    assert expanded==manifest['bytes']and h.hexdigest()==manifest['sha256'];save(out/'actual-signed-database-bytes.json',{'selected':selected,'compressed_sha256':manifest['compressed_sha256'],'expanded_sha256':h.hexdigest(),'expanded_bytes':expanded,'metadata':meta})
    report=api('/app-modules/website-statistics-v2/run',{'site_id':primary[0],'search':primary[2]});save(out/'actual-geodata-live-report.json',report);geo=report['geography'];assert report['requests']==1 and geo['requests']==1 and geo['metadata']['release']=='2026-11'and geo['metadata']['sha256']==manifest['sha256']and geo['counts']['non_public']==1 and not geo['countries']
    endpoint='/software/website-statistics-v2/geodata-job-records';inventory=api(endpoint);save(out/'original-geodata-job-inventory.json',inventory);inv=inventory['inventory'];assert inv['read_only']and inv['active_max']==128 and inv['archive_max']==512;record=next(x for x in inv['entries']if x['job_id']==data_job['job_id']);assert record['state']=='succeeded'and not record['archived']and re.fullmatch('[a-f0-9]{64}',record['sha256']);archived=api(endpoint+'/archive',{'job_id':record['job_id'],'expected_sha256':record['sha256'],'confirm':'ARCHIVE GEODATA JOB '+record['job_id']});assert archived['record']=={**record,'archived':True};after=api(endpoint);assert next(x for x in after['inventory']['entries']if x['job_id']==record['job_id'])==archived['record'];assert record['job_id']in after['committed'];save(out/'original-geodata-archived-record.json',{'record':archived,'inventory':after})
    save(out/'cold-fixtures.json',{'primary_site':primary[0],'primary_path':primary[2],'neighbor_site':neighbor[0],'data_job':data_job['job_id'],'selected':selected,'manifest_sha256':available['manifest_sha256'],'database_sha256':manifest['sha256'],'job_record':archived['record']})
    proof.update(actual_current_signed_city_install_and_cache_report=True,private_IP_not_falsely_geolocated=True,actual_original_job_archived_without_deletion=True,original_data_job=data_job['job_id'])
    proof.update(ok=True,actual_nginx_access_requests=True,signed_statistics_version=item['version'],
        checked_original_sha_and_progress=True,rewritten_archive_labelled_changed=True,
        missing_corrupt_source_labelled_missing=True,other_site_inventory_isolated=True,anonymous_access_refused=True,
        native_request_id_dedup=True,raw_logs_and_vhosts_preserved=True)
except BaseException:
    proof['failure']=traceback.format_exc()
finally:
    if csrf:
        try:api('/logout',{})
        except Exception:proof['ok']=False
    if proof['ok']:
        r=subprocess.run(['python3','-I','-B',str(inputs/'cold.py'),str(inputs),'snapshot'],capture_output=True,text=True,timeout=240)
        (out/'snapshot-transport.stdout').open('x').write(r.stdout);(out/'snapshot-transport.stderr').open('x').write(r.stderr);proof['cold_snapshot_prepared']=r.returncode==0;proof['ok']=proof['ok']and r.returncode==0
    save(out/'phase1.json',proof)
    print(json.dumps(proof),flush=True)
sys.exit(0 if proof['ok'] else 1)
