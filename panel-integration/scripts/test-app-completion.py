#!/usr/bin/env python3
"""New application workflows, real services; mutations restricted to owned QA fixtures."""
import copy, datetime, json, os, pathlib, time, uuid
from panel_client import PanelClient

assert os.environ.get('PANEL_VM') == 'panel-compat-ubuntu24', 'Isolated Ubuntu application QA required'
assert os.environ.get('PANEL_BASE') == 'http://127.0.0.1:19220', 'QA panel only'
root = pathlib.Path(__file__).resolve().parents[1]
fixture = json.loads((root / '.local/all50-qa-ubuntu24-functions.json').read_text())
assert fixture['passed'] and not fixture.get('cleaned_up')
p = PanelClient()
p.timeout = 65
checks = []
report = {'checks': checks, 'passed': False, 'release': p.api('/ready')}
def passed(message):
    checks.append(message)
    (root / '.local/app-completion-acceptance.json').write_text(json.dumps(report, ensure_ascii=False, indent=2)+'\n')
    print('PASS', message, flush=True)
def module(id, action='run', **values): return p.api('/app-modules/'+id+'/'+action, values)
def rejected(call):
    try: call()
    except RuntimeError: return
    raise AssertionError('Invalid/stale operation accepted')
def get(port, path='/', domain=None, agent='CloudStack QA', cookie=None, method='GET'):
    args = ['curl','-sS','--max-time','3','-o','/dev/null','-w','%{http_code}','-X',method,'-A',agent]
    if domain: args += ['-H','Host: '+domain]
    if cookie: args += ['-H','Cookie: '+cookie]
    return int(p.vm(*(args+['http://127.0.0.1:'+str(port)+path])).stdout.strip())
def read_http(port): return p.vm('curl','-fsS','--max-time','3','http://127.0.0.1:'+str(port)).stdout.strip()

try:
    source, target = fixture['sites']
    sites = p.api('/sites')
    for id in [source, target]:
        site = next(s for s in sites if s['id']==id)
        assert site['slug'].startswith('functions-')
    scan = module('php-code-security', site_id=source, severity='high', search='dynamic-eval')
    # Exact configured names are obtained from the real finding, not guessed.
    full = module('php-code-security', site_id=source)
    finding = next(x for x in full['findings'] if x['path']=='risk.php')
    scan = module('php-code-security', site_id=source, severity=finding['severity'], search=finding['rule'])
    assert any(x['path']=='risk.php' for x in scan['findings'])
    assert all(x['severity']==finding['severity'] and x['rule']==finding['rule'] for x in scan['findings'])
    assert module('php-code-security', site_id=source, excludes=['risk.php'])['findings']==[]
    assert len(finding['sha256'])==64 and full['findings_count']==len(full['findings'])
    rejected(lambda: module('php-code-security', site_id=source, severity='not-a-level'))
    passed('PHP actual findings, rule/severity/exclusion filters, content hashes and invalid-filter rejection')

    daily = module('daily-report')
    archive = module('daily-report','archive')['reports']
    assert archive
    stored = module('daily-report','report',resource_id=archive[0]['day'])
    assert stored == daily
    rejected(lambda: module('daily-report','report',resource_id='../../etc/passwd'))
    history = p.api('/app-modules/daily-report/history')['history']
    assert any(h['action']=='report' and h['outcome']=='succeeded' for h in history)
    assert all('token' not in h and 'password' not in h for h in history)
    passed('Actual saved daily archive, unchanged historical report, invalid date rejection and durable operation history')

    username = 'ftp-complete-'+uuid.uuid4().hex[:8]
    first, second = 'qa-'+uuid.uuid4().hex, 'qa-'+uuid.uuid4().hex
    created = False
    code = '''import ftplib,ssl,sys,json
v=json.load(sys.stdin);ctx=ssl.create_default_context(cafile='/etc/panel/security-apps/modules/pure-ftpd/server.pem')
f=ftplib.FTP_TLS(context=ctx);f.connect('localhost',2121,timeout=10)
try:f.login(v['username'],v['password']);assert v['allowed'];f.prot_p();assert f.pwd()=='/';f.quit()
except ftplib.error_perm:assert not v['allowed']
print('verified')'''
    def login(password, allowed):
        assert p.vm('sudo','python3','-c',code,input=json.dumps({'username':username,'password':password,'allowed':allowed})).stdout.strip()=='verified'
    try:
        module('pure-ftpd','create',username=username,password=first,site_id=target);created=True
        login(first,True)
        module('pure-ftpd','password',username=username,password=second)
        login(second,True);login(first,False)
        before = p.vm('sudo','sha256sum','/etc/panel/security-apps/modules/pure-ftpd/users.passwd','/etc/panel/security-apps/modules/pure-ftpd/users.pdb').stdout
        rejected(lambda: module('pure-ftpd','password',username=username,password='short'))
        rejected(lambda: module('pure-ftpd','password',username='missing-'+uuid.uuid4().hex[:8],password=first))
        after = p.vm('sudo','sha256sum','/etc/panel/security-apps/modules/pure-ftpd/users.passwd','/etc/panel/security-apps/modules/pure-ftpd/users.pdb').stdout
        assert before==after
        assert second not in json.dumps(p.api('/app-modules/pure-ftpd/history'))
        passed('Trusted FTPS password rotation, old-password rejection, failed-operation two-file preservation and secret-free history')
    finally:
        if created: module('pure-ftpd','delete',username=username)

    app_id = 'qa-complete-'+uuid.uuid4().hex[:8]
    entry = app_id+'.js'
    bad_entry = app_id+'-bad.js'
    body = "require('http').createServer((q,r)=>r.end('worker:'+process.pid)).listen(Number(process.env.PORT),process.env.HOST);console.log('completion-ready');"
    p.api('/sites/'+target+'/files/action',{'action':'create','path':entry,'content':body})
    p.api('/sites/'+target+'/files/action',{'action':'create','path':bad_entry,'content':"throw new Error('controlled QA startup failure');"})
    created = False
    try:
        app = module('pm2-manager','create',resource_id=app_id,site_id=target,entry=entry,port=22356,instances=2,memory_mb=128)['app'];created=True
        assert app['revision']==1 and len({read_http(22356) for _ in range(12)})==2
        changed = module('pm2-manager','update',resource_id=app_id,expected_revision=1,port=22357,instances=1,memory_mb=192)['app']
        assert changed['revision']==2 and len({read_http(22357) for _ in range(8)})==1
        rejected(lambda:module('pm2-manager','update',resource_id=app_id,expected_revision=1,instances=2))
        rejected(lambda:module('pm2-manager','update',resource_id=app_id,expected_revision=2,instances=8,memory_mb=256))
        rejected(lambda:module('pm2-manager','update',resource_id=app_id,expected_revision=2,entry=bad_entry))
        current = next(a['app'] for a in module('pm2-manager')['apps'] if a['app']['id']==app_id)
        assert current==changed and read_http(22357).startswith('worker:')
        module('pm2-manager','stop',resource_id=app_id)
        module('pm2-manager','start',resource_id=app_id)
        assert read_http(22357).startswith('worker:')
        assert 'completion-ready' in module('pm2-manager','logs',resource_id=app_id)['logs']
        passed('Real PM2 cluster workers, port/threshold update, stale/unsafe-limit rejection, broken-entry rollback and stop/start recovery')
    finally:
        if created: module('pm2-manager','delete',resource_id=app_id)
    assert p.api('/sites/'+target+'/files/text?path='+entry)['content']==body
    passed('Deleting managed PM2 service retains user application source files')

    initial = p.api('/software/apache-waf/config')
    original = copy.deepcopy(initial['settings'])
    assert initial['status']['installed'] and initial['status']['version']=='2.0.0'
    apache_sites = [s for s in sites if s.get('settings',{}).get('web_server')=='apache' and s['status']=='running']
    assert apache_sites
    apache = next(s for s in apache_sites if s['slug'].startswith('compat-apache-'))
    aid, domain = apache['id'], apache['domain']
    def configure(cfg):
        cfg['policy']['revision'] = p.api('/software/apache-waf/config')['settings']['policy']['revision']
        p.api('/software/apache-waf/preview',{'settings':cfg})
        key = uuid.uuid4().hex
        job = p.api('/software/apache-waf/configure',{'settings':cfg},idempotency_key=key)['job_id']
        p.wait(job,timeout=90)
        assert p.api('/software/apache-waf/configure',{'settings':cfg},idempotency_key=key)['job_id']==job
        return p.api('/software/apache-waf/config')['settings']
    try:
        cfg = copy.deepcopy(original)
        cfg['policy']['sites'] = [s for s in cfg['policy']['sites'] if s['site_id']!=aid]
        cfg['policy']['sites'].append({'site_id':aid,'mode':'block','cc_enabled':False,'groups':{'cookie':True}})
        cfg['policy']['lists']['url_deny'].append({'id':uuid.uuid4().hex,'site_id':aid,'value':'/qa-denied'})
        cfg['policy']['lists']['url_allow'].append({'id':uuid.uuid4().hex,'site_id':aid,'value':'/qa-allowed'})
        cfg['policy']['lists']['ua_deny'].append({'id':uuid.uuid4().hex,'site_id':aid,'value':'Blocked completion UA'})
        cfg['policy']['rules'].append({'id':uuid.uuid4().hex,'site_id':aid,'name':'QA观察','field':'uri','operator':'exact','value':'/qa-observed','action':'observe','enabled':True})
        cfg=configure(cfg)
        assert get(19080,domain=domain)==200
        assert get(19080,domain=domain,method='TRACE') in (403,405)
        assert get(19080,'/?q=union%20select',domain)==403
        assert get(19080,'/?q=%3Cscript%3E',domain)==403
        assert get(19080,'/qa-denied',domain)==403
        assert get(19080,'/qa-allowed',domain,'Blocked completion UA')==403
        assert get(19080,'/qa-allowed?q=%3Cscript%3E',domain)==404
        assert get(19080,'/qa-observed',domain)==404
        assert get(19080,domain=domain,cookie='q=union%20select')==403
        cfg['policy']['sites'][-1]['mode']='observe';cfg=configure(cfg)
        assert get(19080,domain=domain,agent='sqlmap')==200
        events=p.api('/software/apache-waf/report?site_id='+aid+'&limit=5000')
        assert events['blocked']>=4 and events['observed']>=2
        for e in events['events']:
            assert not any(k in e for k in ('args','cookie','user_agent','request_body'))
        invalid=copy.deepcopy(cfg);invalid['policy']['cc_enabled']=True
        rejected(lambda:p.api('/software/apache-waf/preview',{'settings':invalid}))
        stale=copy.deepcopy(cfg);stale['policy']['revision']=0;stale['profile']='strict'
        rejected(lambda:p.api('/software/apache-waf/preview',{'settings':stale}))
        invalid=copy.deepcopy(cfg);invalid['policy']['raw_apache']='Require all granted'
        rejected(lambda:p.api('/software/apache-waf/preview',{'settings':invalid}))
        passed('Native Apache scoped lists/custom rules/cookie protection, observation, privacy events, stale revision and unsupported/raw directive rejection')
    finally:
        restored=configure(copy.deepcopy(original))
        expected=copy.deepcopy(original);expected['policy']['revision']=restored['policy']['revision']
        assert restored==expected and p.api('/software/apache-waf/config')['status']['healthy']
    passed('Apache original policies restored through backed-up native validation, graceful reload and idempotent jobs')

    network=module('network-threat-detection')
    assert 'listener_details' in network and 'partial' in network and 'baseline_present' in network
    assert any(x['public'] is False for x in network['listener_details'])
    passed('Real network listener inventory with loopback/public classification and explicit completeness/baseline state')
    report['passed']=True;passed('All new completion workflows passed against the signed QA release')
finally: p.close()
