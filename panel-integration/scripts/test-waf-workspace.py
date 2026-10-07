"""Real WAF acceptance limited to Ubuntu QA and a newly-created test website.

Keeps WAF installed, restores existing policies, never weakens an existing site.
"""
import copy, json, os, time, uuid
from panel_client import PanelClient

assert os.environ.get('PANEL_VM') == 'panel-compat-ubuntu24', 'isolated QA VM required'
assert os.environ.get('PANEL_BASE') == 'http://127.0.0.1:19220', 'QA API only'
p = PanelClient()
initial = p.api('/software/nginx-waf/config')
assert initial['status']['installed'], 'existing WAF required; do not reinstall'
original = copy.deepcopy(initial['settings'])
if initial['status']['version'] != '2.1.0':
    registry = p.api('/app-registry?refresh=1')
    app = next(a for a in registry['catalog']['apps'] if a['id'] == 'nginx-waf')
    assert app['version'] == '2.1.0' and not registry['source']['stale'], 'signed WAF 2.1.0 catalog required'
    job = p.api('/app-registry/nginx-waf/update', {'expected_version': app['version'], 'expected_sha256': app['sha256']})['job_id']
    p.wait(job, timeout=120)
    migrated = p.api('/software/nginx-waf/config')
    assert migrated['status']['version'] == '2.1.0' and migrated['status']['healthy']
    assert migrated['settings']['profile'] == original['profile']
    assert migrated['settings']['rate_per_second'] == original['rate_per_second']
slug = 'waf-workspace-' + str(int(time.time()))
created = p.api('/sites', {'name': '防火墙管理工作台验收', 'slug': slug, 'php_version_id': ''})
p.wait(created['job_id'], timeout=120)
listing = p.api('/sites')
site = next(s for s in (listing['sites'] if isinstance(listing, dict) else listing) if s['slug'] == slug)
ident = site['id']
jobs = []

def configure(cfg):
    cfg['policy']['revision'] = p.api('/software/nginx-waf/config')['settings']['policy']['revision']
    p.api('/software/nginx-waf/preview', {'settings': cfg})
    key = str(uuid.uuid4())
    job = p.api('/software/nginx-waf/configure', {'settings': cfg}, idempotency_key=key)['job_id']
    p.wait(job, timeout=120)
    assert p.api('/software/nginx-waf/configure', {'settings': cfg}, idempotency_key=key)['job_id'] == job
    jobs.append(job)
    return p.api('/software/nginx-waf/config')['settings']

def visit(path='/', agent='Yunzhan WAF QA Browser', cookie=None, method='GET'):
    args = ['curl', '-sS', '--max-time', '3', '-o', '/dev/null', '-w', '%{http_code}', '-X', method, '-H', 'Host: ' + site['domain'], '-A', agent]
    if cookie: args += ['-H', 'Cookie: ' + cookie]
    return int(p.vm(*(args + ['http://127.0.0.1:19101' + path])).stdout.strip())

try:
    cfg = p.api('/software/nginx-waf/config')['settings']
    cfg['policy']['sites'].append({'site_id': ident, 'mode': 'block', 'cc_enabled': False, 'groups': {'cookie': True}})
    cfg['policy']['lists']['url_deny'].append({'id': uuid.uuid4().hex, 'site_id': ident, 'value': '/qa-denied'})
    cfg['policy']['lists']['url_allow'].append({'id': uuid.uuid4().hex, 'site_id': ident, 'value': '/qa-allowed'})
    cfg['policy']['lists']['ua_deny'].append({'id': uuid.uuid4().hex, 'site_id': ident, 'value': 'Blocked QA scanner'})
    cfg['policy']['rules'].append({'id': uuid.uuid4().hex, 'site_id': ident, 'name': '验收观察规则', 'field': 'uri', 'operator': 'exact', 'value': '/qa-audit', 'action': 'observe', 'enabled': True})
    cfg = configure(cfg)
    assert visit('/') == 200

    assert visit('/', method='TRACE') == 405
    assert visit('/', method='TRACK') == 405
    assert visit('/?q=union%20select') == 403
    assert visit('/?q=%3Cscript%3E') == 403
    assert visit('/qa-denied') == 403
    assert visit('/qa-allowed', 'Blocked QA scanner') == 403, 'UA blacklist above URL allow'
    assert visit('/qa-allowed?q=%3Cscript%3E') == 404, 'URL allow should bypass feature rules'
    assert visit('/qa-audit') == 404, 'observation must not block'
    assert visit('/', cookie='q=union%20select') == 403
    assert visit('/__panel_health_' + ident, 'sqlmap') == 200
    cfg['policy']['sites'][-1]['mode'] = 'observe'
    cfg = configure(cfg)
    assert visit('/', 'sqlmap') == 200
    cfg['policy']['sites'][-1]['mode'] = 'block'
    cfg['policy']['sites'][-1]['cc_enabled'] = True
    cfg['policy']['sites'][-1]['rate_per_second'] = 200
    cfg['policy']['cc_rules'].append({'id': uuid.uuid4().hex, 'site_id': ident, 'path': '/', 'prefix': False, 'rate_per_second': 1, 'burst': 1, 'enabled': True})
    cfg = configure(cfg)
    codes = [visit('/') for _ in range(8)]
    assert 429 in codes, codes
    time.sleep(1.1)
    report = p.api('/software/nginx-waf/report?site_id=' + ident + '&limit=5000')
    assert report['blocked'] >= 6 and report['observed'] >= 2 and any(x['reason'] == 'cc' for x in report['events']), report
    for field in ['request_body', 'cookie', 'args', 'user_agent']:
        assert all(field not in x for x in report['events']), 'log leaked raw request data'
    stale = copy.deepcopy(cfg); stale['policy']['revision'] = 0; stale['profile'] = 'strict'
    try: p.api('/software/nginx-waf/preview', {'settings': stale})
    except RuntimeError: pass
    else: raise AssertionError('different stale draft accepted')
    invalid = copy.deepcopy(cfg); invalid['policy']['raw_nginx'] = 'return 200;'
    try: p.api('/software/nginx-waf/preview', {'settings': invalid})
    except RuntimeError: pass
    else: raise AssertionError('arbitrary config accepted')
finally:
    restored = configure(copy.deepcopy(original))
    expected = copy.deepcopy(original); expected['policy']['revision'] = restored['policy']['revision']
    assert restored == expected, 'existing site policies changed'
    assert p.api('/software/nginx-waf/config')['status']['healthy']
p.vm('sudo', '/usr/sbin/nginx', '-t')
assert len(p.api('/software/nginx-waf/history')['entries']) >= len(jobs)
print(json.dumps({'passed': True, 'site_id': ident, 'site_domain': site['domain'], 'jobs': jobs, 'real_rules': True, 'real_cc': True, 'real_observe': True, 'privacy': True, 'existing_policy_restored': True, 'installed_version': '2.1.0'}, ensure_ascii=False))
