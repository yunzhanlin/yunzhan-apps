"""Real opt-in proxy acceptance, restricted to the named Ubuntu QA VM.

Uses the normal authenticated API and creates only an identifiable test site.
Never enables analytics on an existing customer website or uninstalls software.
"""
import json, os, time, uuid
from panel_client import PanelClient

assert os.environ.get('PANEL_VM') == 'panel-compat-ubuntu24', 'explicit isolated QA VM required'
assert os.environ.get('PANEL_BASE') == 'http://127.0.0.1:19220', 'QA API only'
p = PanelClient()
slug = 'analytics-auto-' + str(int(time.time()))
created = p.api('/sites', {'name': '采集代理自动启停验收', 'slug': slug, 'php_version_id': ''})
p.wait(created['job_id'])
listing = p.api('/sites')
sites = listing['sites'] if isinstance(listing, dict) else listing
site = next(s for s in sites if s['slug'] == slug)
ident = site['id']
route = '/analytics/sites/' + ident + '/config'
before = p.api('/sites/' + ident + '/config')['content']
config = p.api(route)
config['enabled'] = True
idem = str(uuid.uuid4())
job = p.api(route, config, idempotency_key=idem)['job_id']
p.wait(job)
assert p.api(route, config, idempotency_key=idem)['job_id'] == job, 'lost acknowledgement generated a new job'
config = p.api(route)
enabled = p.api('/sites/' + ident + '/config')['content']
assert config['enabled'] and config['proxy_endpoint'] == '127.0.0.1:19100'
assert enabled.count('location ^~ /__yunzhan/analytics/') == 1
assert 'proxy_pass http://127.0.0.1:19100/collect/analytics/;' in enabled
backup = p.vm('sudo', 'test', '-f', '/var/lib/panel-executor/backups/' + job + '.conf')
assert backup.returncode == 0

def visit(path, method='GET', body=None, headers=()):
    args = ['curl', '-sS', '-o', '/dev/null', '-w', '%{http_code}', '-X', method, '-H', 'Host: ' + site['domain']]
    for h in headers:
        args += ['-H', h]
    if body is not None:
        args += ['--data-binary', body]
    return int(p.vm(*(args + ['http://127.0.0.1:19101' + path])).stdout.strip())

query = '?site=' + ident + '&key=' + config['key']
assert visit('/__yunzhan/analytics/tracker.js' + query) == 200
event = {k: uuid.uuid4().hex for k in ['id', 'page_id', 'visitor', 'session']}
event.update(kind='pageview', path='/actual-browser-path')
assert visit('/__yunzhan/analytics/event' + query, 'POST', json.dumps(event),
             ['Content-Type: application/json', 'Origin: http://' + site['domain'], 'User-Agent: Mozilla/5.0 Chrome/123.0', 'Cookie: panel_session=not-forwarded']) == 204
assert p.api('/analytics/sites/' + ident + '/report')['overview']['pv'] == 1
for path in ['/__yunzhan/analytics/api/ready', '/__yunzhan/analytics/anything', '/__yunzhan/analytics/event/extra']:
    assert visit(path) == 404, 'collector proxy exposed a non-collector route'
assert visit('/__yunzhan/analytics/event' + query, 'POST', json.dumps(event),
             ['Content-Type: application/json', 'Origin: https://wrong.example']) == 403

config['enabled'] = False
disabled_job = p.api(route, config)['job_id']
p.wait(disabled_job)
disabled = p.api('/sites/' + ident + '/config')['content']
assert '/__yunzhan/analytics/' not in disabled and '/collect/analytics/' not in disabled
assert disabled == before, 'disable changed unrelated Nginx configuration'
assert not p.api(route)['enabled']
assert visit('/__yunzhan/analytics/tracker.js' + query) == 404
assert p.api('/analytics/sites/' + ident + '/report')['overview']['pv'] == 1, 'disable deleted historical statistics'
p.vm('sudo', '/usr/sbin/nginx', '-t')
print(json.dumps({'passed': True, 'site_id': ident, 'site_domain': site['domain'], 'enable_job': job,
                  'disable_job': disabled_job, 'upstream_from_actual_listener': True, 'backup_exists': True,
                  'same_origin_tracker': 200, 'same_origin_event': 204, 'foreign_origin': 403,
                  'non_collector_routes': 404, 'disabled_tracker': 404, 'restored_original_file': True,
                  'historical_pv_preserved': 1}, ensure_ascii=False))
