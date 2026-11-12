"""Exercise comparison using actually collected website events."""
import contextlib
import hashlib
import http.cookiejar
import json
import os
from pathlib import Path
import platform
import re
import secrets
import subprocess
import sys
import time
import urllib.error
import urllib.request
import urllib.parse

os.umask(0o077)
assert os.geteuid() == 0 and os.environ['GITHUB_ACTIONS'] == 'true'
assert os.environ['GITHUB_REPOSITORY'] == 'yunzhanlin/yunzhan-apps'
evidence = Path(sys.argv[1])
out = evidence / 'business-phase1'
out.mkdir(mode=0o700)
plan = json.loads((Path(__file__).resolve().parent / 'cohort.json').read_bytes())
arch = {'x86_64': 'amd64', 'aarch64': 'arm64'}[platform.machine()]
assert json.loads(Path('/opt/panel/current/SOURCE_INPUTS.json').read_bytes())['inputs_sha256'] == plan['source_inputs_sha256']
origin = 'http://127.0.0.1:19100'
csrf = ''


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        raise AssertionError('Unexpected local redirect')


client = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect(),
                                    urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))


def save(name, value):
    with (out / name).open('x') as f:
        json.dump(value, f, indent=2)
        f.write('\n')


def api(path, data=None, expected=200):
    headers = {'Origin': origin, 'Content-Type': 'application/json', 'X-CSRF-Token': csrf}
    if data is not None:
        headers['Idempotency-Key'] = secrets.token_hex(16)
    body = None if data is None else json.dumps(data).encode()
    try:
        with client.open(urllib.request.Request(origin + '/api' + path, body, headers), timeout=65) as response:
            assert response.status == expected
            return json.loads(response.read(6 << 20))
    except urllib.error.HTTPError as error:
        if error.code == expected:
            return json.loads(error.read(4096))
        raise


def wait(read, valid, limit=600):
    cutoff = time.monotonic() + limit
    while time.monotonic() < cutoff:
        v = read()
        if valid(v):
            return v
        time.sleep(2)
    raise TimeoutError('Panel job did not settle')



def job(label, route, payload, limit=2400):
    save(label + "-original-request.json", {"path": route, "payload": payload, "maximum_posts": 1})
    response = api(route, payload, 202)
    identifier = response["job_id"]
    assert re.fullmatch("[0-9a-f]{32}", identifier)
    row = wait(lambda: api("/jobs/" + identifier),
               lambda value: value["state"] in ("succeeded", "failed", "needs_attention"), limit)
    save(label + "-original-outcome.json", row)
    assert row["state"] == "succeeded", label
    return response, row


module = '/app-modules/website-analytics'
registry = '/app-registry/website-analytics'
proof = {'ok': False, 'architecture': arch, 'source_inputs_sha256': plan['source_inputs_sha256'],
         'Main_changed': False, 'all50_commercial': False}


def catalogue():
    for delay in (10, 30, 60, 0):
        try:
            data = api('/app-registry?refresh=1')
            break
        except urllib.error.HTTPError as error:
            if error.code != 503 or not delay:
                raise
            time.sleep(delay)
    assert not data['source']['stale'] and data['source']['resolved_commit'] == plan['served_head']
    assert data['host'] == {'platform': 'ubuntu-24.04', 'architecture': arch}
    item, = [app for app in data['catalog']['apps'] if app['id'] == 'website-analytics']
    status, = [app for app in data['status'] if app['id'] == 'website-analytics']
    assert item == plan['items']['website-analytics'] and status['state_known'] and status['supported']
    return item, status


def create_site(label):
    slug = 'c105r3-' + label
    domain = slug + '.example.test'
    _, site = job('site-' + label, '/sites', {'name': slug, 'slug': slug, 'domain': domain})
    route = '/analytics/sites/' + site['site_id']
    config = api(route + '/config')
    _, collector = job('collector-' + label, route + '/config',
                       {'enabled': True, 'clicks': True, 'retention_days': 30, 'revision': config['revision'],
                        'auto_inject_html': False})
    config = api(route + '/config')
    assert config['enabled'] and config['clicks'] and config['retention_days'] == 30
    assert config['site_id'] == site['site_id'] and re.fullmatch('[a-f0-9]{32}', config['key'])
    return (domain, route, config)


def event(site, kind, path, visitor, session, before):
    domain, _, config = site
    query = urllib.parse.urlencode({'site': config['site_id'], 'key': config['key']})
    body = {'id': secrets.token_hex(16), 'page_id': secrets.token_hex(16), 'kind': kind,
            'visitor': visitor, 'session': session, 'path': path, 'x': 25, 'y': 40}
    request = urllib.request.Request('http://127.0.0.1:19101/__yunzhan/analytics/event?' + query,
                                     json.dumps(body).encode(),
                                     {'Host': domain, 'Origin': 'http://' + domain, 'Content-Type': 'application/json'})
    assert time.time() < before
    with client.open(request, timeout=3) as reply:
        assert reply.status == 204
    assert time.time() < before


def until(stamp):
    while time.time() < stamp:
        time.sleep(0.04)


def fmt(stamp):
    return time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime(stamp))


def compare_query(start, end):
    return '?' + urllib.parse.urlencode({'from': fmt(start), 'to': fmt(end)})


try:
    login = json.loads(Path('/etc/panel/first-login.json').read_bytes())
    csrf = api('/login', {key: login[key] for key in ('username', 'password')})['csrf']
    login.clear()
    item, status = catalogue()
    assert not status['installed']
    update = plan['mode'] == 'signed-period-comparison-update'
    if update:
        assert item['version'] == '2.4.3'
        _, installed = job('install-legacy-analytics', '/software/website-analytics/install', {})
    else:
        assert plan['mode'] == 'retained-query-context' and item['version'] == '2.4.2'
        _, installed = job('install-query-context-analytics', registry + '/install',
                           {'expected_version': item['version'], 'expected_sha256': item['sha256']})
    before_version = '2.4.2'
    assert api(module)['status']['version'] == before_version
    record = Path('/etc/panel/security-apps/modules/website-analytics/installed.json')
    installation = json.loads(record.read_bytes())
    assert installation['version'] == before_version
    primary = create_site('primary')
    other = create_site('control')
    primary_domain, route, configuration = primary
    visitor, session = secrets.token_hex(16), secrets.token_hex(16)
    start = int(time.time()) + 1
    middle, finish = start + 4, start + 8
    until(start + 0.05)
    event(primary, 'pageview', '/previous', visitor, session, middle)
    event(primary, 'pageview', '/previous-next', visitor, session, middle)
    event(other, 'pageview', '/control-previous', visitor, session, middle)
    until(middle + 0.05)
    event(primary, 'pageview', '/current', visitor, session, finish)
    event(primary, 'pageview', '/current-next', secrets.token_hex(16), secrets.token_hex(16), finish)
    event(primary, 'pageview', '/current-more', visitor, session, finish)
    event(primary, 'click', '/current', visitor, session, finish)
    event(other, 'pageview', '/control-current', visitor, session, finish)
    until(finish + 0.05)
    current_query = compare_query(middle, finish)
    previous_query = compare_query(start, middle)
    assert api(route + '/compare' + current_query, expected=409)['error']
    before = [api(route + '/report' + query) for query in (previous_query, current_query)]
    assert [(r['overview']['pv'], r['overview']['uv'], r['overview']['sessions'], r['overview']['clicks']) for r in before] == [(2, 1, 1, 0), (3, 2, 2, 1)]
    if update:
        _, eligible = catalogue()
        assert eligible['installed_version'] == before_version and eligible['update_available'] and eligible['update_supported']
        _, updated = job('update-analytics', registry + '/update',
                         {'expected_version': item['version'], 'expected_sha256': item['sha256']})
        after = json.loads(record.read_bytes())
        assert after.pop('version') == '2.4.3' and after.pop('updated_at')
        assert installation.pop('version') == before_version and installation == after
        assert api(route + '/config') == configuration
        after_reports = [api(route + '/report' + query) for query in (previous_query, current_query)]
        assert [tuple(r['overview'][m] for m in ('pv','uv','sessions','clicks')) for r in after_reports] == [(2,1,1,0), (3,2,2,1)]
        report = api(route + '/compare' + current_query)
        assert report['site_id'] == configuration['site_id'] and report['within_retention']
        assert report['retention_days'] == 30
        assert report['previous'] == {'from': fmt(start), 'to': fmt(middle), 'pv': 2, 'uv': 1, 'sessions': 1, 'clicks': 0}
        assert report['current'] == {'from': fmt(middle), 'to': fmt(finish), 'pv': 3, 'uv': 2, 'sessions': 2, 'clicks': 1}
        control = api(other[1] + '/compare' + current_query)
        assert control['site_id'] == other[2]['site_id'] and control['current']['pv'] == control['previous']['pv'] == 1
        assert control['current']['clicks'] == 0
        outside = api(route + '/compare' + compare_query(finish - 20 * 86400, finish))
        assert not outside['within_retention'] and outside['retention_days'] == 30
        assert api(route + '/compare' + compare_query(finish - 32 * 86400, finish), expected=400)['error']
        _, latest = catalogue()
        assert latest['installed_version'] == '2.4.3' and not latest['update_available']
        save('actual-comparison.json', {'comparison': report, 'control': control, 'outside': outside})
        proof.update(signed_update={'job': updated['id'], 'version': item['version'], 'manifest_sha256': item['sha256']},
                     actual_collected_windows=True, original_site_configuration_retained=True,
                     original_installation_retained=True, control_site_isolated=True, retention_cutoff_reported=True)
    proof.update(ok=True, previous_collector_compatibility=True, registry_version=item['version'], installed_job=installed['id'])
except BaseException:
    import traceback
    proof['failure'] = traceback.format_exc()
finally:
    if csrf:
        with contextlib.suppress(Exception):
            api('/logout', {})
    save('original-proof.json', proof)
sys.exit(0 if proof['ok'] else 1)
