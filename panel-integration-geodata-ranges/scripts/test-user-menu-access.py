#!/usr/bin/env python3
"""Real scoped logins, forbidden calls, session revocation and reboot persistence.

Only own fixture users/websites on explicitly isolated QA hosts are changed.
Credentials remain in memory. Existing users, services and websites are untouched.
"""
import http.cookiejar
import json
import os
import pathlib
import time
import urllib.error
import urllib.request
import uuid
from panel_client import PanelClient

assert os.environ.get('PANEL_VM') in ('panel-compat-ubuntu24', 'panel-store-apps-debian13'), 'Isolated QA host required'
p = PanelClient()
root = pathlib.Path(__file__).resolve().parents[1]
state = root / os.environ.get('MENU_ACCESS_STATE', '.local/menu-access.json')
assert not state.exists(), 'Inspect previous fixture state before rerunning'
v = {'checks': [], 'users': [], 'sites': [], 'passed': False, 'cleaned_up': False}
sessions = []
def checkpoint():
    state.parent.mkdir(parents=True, exist_ok=True)
    state.write_text(json.dumps(v, indent=2) + '\n')
def passed(detail):
    v['checks'].append(detail); checkpoint(); print('PASS', detail, flush=True)
def module(action='run', **body): return p.api('/app-modules/user-manager/' + action, body)
def row(name): return next(x for x in module()['users'] if x['username'] == name)
def login(name, password):
    client = urllib.request.build_opener(urllib.request.ProxyHandler({}), urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))
    status, data = request(client, '/login', {'username': name, 'password': password})
    assert status == 200, status
    sessions.append((client, data['csrf']))
    return client, data['csrf']
def request(client, path, body=None, csrf=''):
    req = urllib.request.Request(p.base + '/api' + path, data=None if body is None else json.dumps(body).encode(),
        headers={'Content-Type':'application/json', 'Origin':p.origin, 'X-CSRF-Token':csrf, 'Idempotency-Key':str(uuid.uuid4())})
    try:
        with client.open(req, timeout=15) as r: return r.status, json.load(r)
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read())
def create(role, menus, sites):
    name = 'qaacl-' + uuid.uuid4().hex[:9]
    password = 'QA-' + uuid.uuid4().hex
    module('create', username=name, password=password, role=role, menu_ids=menus, site_ids=sites)
    v['users'].append(name); checkpoint()
    return name, password
def cleanup():
    # Never delete a pre-existing user or website.
    existing = {x['username']:x for x in module()['users']}
    for name in v['users']:
        assert name.startswith('qaacl-')
        if name in existing: module('delete', username=name, expected_revision=existing[name]['revision'])
    for site in v['sites']:
        current = next((x for x in p.api('/sites') if x['id'] == site['id']), None)
        if current:
            assert current['slug'] == site['slug'] and current['slug'].startswith('qaacl-')
            p.wait(p.api('/sites/' + current['id'], {'confirm_domain':current['domain']}, method='DELETE')['job_id'], timeout=120)
    v['cleaned_up'] = True; checkpoint()
try:
    checkpoint()
    assert p.api('/me')['role'] == 'admin'
    module()
    slug = 'qaacl-' + uuid.uuid4().hex[:9]
    p.wait(p.api('/sites', {'name':slug,'slug':slug,'domain':slug+'.example.test','php_version_id':''})['job_id'], timeout=120)
    site = next(x for x in p.api('/sites') if x['slug'] == slug)
    v['sites'].append({'id':site['id'],'slug':slug}); checkpoint()
    reader, password = create('viewer', ['files'], [site['id']])
    client, csrf = login(reader,password)
    status, me = request(client, '/me')
    assert status == 200 and me['menu_ids'] == ['files'] and me['role'] == 'viewer'
    status, sites = request(client, '/sites')
    assert status == 200 and [x['id'] for x in sites] == [site['id']]
    assert request(client, '/sites/'+site['id']+'/files?path=')[0] == 200
    for path in ('/overview','/software','/app-modules/user-manager','/filesystem?path=/','/sites/'+uuid.uuid4().hex+'/files'):
        assert request(client,path)[0] == 403, path
    assert request(client,'/sites/'+site['id']+'/files/action',{'action':'create','path':'forbidden.txt','content':'no'},csrf)[0] == 403
    assert request(client,'/session/activity',{},csrf)[0] == 200
    passed('actual viewer login: files-only menu, assigned website only, reads work, global/other-site/writes rejected')
    restricted, secret = create('admin', ['runtimes'], [])
    restricted_client, restricted_csrf = login(restricted,secret)
    assert request(restricted_client,'/software')[0] == 200
    for path in ('/sites','/overview','/app-modules/user-manager','/software/nginx-waf/config'):
        assert request(restricted_client,path)[0] == 403, path
    assert request(restricted_client,'/app-registry/nginx-waf/install',{'settings':{}},restricted_csrf)[0] == 403
    passed('actual restricted administrator: store reads allowed, direct security installer bypass rejected')
    manager, secret = create('admin', ['panel-access'], [])
    manager_client, manager_csrf = login(manager,secret)
    assert request(manager_client,'/app-modules/user-manager/run',{},manager_csrf)[0] == 200
    before = row(restricted)
    assert request(manager_client,'/app-modules/user-manager/update',{'username':restricted,'role':'admin','menu_ids':['terminal'],'expected_revision':before['revision']},manager_csrf)[0] == 409
    passed('limited account administrator cannot manage or grant permissions above own ceiling')
    before = row(reader)
    module('update', username=reader, role='viewer', menu_ids=[], site_ids=[site['id']], expected_revision=before['revision'])
    assert request(client,'/me')[0] == 401
    try: module('update', username=reader, role='viewer', menu_ids=['files'], expected_revision=before['revision'])
    except RuntimeError as e: assert 'HTTP 409' in str(e)
    else: raise AssertionError('stale authorization accepted')
    fresh, fresh_csrf = login(reader,password)
    assert request(fresh,'/me')[1]['menu_ids'] == []
    assert request(fresh,'/sites')[0] == 403 and request(fresh,'/account')[0] == 200
    p.vm('sudo','systemctl','restart','panel')
    for _ in range(20):
        try:
            current = p.api('/me'); break
        except (RuntimeError, urllib.error.URLError, ConnectionError): time.sleep(.3)
    else: raise AssertionError('panel did not restart')
    assert request(fresh,'/me')[1]['menu_ids'] == [] and request(fresh,'/sites')[0] == 403
    assert row(reader)['revision'] == before['revision'] + 1
    passed('actual permission update revokes old login; stale revision rejected; empty grants/self recovery and revision persist after service restart')
    v['passed'] = True; checkpoint()
finally:
    for client, csrf in sessions:
        try: request(client,'/logout',{},csrf)
        except (urllib.error.URLError, ConnectionError): pass
    cleanup()
    p.close()
print('PASS own temporary accounts removed and own website recoverably archived; report:',state,flush=True)
