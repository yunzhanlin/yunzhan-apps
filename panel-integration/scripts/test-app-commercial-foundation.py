#!/usr/bin/env python3
"""Signed QA install business proof; never run against the user's main panel."""
import json, os, pathlib, sys, time, uuid
from panel_client import PanelClient

assert os.environ.get('PANEL_VM') in ('panel-compat-ubuntu24', 'panel-store-apps-debian13'), 'Isolated QA host required'
root = pathlib.Path(__file__).resolve().parents[1]
state = root / os.environ.get('COMMERCIAL_QA_STATE', '.local/commercial-foundation-qa.json')
p = PanelClient()
ids = ('enterprise-tamper-proof', 'website-tamper-proof', 'file-monitor')
def module(id, action='run', **body): return p.api('/app-modules/' + id + '/' + action, body)
def checkpoint(): state.parent.mkdir(parents=True, exist_ok=True); state.write_text(json.dumps(v, indent=2) + '\n')
def passed(message): v['checks'].append(message); checkpoint(); print('PASS', message, flush=True)
def poll(check, timeout=25):
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        try:
            if check(): return
        except RuntimeError:
            # The target does not exist before initial copy; executor briefly
            # disconnects during this script's own controlled restart.
            pass
        time.sleep(.4)
    raise AssertionError('Actual event-driven result not observed within bounded deadline')
def text(site, name): return p.api('/sites/' + site + '/files/text?path=' + name)['content']
def create(site, name, value): p.api('/sites/' + site + '/files/action', {'action': 'create', 'path': name, 'content': value})
def write(site, name, value):
    old = p.api('/sites/' + site + '/files/text?path=' + name)
    p.api('/sites/' + site + '/files/action', {'action': 'save', 'path': name, 'content': value, 'expected_sha256': old['sha256']})
def policy(id): return next(x for x in module(id, 'policies')['policies'] if x['site_id'] == v['sites'][0])
def plan(): return next(x for x in module('files-sync')['plans'] if x['id'] == v['plan'])
def cleanup():
    assert v['plan'].startswith('qa-commercial-')
    for row in module('files-sync')['plans']:
        if row['id'] == v['plan']: module('files-sync', 'remove-plan', resource_id=row['id'], expected_revision=row['revision'])
    for siteid in v['sites']:
        site = next((x for x in p.api('/sites') if x['id'] == siteid), None)
        if not site: continue
        assert site['slug'].startswith('commercial-') and site['domain'] == site['slug'] + '.example.test'
        for id in ids:
            if any(x['site_id'] == siteid for x in module(id, 'policies')['policies']): module(id, 'pause', site_id=siteid)
        p.wait(p.api('/sites/' + siteid, {'confirm_domain': site['domain']}, method='DELETE')['job_id'], timeout=180)
    v['cleaned_up'] = True; checkpoint(); print('PASS own plans removed, monitors paused, websites recoverably archived', flush=True)

try:
    if len(sys.argv) > 1 and sys.argv[1] == 'cleanup': v = json.loads(state.read_text()); cleanup(); sys.exit(0)
    assert not state.exists(), 'Inspect prior state before rerunning'
    v = {'sites': [], 'plan': 'qa-commercial-' + uuid.uuid4().hex[:8], 'checks': [], 'passed': False}; checkpoint()
    for _ in range(2):
        slug = 'commercial-' + uuid.uuid4().hex[:8]
        p.wait(p.api('/sites', {'name': slug, 'slug': slug, 'domain': slug + '.example.test', 'php_version_id': ''})['job_id'], timeout=180)
        site = next(x for x in p.api('/sites') if x['slug'] == slug); v['sites'].append(site['id']); checkpoint()
    source, target = v['sites']
    create(source, 'protected.txt', 'trusted'); create(source, 'copy.txt', 'first')
    for id in ids:
        module(id, 'baseline', site_id=source, excludes=['copy.txt'], interval=86400, realtime=True, auto_restore=id=='enterprise-tamper-proof')
        poll(lambda id=id: policy(id)['watcher_state'] == 'active')
    passed('all three real kernel monitors running, signed baselines and 86400-second fallback')
    before = policy('enterprise-tamper-proof')['revision']
    module('enterprise-tamper-proof', 'pause', site_id=source, expected_revision=before)
    write(source, 'protected.txt', 'observed-edit')
    for id in ('website-tamper-proof', 'file-monitor'):
        poll(lambda id=id: any(x.get('trigger')=='inotify' and x.get('changes_count', 0)>0 for x in module(id, 'history', site_id=source)['history']))
    assert text(source, 'protected.txt') == 'observed-edit'
    passed('actual application writes trigger realtime website/file detection, not scheduled polling')
    revision = policy('enterprise-tamper-proof')['revision']
    module('enterprise-tamper-proof', 'resume', site_id=source, expected_revision=revision)
    poll(lambda: text(source, 'protected.txt') == 'trusted')
    # Resume performs inotify-reconcile catchup; a second live write proves the
    # ordinary kernel-event path independently of that startup catchup.
    write(source, 'protected.txt', 'live-tamper')
    poll(lambda: text(source, 'protected.txt') == 'trusted')
    assert any(x.get('trigger')=='inotify' and x.get('restored_count', 0)>0 for x in module('enterprise-tamper-proof', 'history', site_id=source)['history'])
    passed('resume immediately catches up and restores actual signed content after event')
    try: module('enterprise-tamper-proof', 'watch-mode', site_id=source, expected_revision=before, realtime=False)
    except RuntimeError as e: assert 'HTTP 409' in str(e)
    else: raise AssertionError('Stale monitor revision accepted')
    module('files-sync', 'schedule', resource_id=v['plan'], site_id=source, target_site_id=target, excludes=['protected.txt'], interval=86400, realtime=True, enabled=True, expected_revision=0)
    poll(lambda: text(target, 'copy.txt')=='first')
    write(source, 'copy.txt', 'second')
    poll(lambda: text(target, 'copy.txt')=='second')
    passed('actual initial catchup and sub-interval realtime incremental copy')
    row = plan(); module('files-sync', 'pause-plan', resource_id=row['id'], expected_revision=row['revision'])
    write(source, 'copy.txt', 'restart-catchup'); time.sleep(2)
    assert text(target, 'copy.txt')=='second'
    row = plan(); module('files-sync', 'resume-plan', resource_id=row['id'], expected_revision=row['revision'])
    p.vm('sudo', 'systemctl', 'restart', 'panel-executor')
    poll(lambda: text(target, 'copy.txt')=='restart-catchup', timeout=35)
    passed('pause makes no writes and actual executor restart preserves realtime sync/catchup')
    for _ in range(105): module('file-monitor', 'check', site_id=source)
    history = p.api('/app-modules/file-monitor/history?site_id=' + source + '&limit=20&offset=100')
    assert history['total'] >= 105 and len(history['history']) >= 5 and history['retention_days']==365
    assert all(x['site_id']==source for x in history['history'])
    passed('actual authenticated GET history reaches beyond old 100-entry ring with scoped pagination')
    delivery = module('mobile-pwa')
    assert len(delivery['mobile_downloads'])==3 and delivery['version']=='1.3.0'
    assert all(len(x['sha256'])==64 and x['url'].startswith('https://github.com/yunzhanlin/yunzhan-apps/releases/download/') for x in delivery['mobile_downloads'])
    passed('actual mobile handler supplies three fixed native deliveries and checksums with explicit scope')
    for id in ids: module(id, 'pause', site_id=source)
    row = plan(); module('files-sync', 'pause-plan', resource_id=row['id'], expected_revision=row['revision'])
    v['passed'] = True; checkpoint(); print('Own fixture policies paused for UI acceptance, then cleanup', flush=True)
finally: p.close()
