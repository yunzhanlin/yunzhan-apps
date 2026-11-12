"""Exercise actual daily report scheduling and signed package lifecycle."""
import contextlib
import datetime as dt
import hashlib
import http.cookiejar
import json
import os
from pathlib import Path
import platform
import re
import secrets
import sqlite3
import subprocess
import sys
import time
import urllib.error
import urllib.request
from zoneinfo import ZoneInfo

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
    for app, item in plan['items'].items():
        assert next(x for x in data['catalog']['apps'] if x['id'] == app) == item
    return {entry['id']: entry for entry in data['status']}



module = '/app-modules/daily-report'
registry = '/app-registry/daily-report'
settings_route = module + '/schedule'
version = '1.4.1'
proof = {'ok': False, 'architecture': arch, 'source_inputs_sha256': plan['source_inputs_sha256'],
         'Main_changed': False, 'all50_commercial': False}


def database():
    return sqlite3.connect('file:/var/lib/panel/panel.db?mode=ro', uri=True, timeout=12)


def observation(day):
    with contextlib.closing(database()) as db:
        row = db.execute('SELECT report,created_at FROM app_daily_reports WHERE day=?', (day,)).fetchone()
        events = db.execute("SELECT id FROM notifications WHERE source='daily-report' AND source_id=?", (day,)).fetchall()
        return {'row_sha256': hashlib.sha256(row[0].encode()).hexdigest() if row else None,
                'created_at': row[1] if row else None, 'notification_ids': [event[0] for event in events]}


def raw_date(value):
    return dt.datetime.fromisoformat(value.replace('Z', '+00:00'))


try:
    login = json.loads(Path('/etc/panel/first-login.json').read_bytes())
    csrf = api('/login', {key: login[key] for key in ('username', 'password')})['csrf']
    login.clear()
    item = plan['items']['daily-report']
    baseline = catalogue()['daily-report']
    assert baseline['state_known'] and baseline['supported'] and not baseline['installed']
    _, site = job('create-real-daily-site', '/sites', {'name': 'Scheduled report fixture',
                  'slug': 'c108-daily', 'domain': 'c108-daily.example.test'}, 300)
    assert re.fullmatch('[a-f0-9]{32}', site['site_id'])
    update = plan['mode'] == 'signed-daily-schedule-update'
    if update:
        assert item['version'] == version
        _, installed = job('install-legacy-daily', '/software/daily-report/install', {})
    else:
        assert plan['mode'] == 'original-daily-calendar' and item['version'] == '1.4.0'
        _, installed = job('install-signed-daily', registry + '/install',
                           {'expected_version': item['version'], 'expected_sha256': item['sha256']})
    assert api(module)['status']['version'] == '1.4.0'
    assert api(settings_route, expected=409)['error']
    old_report = api(module + '/run', {})
    assert old_report['sites'] >= 1 and old_report['running_sites'] >= 1 and old_report['resources']
    old_day = raw_date(old_report['created_at']).astimezone(ZoneInfo('Asia/Shanghai')).date().isoformat()
    old = observation(old_day)
    assert old['row_sha256'] and len(old['notification_ids']) == 1
    if update:
        eligible = catalogue()['daily-report']
        assert eligible['installed_version'] == '1.4.0' and eligible['update_available'] and eligible['update_supported']
        _, updated = job('update-scheduled-daily', registry + '/update',
                         {'expected_version': version, 'expected_sha256': item['sha256']})
        assert updated['kind'] == 'software_update'
        assert observation(old_day) == old
        assert api(settings_route) == {'time_zone':'Asia/Shanghai', 'local_time':'00:00', 'revision':0}
        now = dt.datetime.now(dt.timezone.utc)
        due = now.replace(second=0, microsecond=0) + dt.timedelta(minutes=3)
        for candidate in ('Pacific/Pago_Pago', 'Pacific/Kiritimati'):
            zone = ZoneInfo(candidate)
            date = due.astimezone(zone).date().isoformat()
            if date != old_day and now.astimezone(zone).date().isoformat() == date and observation(date)['row_sha256'] is None:
                break
        else:
            raise AssertionError('Could not select a distinct local date')
        chosen = {'time_zone': candidate, 'local_time': due.astimezone(zone).strftime('%H:%M'), 'expected_revision': 0}
        saved = api(settings_route, chosen)
        assert saved['revision'] == 1 and saved['time_zone'] == candidate and saved['local_time'] == chosen['local_time']
        assert api(settings_route, {**chosen, 'local_time': '12:00'}, expected=409)['error']
        assert api(settings_route) == saved
        waiting = wait(lambda: api(module)['daily_worker'],
                       lambda state: state['state'] == 'waiting_schedule' and state['report_day'] == date, 115)
        assert waiting['fresh'] and observation(date)['row_sha256'] is None
        done = wait(lambda: api(module)['daily_worker'], lambda state: state['report_day'] == date and
                    state['state'] in ('saved', 'saved_partial'), 310)
        assert done['fresh'] and raw_date(done['checked_at']) >= due
        current = observation(date)
        assert current['row_sha256'] and len(current['notification_ids']) == 1
        fetched = api(module + '/report', {'resource_id': date})
        assert raw_date(fetched['created_at']) >= due and fetched['running_sites'] >= 1
        assert raw_date(fetched['created_at']).astimezone(zone).date().isoformat() == date
        assert observation(old_day) == old and api(settings_route) == saved
        assert not catalogue()['daily-report']['update_available']
        with contextlib.closing(database()) as db:
            assert db.execute("SELECT count(*) FROM audit_logs WHERE action='daily-report.schedule'").fetchone()[0] == 1
        save('original-worker-waiting.json', waiting)
        save('original-worker-generated.json', done)
        save('original-schedule.json', saved)
        save('original-local-day-report.json', {'day':date, 'due':due.isoformat(), 'report_created_at':fetched['created_at'],
                                                'original':old, 'scheduled':current})
        proof['signed_update'] = {'job': updated['id'], 'version': version, 'manifest_sha256': item['sha256']}
        proof.update(actual_automatic_local_day=True, checked_wait_before_generation=True,
                     original_report_and_notification_preserved=True, stale_schedule_edit_rejected=True)
    proof.update(ok=True, registry_version=item['version'], installed_job=installed['id'],
                 original_daily_calendar_verified=True, legacy_schedule_route_denied=True)
except BaseException:
    import traceback
    proof['failure'] = traceback.format_exc()
finally:
    if csrf:
        with contextlib.suppress(Exception):
            api('/logout', {})
    save('original-proof.json', proof)
sys.exit(0 if proof['ok'] else 1)
