"""Actual signed F59 -> C15 installation in a new, isolated AMD64 KVM guest.

Every mutation is once-only. A failed/unknown job is retained and stops the
suite. This is infrastructure acceptance, never an all-app commercial claim.
Private snapshots and diagnostics are encrypted by the host before upload.
"""
import calendar, contextlib, gc, hashlib, http.cookiejar, json, os, pathlib, platform
import re, runpy, secrets, shutil, sqlite3, stat, subprocess, sys, time
import traceback, urllib.error, urllib.request

os.umask(0o077)
assert os.geteuid() == 0 and platform.machine() == 'x86_64'
payload = pathlib.Path(sys.argv[1]).resolve(strict=True)
assert len(sys.argv) == 2 and payload.is_dir()
base = pathlib.Path('/opt/panel-native-qa-' + secrets.token_hex(16))
base.mkdir(mode=0o700)
evidence = base / 'evidence'; evidence.mkdir(mode=0o700)
def sha(p):
    h = hashlib.sha256()
    with pathlib.Path(p).open('rb') as f:
        for block in iter(lambda: f.read(1 << 20), b''): h.update(block)
    return h.hexdigest()
def save(name, value):
    assert re.fullmatch('[A-Za-z0-9._-]+', name)
    with os.fdopen(os.open(evidence / name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600), 'w') as f:
        json.dump(value, f, sort_keys=True, indent=2); f.write('\n'); f.flush(); os.fsync(f.fileno())
pins = json.loads((payload / 'assets.json').read_bytes())
assert pins['format'] == 1 and pins['architecture'] == 'amd64'
assert pins['programme_key_sha256'] == '4ccfcc861d56a41e3ba7f7ace7e2432c815f366c58448d783df92c6632f01339'
assert pins['verifier_sha256'] == 'fe128e82b4e11345b320cd782134768bfe1a4df14947c425d7494873a7a7b7b5'
shutil.copyfile(payload / 'assets.json', base / 'assets.json', follow_symlinks=False)
os.chmod(base / 'assets.json', 0o600)
for name, expected in pins['files'].items():
    assert re.fullmatch('[A-Za-z0-9._-]+', name)
    source = payload / name; info = source.lstat()
    assert stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and sha(source) == expected
    shutil.copyfile(source, base / name, follow_symlinks=False); os.chmod(base / name, 0o600)
assert sha(base / 'programme.pub') == pins['programme_key_sha256']
assert sha(base / 'signed-release.py') == pins['verifier_sha256']
old = '0.1.0-dev.proapps24memorywaitbmpw'
new = '0.1.0-dev.proapps24streamcandidate15'
assert pins['source_inputs_sha256'] == 'fc1a0eb160c482f15eb69ca3cb2a0c2e9fc8bb73c4106adcbd9698366bca0ef1'
assert pins['old_source_inputs_sha256'] == 'd09edb15d2bcc2b098aabcb6f6ad5517aba4736309afe1cf9d630fb11dabe20a'
assert pins['programme_update_source_inputs_sha256'] == 'ab45cca5a8b3f1fa7fd31c29ca1f2b886eaf9d660169bc92c79b5f7a5134efa4'
assert pins['programme_update_version'] == '0.1.0-dev.proapps24streamcandidate21'
proof = {'ok': False, 'actual_KVM_guest': True, 'architecture': 'amd64', 'Main_changed': False,
         'all50_commercial': False, 'normal_signed_programme_upgrade': False,
         'normal_store_update': False, 'actions': [], 'base': str(base)}
http = None; csrf = ''; origin = 'http://127.0.0.1:19100'
def command(label, argv, timeout=30, require_success=True):
    started = time.monotonic()
    with (evidence / (label + '.log')).open('xb') as output:
        result = subprocess.run(argv, stdin=subprocess.DEVNULL, stdout=output, stderr=subprocess.STDOUT, timeout=timeout)
    record = {'label': label, 'exit': result.returncode, 'seconds': time.monotonic() - started,
              'log_sha256': sha(evidence / (label + '.log'))}
    save(label + '-result.json', record)
    if require_success: assert result.returncode == 0, label + ' failed; original log retained'
    return record
def programme(version, action):
    archive = base / ('panel-' + version + '-linux-amd64.tar.gz')
    args = ['python3', '-I', '-B', str(base / 'signed-release.py'), action, str(archive), '--public-key', str(base / 'programme.pub')]
    if action == 'install':
        proof['actions'].append({'kind': 'signed-programme-install', 'version': version, 'attempt': 1})
        save(version + '-install-intent.json', proof['actions'][-1])
    return command(version + '-' + action, args, 1200 if version == old else 1000)
class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs): raise AssertionError('API redirect refused')
def api(path, body=None, key=None):
    headers = {'Content-Type': 'application/json', 'Origin': origin, 'X-CSRF-Token': csrf}
    if key: headers['Idempotency-Key'] = key
    data = None if body is None else json.dumps(body, separators=(',', ':')).encode()
    request = urllib.request.Request('http://127.0.0.1:19100/api' + path, data=data, headers=headers)
    try:
        with http.open(request, timeout=110) as response:
            raw = response.read((4 << 20) + 1); assert len(raw) <= 4 << 20
            return response.status, json.loads(raw)
    except urllib.error.HTTPError as error:
        raw = error.read(8192)
        save('HTTP-' + secrets.token_hex(8) + '.json', {'path': path, 'status': error.code, 'body': raw.decode('utf8', 'replace')})
        raise AssertionError('API ' + path + ' returned HTTP ' + str(error.code)) from None
def sign_in():
    global http, csrf
    import http.cookiejar as cookies
    http = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect(), urllib.request.HTTPCookieProcessor(cookies.CookieJar()))
    path = pathlib.Path('/etc/panel/first-login.json'); s = path.lstat()
    assert stat.S_ISREG(s.st_mode) and s.st_uid == 0 and stat.S_IMODE(s.st_mode) == 0o600
    access = json.loads(path.read_bytes())
    try:
        status, result = api('/login', {k: access[k] for k in ('username', 'password')})
        assert status == 200 and type(result['csrf']) is str and result['csrf']
        csrf = result['csrf']
    finally: access.clear()
def sign_out():
    global http, csrf
    if csrf:
        status, _ = api('/logout', {}); assert status == 200
        csrf = ''; http = None
def row(job):
    with contextlib.closing(sqlite3.connect('file:/var/lib/panel/panel.db?mode=ro', uri=True, timeout=3)) as db:
        db.row_factory = sqlite3.Row; db.execute('PRAGMA query_only=ON')
        value = db.execute('SELECT * FROM runtime_jobs WHERE id=?', (job,)).fetchone()
        assert value is not None
        return dict(value)
def install_nginx_prerequisite():
    # Distribution Nginx serves the panel's ordinary HTTP site. The independent
    # stream engine additionally requires a recorded runtime with stream flags.
    # Obtain it through the same signed store and original runtime worker as UI.
    target = 'nginx-1.30.6'
    prefix = '/opt/panel/runtimes/nginx/1.30.6'
    assert not os.path.lexists(prefix)
    status, page = api('/app-registry?refresh=1')
    assert status == 200 and page['source']['stale'] is False
    item = next(v for v in page['catalog']['apps'] if v['id'] == 'nginx')
    assert item['version'] == '1.30.6-compat1' and item['provider'] == 'runtime' and item['target'] == target
    assert item['sha256'] == '81a8de8111b5c015f96359ff23cc97064fc5508d6f9ab602ca9a220a2f5200a8'
    key = 'native-nginx-' + secrets.token_hex(16)
    body = {'expected_version': item['version'], 'expected_sha256': item['sha256']}
    save('nginx-once-intent.json', {'POST_maximum': 1, 'body': body, 'idempotency_key': key, 'item': item})
    proof['actions'].append({'kind': 'nginx-store-install', 'POST_attempts': 1, 'target': target})
    status, response = api('/app-registry/nginx/install', body, key)
    save('nginx-queue-response.json', {'status': status, 'response': response})
    assert status == 202 and response['provider'] == 'runtime' and response['target'] == target
    assert re.fullmatch('[a-f0-9]{32}', response['job_id'])
    observed = []
    for attempt in range(451):
        value = row(response['job_id']); observed.append({'at': time.time(), 'row': value})
        assert value['target_id'] == target and value['idempotency_key'] == key
        if value['state'] in ('succeeded', 'failed', 'cancelled', 'needs_attention'): break
        assert value['state'] in ('queued', 'running') and attempt < 450
        time.sleep(2)
    save('nginx-original-job.json', observed)
    assert value['state'] == 'succeeded' and value['error'] == '', 'Original Nginx build did not succeed; not replayed'
    command('nginx-prerequisite-version', [prefix + '/sbin/nginx', '-V'], 10)
    text = (evidence / 'nginx-prerequisite-version.log').read_text()
    assert 'nginx version: nginx/1.30.6\n' in text and '--with-stream' in text.split() and '--with-stream_ssl_module' in text.split()
    proof['normal_store_Nginx_stream_runtime_installed'] = True
def store_change(version, operation):
    status, page = api('/app-registry?refresh=1')
    assert status == 200 and page['source']['stale'] is False
    item = next(v for v in page['catalog']['apps'] if v['id'] == 'load-balance')
    current = next(v for v in page['status'] if v['id'] == 'load-balance')
    assert item['version'] == version and item['provider'] == 'panel-module'
    if version == '1.9.0': assert item['sha256'] == 'a50afd7d2298a6229dcd0dcebdec8fca9684d9d64ee786b62577c8d3ba21038f'
    save('store-' + version + '-before.json', {'item': item, 'status': current, 'source': page['source'], 'host': page['host']})
    if operation == 'install': assert current['installed'] is False
    else:
        assert current['installed_version'] == '1.8.5' and current['latest_version'] == version
        assert all(current[k] is True for k in ('state_known', 'installed', 'healthy', 'version_known', 'update_available', 'update_supported'))
    key = 'native-qa-' + secrets.token_hex(16)
    body = {'expected_version': version, 'expected_sha256': item['sha256']}
    save('store-' + version + '-once-intent.json', {'operation': operation, 'body': body, 'idempotency_key': key, 'POST_maximum': 1})
    proof['actions'].append({'kind': 'app-' + operation, 'version': version, 'POST_attempts': 1})
    status, response = api('/app-registry/load-balance/' + operation, body, key)
    save('store-' + version + '-response.json', {'status': status, 'response': response})
    assert status == 202 and response['provider'] == 'panel-module' and re.fullmatch('[a-f0-9]{32}', response['job_id'])
    job = response['job_id']; observed = []; proof['last_job_id'] = job
    for attempt in range(181):
        value = row(job); observed.append({'at': time.time(), 'row': value})
        assert value['target_id'] == 'load-balance' and value['idempotency_key'] == key
        if value['state'] in ('succeeded', 'failed', 'cancelled', 'needs_attention'): break
        assert value['state'] in ('queued', 'running') and attempt < 180
        time.sleep(2)
    save('store-' + version + '-original-job.json', observed)
    assert value['state'] == 'succeeded' and value['error'] == '', 'Original store job did not succeed; never replayed'
    status, page = api('/app-registry'); current = next(v for v in page['status'] if v['id'] == 'load-balance')
    save('store-' + version + '-after.json', {'status': current, 'source': page['source']})
    assert status == 200 and current['installed_version'] == current['latest_version'] == version
    assert all(current[k] is True for k in ('installed', 'healthy', 'version_known')) and current['update_available'] is False
    return job
def nss():
    result = {}
    for name in ('passwd', 'group', 'shadow', 'gshadow'):
        raw = pathlib.Path('/etc/' + name).read_bytes()
        selected = [v for v in raw.splitlines(keepends=True) if v.startswith(b'panel-lbstream:')]
        assert len(selected) <= 1
        rest = b''.join(v for v in raw.splitlines(keepends=True) if not v.startswith(b'panel-lbstream:'))
        result[name] = {'sha256': hashlib.sha256(raw).hexdigest(), 'dedicated_count': len(selected),
                        'without_dedicated_sha256': hashlib.sha256(rest).hexdigest()}
    return result
def observed_business(library, policy, label, original=None):
    # A genuinely new installation has no previous source sample yet. Wait
    # for its ordinary worker to establish an actual healthy source before
    # taking either full snapshot. Never insert/reset a row or invoke a worker.
    deadline = time.monotonic() + 65
    for attempt in range(13):
        assert time.monotonic() < deadline
        with contextlib.closing(sqlite3.connect('file:/var/lib/panel/panel.db?mode=ro', uri=True, timeout=3)) as db:
            db.execute('PRAGMA query_only=ON'); db.execute('BEGIN')
            rows = db.execute('SELECT id,worker_state,worker_sequence,worker_checked_at FROM load_balance_traffic_source').fetchmany(2)
            assert len(rows) <= 1
            now = time.time(); healthy = False
            if rows:
                identity, state, sequence, clock = rows[0]
                assert identity == 1 and state in ('clear', 'error', 'stale', 'unknown')
                assert type(sequence) is int and 0 <= sequence < 1 << 60 and type(clock) is str
                match = re.fullmatch(r'(\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d)(?:\.(\d{1,9}))?Z', clock)
                if match:
                    stamp = calendar.timegm(time.strptime(match[1], '%Y-%m-%dT%H:%M:%S')) + int((match[2] or '').ljust(9, '0')) / 1e9
                    healthy = state == 'clear' and now - 16 <= stamp <= now + 1
            save(label + '-source-' + str(attempt) + '.json', {'observed': rows, 'at': now, 'healthy': healthy, 'same_snapshot_transaction': True})
            if healthy:
                if original is None:
                    record = library['original']['capture'](db); library['original']['validate'](record)
                else: record = library['capture_installed'](db, original, policy)
                return record
        assert attempt < 12 and time.monotonic() + 5 < deadline
        time.sleep(5)
    raise AssertionError('No real healthy source within the original bounded observation window')
try:
    for path in ('/etc/panel-release', '/opt/panel', '/var/lib/panel', '/var/lib/panel-executor', '/etc/nginx/nginx.conf'):
        assert not os.path.lexists(path), 'New guest already has protected installation state: ' + path
    save('guest-identity.json', {'architecture': platform.machine(), 'boot_id': pathlib.Path('/proc/sys/kernel/random/boot_id').read_text().strip(),
                               'machine_id_sha256': sha('/etc/machine-id'), 'os_release': pathlib.Path('/etc/os-release').read_text(),
                               'PID1': pathlib.Path('/proc/1/comm').read_text().strip(), 'fresh_protected_paths_absent': True})
    assert pathlib.Path('/proc/1/comm').read_text().strip() == 'systemd'
    programme(old, 'verify'); programme(new, 'verify'); programme(old, 'install')
    sign_in(); install_nginx_prerequisite(); store_change('1.8.5', 'install'); sign_out()
    library = runpy.run_path(str(base / 'candidate8-programme-business.py'))
    policy = json.loads((base / 'policy.json').read_bytes()); library['contract'](policy)
    before = observed_business(library, policy, 'before')
    save('programme-before-full.json', before)
    before_nss = nss(); save('NSS-before.json', before_nss)
    assert all(v['dedicated_count'] == 0 for v in before_nss.values())
    gc.collect()
    for p in pathlib.Path('/proc/self/fd').iterdir():
        try: target = os.readlink(p)
        except FileNotFoundError: continue
        assert not target.startswith('/var/lib/panel/panel.db'), 'QA kept a Core reader across installer'
    programme(new, 'install')
    after = observed_business(library, policy, 'after', before)
    save('programme-after-full.json', after)
    result = library['compare'](before, after, policy); save('programme-preservation.json', result)
    assert nss() == before_nss
    proof['normal_signed_programme_upgrade'] = True
    prerequisites = {}
    for name in ('/var/lib/panel-executor/runtime-lifecycle.lock', '/var/lib/panel-executor/docker-jobs', '/var/lib/panel-executor/docker-jobs/compose.lock'):
        try:
            s = pathlib.Path(name).lstat()
            prerequisites[name] = {'exists': True, 'mode': s.st_mode, 'uid': s.st_uid, 'gid': s.st_gid, 'size': s.st_size, 'inode': s.st_ino, 'nlink': s.st_nlink}
        except FileNotFoundError: prerequisites[name] = {'exists': False}
    save('stream-original-prerequisite-metadata.json', prerequisites)
    proof['original_compose_coordination_lock_present'] = prerequisites['/var/lib/panel-executor/docker-jobs/compose.lock']['exists']
    assert proof['original_compose_coordination_lock_present'] is False, 'First-install regression must exercise normal missing coordination inode'
    sign_in(); job = store_change('1.9.0', 'update')
    status, workspace = api('/app-registry/load-balance/stream/workspace')
    save('native-workspace.json', workspace); assert status == 200
    assert workspace['available'] and workspace['state'] == 'empty'
    assert workspace['entries'] == [] and workspace['generation'] == 0
    sign_out()
    # Capture every actual post-app field immediately, including the now
    # populated native request table. Preserve original programme snapshots;
    # do not project those tables away or relabel the original formats/times.
    full = runpy.run_path(str(base / 'candidate8-stream19-full-business.py'))
    full['C7']['validate_installed'](after, before, policy)
    with contextlib.closing(sqlite3.connect('file:/var/lib/panel/panel.db?mode=ro', uri=True, timeout=3)) as db:
        db.execute('PRAGMA query_only=ON'); db.execute('BEGIN')
        post_app = full['capture'](db, before, policy)
    save('app-after-full105.json', post_app)
    assert 0 <= post_app['at'] - after['at'] <= 600
    proof['all105_post_app_business_fields_captured'] = True
    proof['full_app_owned_delta_comparison_pending'] = True
    coordination = pathlib.Path('/var/lib/panel-executor/docker-jobs/compose.lock').lstat()
    assert stat.S_ISREG(coordination.st_mode) and stat.S_IMODE(coordination.st_mode) == 0o600 and coordination.st_uid == coordination.st_gid == 0 and coordination.st_nlink == 1 and coordination.st_size == 0
    proof['original_parent_coordination_initialized_then_readonly_child_completed'] = True
    after_nss = nss(); save('NSS-after.json', after_nss)
    assert all(v['dedicated_count'] == 1 for v in after_nss.values())
    assert all(after_nss[k]['without_dedicated_sha256'] == before_nss[k]['sha256'] for k in before_nss)
    result = subprocess.run(['getent', 'passwd', 'panel-lbstream'], capture_output=True, text=True, timeout=5)
    fields = result.stdout.strip().split(':')
    assert result.returncode == 0 and len(fields) == 7 and fields[0] == 'panel-lbstream'
    assert fields[2].isdigit() and fields[3].isdigit() and int(fields[2]) > 0 and fields[6] == '/usr/sbin/nologin'
    # The frozen normal cohort's own-unit component never resets a Core request.
    native_root = pathlib.Path('/var/lib/panel-executor/qa-l4-stop24-amd64.' + secrets.token_hex(16))
    native_root.mkdir(mode=0o700); (native_root / 'tmp').mkdir(mode=0o700)
    binary = base / 'executor-tests'; assert sha(binary) == pins['files']['executor-tests']
    os.chmod(binary, 0o700)
    result = command('native-clean-versus-child-OOM',
              ['/usr/bin/env', 'PANEL_NATIVE_QA=1', 'PANEL_LBSTREAM_STOP_QA_ROOT=' + str(native_root),
               'TMPDIR=' + str(native_root / 'tmp'), str(binary),
               '-test.run=^TestLoadBalanceStreamStopNativeOriginalCleanAndChildOOMAreDistinct$', '-test.v', '-test.count=1'], 120)
    native_log = (evidence / 'native-clean-versus-child-OOM.log').read_text()
    assert result['exit'] == 0 and '--- SKIP:' not in native_log
    assert 'mode=clean accepted=true' in native_log and 'mode=child-oom accepted=false' in native_log
    proof['native_original_PID1_clean_and_child_OOM_component_passed_without_skips'] = True
    command('native-TCP-UDP-controls', ['/usr/bin/python3', '-I', '-B', str(base / 'native-stream-traffic.py'), str(base)], 1600)
    traffic = json.loads((evidence / 'stream-live' / 'proof.json').read_bytes())
    assert traffic['ok'] and traffic['normal_UDP_and_TCP_removal'] and traffic['workspace_generation5_stopped_verified']
    proof['real_TCP_UDP_egress_active_drain_and_final_stop'] = True
    # A distinct new original control restores this owned stopped generation.
    # Preserve a real connection through the original signed live-programme
    # replacement, then issue one fresh control under the new programme. The
    # old five requests and their captures remain untouched and are not replayed.
    sign_in()
    live = runpy.run_path(str(base / 'native-candidate21-live-programme.py'))
    proof['configured_live_programme_upgrade'] = live['run'](base, http, csrf)
    sign_out()
    proof['configured_upgrade_owned_logout_snapshot'] = live['capture_after_owned_logout'](base)
    proof['final_programme_source_inputs_sha256'] = pins['programme_update_source_inputs_sha256']
    proof.update(ok=True, normal_store_update=True, dedicated_UID=int(fields[2]), dedicated_GID=int(fields[3]),
                 store_update_hint_then_latest_installed=True, original_job_id=job, full_stream_traffic_acceptance=False)
except BaseException:
    save('failure.json', {'traceback': traceback.format_exc()})
finally:
    if csrf:
        try: sign_out(); proof['own_session_logged_out'] = True
        except BaseException: proof['own_session_logout_failed'] = True
    try:
        command('native-unit-diagnostics', ['systemctl', 'show', 'panel-lbstream-install@*.service', 'panel-lbstream-account-create@*.service',
                    '-p', 'Id,LoadState,ActiveState,SubState,Result,MainPID,ControlPID,ExecMainStatus,InvocationID'], 10, False)
        journal = command('native-journal', ['journalctl', '-b', '--no-pager', '-o', 'short-precise', '-u', 'panel-lbstream-install@*', '-u', 'panel-lbstream-account-create@*'], 10, False)
        command('panel-journal', ['journalctl', '-b', '--no-pager', '-n', '150', '-u', 'panel', '-u', 'panel-executor'], 10, False)
        if proof['normal_store_update']: assert journal['exit'] == 0, 'A successful native update requires actual native journal evidence'
    except BaseException:
        proof['ok'] = False; proof['journal_diagnostic_failure'] = traceback.format_exc()
    try:
        if pathlib.Path('/var/lib/panel/panel.db').exists():
            with contextlib.closing(sqlite3.connect('file:/var/lib/panel/panel.db?mode=ro', uri=True, timeout=3)) as db:
                with contextlib.closing(sqlite3.connect(evidence / 'final-Core-private.sqlite')) as output: db.backup(output)
        roots = [str(p) for p in pathlib.Path('/var/lib/panel-executor').glob('load-balance-stream*')]
        roots += [str(p) for p in (pathlib.Path('/etc/panel/load-balance-stream'), pathlib.Path('/etc/panel/security-apps/modules/load-balance')) if os.path.lexists(p)]
        if roots:
            assert len(roots) <= 32
            command('original-native-ledgers', ['tar', '-czf', str(evidence / 'original-native-ledgers.tar.gz'), '--', *sorted(roots)], 30)
        save('NSS-final-public.json', nss())
    except BaseException:
        proof['ok'] = False; proof['diagnostic_failure'] = traceback.format_exc()
    save('proof.json', proof)
    # Only this public, credential-free summary crosses stdout. Full typed rows,
    # logs and DB are in a separate encrypted evidence artifact, never plaintext.
    print(json.dumps(proof), flush=True)
    sys.exit(0 if proof['ok'] else 1)
