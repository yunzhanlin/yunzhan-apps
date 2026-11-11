"""Exercise actual PHP-FPM website processes through the signed panel."""
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


def site_http(domain, path):
    assert domain in ("c95-guarded.example.test", "c95-control.example.test")
    assert path in ("/process.php", "/retained.txt")
    request = urllib.request.Request("http://127.0.0.1:19101" + path, headers={"Host": domain})
    for delay in (0.25, 0.5, 1, 2, 4, 0):
        try:
            with client.open(request, timeout=20) as response:
                assert response.status == 200
                return response.read(65537)
        except urllib.error.HTTPError as error:
            if error.code not in (502, 503, 504) or not delay:
                raise
            time.sleep(delay)


def site_by_id(id):
    rows = api("/sites")
    row, = [row for row in rows if row["id"] == id]
    return row


def system(*args):
    return subprocess.check_output(args, text=True, stderr=subprocess.STDOUT, timeout=60).strip()


def set_policy(site, enabled):
    route = "/sites/" + site
    current = api(route + "/settings")
    settings = dict(current["settings"])
    defaults = {"memory_mb": 128, "max_execution_seconds": 30, "upload_mb": 32, "post_mb": 40,
                "timezone": "UTC", "display_errors": False, "max_children": 4, "max_requests": 500}
    settings["php"] = {**(settings.get("php") or defaults), "block_process_functions": enabled}
    payload = {"settings": settings, "expected_revision": current["settings_revision"]}
    preview = api(route + "/settings/preview", payload)
    assert re.fullmatch("[0-9a-f]{64}", preview["config_sha"])
    label = "enable" if enabled else "disable"
    save(label + "-original-preview.json", preview)
    _, result = job(label + "-process-policy", route + "/settings",
                    {**payload, "expected_config_sha": preview["config_sha"]}, 300)
    assert result["site_id"] == site
    observed = api(route + "/settings")
    assert observed["settings_revision"] == current["settings_revision"] + 1
    assert observed["settings"]["php"].get("block_process_functions", False) == enabled
    return result["id"]


proof = {"ok": False, "architecture": arch, "source_inputs_sha256": plan["source_inputs_sha256"],
         "Main_changed": False, "all50_commercial": False}
try:
    login = json.loads(Path("/etc/panel/first-login.json").read_bytes())
    csrf = api("/login", {key: login[key] for key in ("username", "password")})["csrf"]
    login.clear()
    for delay in (15, 60, 90, 0):
        try:
            catalog = api("/app-registry?refresh=1")
            break
        except urllib.error.HTTPError as error:
            raw = error.read(4096)
            with (out / "catalogue-refusals.jsonl").open("a") as receipt:
                receipt.write(json.dumps({"status":error.code,"message":raw.decode("utf-8","replace")[:500]}) + "\n")
            if error.code != 503 or not delay:
                raise
            time.sleep(delay)
    assert not catalog["source"]["stale"]
    assert catalog["source"]["resolved_commit"] in plan.get("authorized_catalogues", [plan["served_head"]])
    assert catalog["host"] == {"platform":"ubuntu-24.04","architecture":arch}
    for app in (("php-85",) if plan["mode"] == "signed-update" else ("php-85", "php-code-security")):
        item, = [row for row in catalog["catalog"]["apps"] if row["id"] == app]
        status, = [row for row in catalog["status"] if row["id"] == app]
        assert item == plan["items"][app] and status["supported"] and status["state_known"] and not status["installed"]
        receipt, result = job("install-" + app, "/app-registry/" + app + "/install",
                              {"expected_version": item["version"], "expected_sha256": item["sha256"]}, 3200)
        assert receipt["provider"] == item["provider"] and receipt["target"] == item["target"]
        proof[app] = {"job": result["id"], "manifest_sha256": item["sha256"], "version": item["version"]}

    sites = {}
    script = """<?php
header('Content-Type: application/json');
$functions = ['exec','passthru','shell_exec','system','proc_open','popen','pcntl_exec'];
$available = array_map('function_exists', $functions);
echo json_encode(['php'=>PHP_VERSION,'sapi'=>PHP_SAPI,'functions'=>$available,
    'result'=>function_exists('exec') ? exec('/usr/bin/printf native-c95') : 'blocked']);
"""
    retained = "C95 retained website file\n"
    for scope in ("guarded", "control"):
        slug = "c95-" + scope
        domain = slug + ".example.test"
        _, created = job("create-" + scope, "/sites",
                         {"name": slug, "slug": slug, "domain": domain, "php_version_id": "php-8.5.12"}, 300)
        site = created["site_id"]
        assert re.fullmatch("[0-9a-f]{32}", site)
        sites[scope] = (site, domain)
        for filename, body in (("process.php", script), ("retained.txt", retained)):
            saved = api("/sites/" + site + "/files/action", {"action":"create", "path":filename, "content":body})
            assert saved["sha256"] == hashlib.sha256(body.encode()).hexdigest()

    if plan["mode"] == "signed-update":
        module = "/app-modules/php-code-security"
        guarded, _ = sites["guarded"]
        _, old = job("install-original-php-code-security", "/software/php-code-security/install", {})
        old_status = api(module)["status"]
        assert old_status["installed"] and old_status["version"] == "1.3.0"
        install_file = Path("/etc/panel/security-apps/modules/php-code-security/installed.json")
        original_record = json.loads(install_file.read_bytes())
        assert original_record["id"] == "php-code-security" and original_record["version"] == "1.3.0"
        assert original_record["installed_at"]
        sample = "<?php if (false) { eval('echo 1;'); }\n"
        name = "quarantine-sample.php"
        digest = hashlib.sha256(sample.encode()).hexdigest()
        site_path = "/sites/" + guarded
        created = api(site_path + "/files/action", {"action":"create", "path":name, "content":sample})
        assert created["sha256"] == digest
        scanned = api(module + "/run", {"site_id":guarded, "search":name})
        assert any(row["sha256"] == digest and row["path"] == name for row in scanned["findings"])
        quarantine = api(module + "/quarantine", {"site_id":guarded,"path":name,"expected_sha":digest,
                                                   "confirm":"QUARANTINE " + name})["record"]
        assert quarantine["state"] == "quarantined" and quarantine["sha256"] == digest
        item = plan["items"]["php-code-security"]
        current = api("/app-registry")
        assert current["source"]["resolved_commit"] in plan["authorized_catalogues"]
        found, = [row for row in current["catalog"]["apps"] if row["id"] == "php-code-security"]
        status, = [row for row in current["status"] if row["id"] == "php-code-security"]
        assert found == item and status["installed_version"] == "1.3.0"
        assert status["update_available"] and status["update_supported"] and status["update_kind"] == "module"
        receipt, updated = job("update-signed-php-code-security", "/app-registry/php-code-security/update",
                               {"expected_version":item["version"], "expected_sha256":item["sha256"]})
        assert receipt["provider"] == "panel-module"
        status = api(module)["status"]
        assert status["version"] == "1.3.1"
        current_record = json.loads(install_file.read_bytes())
        assert current_record.pop("version") == "1.3.1" and current_record.pop("updated_at")
        assert original_record.pop("version") == "1.3.0"
        assert current_record == original_record
        rows = api(module + "/quarantine-list", {"site_id":guarded})["quarantine"]
        assert rows == [quarantine]
        restored = api(module + "/restore-quarantine", {"site_id":guarded,"path":name,"expected_sha":digest,
                 "resource_id":quarantine["id"],"expected_revision":quarantine["revision"],
                 "confirm":"RESTORE PHP " + quarantine["id"]})
        assert restored["restored"] and restored["independent_backup_retained"]
        assert api(site_path + "/files/text?path=" + name)["sha256"] == digest
        proof["php-code-security"] = {"old_job":old["id"], "job":updated["id"], "version":status["version"],
                                      "manifest_sha256":item["sha256"], "quarantine_restored_after_update":True,
                                      "installation_identity_preserved":True}

    def probe(scope, enabled):
        site, domain = sites[scope]
        data = json.loads(site_http(domain, "/process.php"))
        assert data["php"] == "8.5.12" and data["sapi"] == "fpm-fcgi"
        assert data["result"] == ("blocked" if enabled else "native-c95")
        assert len(data["functions"]) == 7
        if enabled:
            assert not any(data["functions"])
        else:
            assert all(data["functions"][:6])
        assert site_http(domain, "/retained.txt") == retained.encode()
        return data

    guarded, _ = sites["guarded"]
    control, _ = sites["control"]
    prior = {scope: probe(scope, False) for scope in sites}
    initial = site_by_id(guarded)["runtime_instance_id"]
    independent = site_by_id(control)["runtime_instance_id"]
    enable = set_policy(guarded, True)
    guarded_data = probe("guarded", True)
    assert probe("control", False) == prior["control"]
    assert site_by_id(control)["runtime_instance_id"] == independent
    active = site_by_id(guarded)["runtime_instance_id"]
    assert active != initial and re.fullmatch("[0-9a-f]{32}-php-8[.]5[.]12-cfg-[0-9a-f]{24}", active)
    unit = "panel-php@" + active + ".service"
    pid = system("/usr/bin/systemctl", "show", unit, "--property=MainPID", "--value")
    assert int(pid) > 1
    system("/usr/bin/systemctl", "restart", unit)
    restarted = system("/usr/bin/systemctl", "show", unit, "--property=MainPID", "--value")
    assert int(restarted) > 1 and restarted != pid
    assert probe("guarded", True) == guarded_data
    disable = set_policy(guarded, False)
    assert probe("guarded", False) == prior["guarded"] and probe("control", False) == prior["control"]
    assert site_by_id(control)["runtime_instance_id"] == independent
    save("original-fpm-observations.json", {"prior": prior, "enabled": guarded_data, "after_disable": prior,
          "restart_pid_changed": True, "control_instance_preserved": True, "enable_job": enable, "disable_job": disable})
    proof.update(ok=True, actual_site_fpm=True, process_functions_disabled=True, separate_site_unchanged=True,
                 original_files_retained=True, restart_persistence=True, reversible=True)
except BaseException:
    import traceback
    proof["failure"] = traceback.format_exc()
finally:
    if csrf:
        with contextlib.suppress(Exception):
            api("/logout", {})
    save("original-proof.json", proof)
sys.exit(0 if proof["ok"] else 1)
