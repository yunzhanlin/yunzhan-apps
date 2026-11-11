"""Exercise the official Apache and PHP runtime installations through the panel through the real panel."""
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
    raise TimeoutError('Panel job or Docker health did not settle')



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
    assert domain == "apache-c88.example.test" and path in ("/c88.php", "/c88.txt")
    request = urllib.request.Request("http://127.0.0.1:19101" + path, headers={"Host": domain})
    with client.open(request, timeout=20) as result:
        assert result.status == 200
        return result.read(1 << 20)


def system(*args):
    return subprocess.check_output(args, text=True, stderr=subprocess.STDOUT, timeout=60).strip()


proof = {"ok": False, "architecture": arch, "source_inputs_sha256": plan["source_inputs_sha256"],
         "Main_changed": False, "all50_commercial": False}
try:
    login = json.loads(Path("/etc/panel/first-login.json").read_bytes())
    csrf = api("/login", {k: login[k] for k in ("username","password")})["csrf"]
    login.clear()
    catalog = api("/app-registry?refresh=1")
    assert not catalog["source"]["stale"]
    assert catalog["source"]["resolved_commit"] in plan["authorized_catalogues"]
    assert catalog["host"] == {"platform":"ubuntu-24.04","architecture":arch}
    for app in ("apache","php-85"):
        item, = [v for v in catalog["catalog"]["apps"] if v["id"] == app]
        status, = [v for v in catalog["status"] if v["id"] == app]
        assert item == plan["items"][app] and status["supported"] and status["state_known"] and not status["installed"]
        receipt, run = job("install-" + app, "/app-registry/" + app + "/install",
                           {"expected_version":item["version"],"expected_sha256":item["sha256"]}, 3050)
        assert receipt["provider"] == "runtime" and receipt["target"] == item["target"]
        proof[app] = {"job":run["id"],"manifest_sha256":item["sha256"],"version":item["version"]}

    apache = "/opt/panel/runtimes/apache/2.4.68/bin/httpd"
    php = "/opt/panel/runtimes/php/8.5.12/bin/php"
    assert "Apache/2.4.68" in system(apache, "-v")
    assert system(php, "-r", 'echo PHP_VERSION;') == "8.5.12"
    domain = "apache-c88.example.test"
    _, created = job("create-native-site", "/sites",
                     {"name":"Apache native PHP QA", "slug":"apache-c88", "domain":domain,
                      "php_version_id":"php-8.5.12"}, 300)
    site = created["site_id"]
    assert re.fullmatch("[0-9a-f]{32}", site)
    route = "/sites/" + site
    php_code = """<?php
header('Content-Type: application/json');
echo json_encode(['php' => PHP_VERSION, 'sapi' => PHP_SAPI, 'software' => $_SERVER['SERVER_SOFTWARE'], 'answer' => 19 * 7]);
"""
    text = "native Apache retained page\n"
    for filename, body in (("c88.php",php_code),("c88.txt",text)):
        saved = api(route + "/files/action", {"action":"create","path":filename,"content":body})
        assert saved["sha256"] == hashlib.sha256(body.encode()).hexdigest()
    pre_switch = json.loads(site_http(domain, "/c88.php"))
    assert pre_switch["php"] == "8.5.12" and pre_switch["sapi"] == "fpm-fcgi" and "nginx" in pre_switch["software"].lower()
    current = api(route + "/settings")
    assert current["php_version_id"] == "php-8.5.12" and current["settings"]["web_server"] == "nginx"
    settings = {**current["settings"],"web_server":"apache"}
    input = {"settings":settings,"expected_revision":current["settings_revision"]}
    preview = api(route + "/settings/preview", input)
    assert re.fullmatch("[0-9a-f]{64}", preview["config_sha"])
    invalid = api(route + "/settings/preview", {**input,"settings":{**settings,"web_server":"fixture-invalid"}},400)
    assert invalid["error"]
    _, switch = job("switch-to-apache", route + "/settings",
                    {**input,"expected_config_sha":preview["config_sha"]}, 300)
    assert switch["site_id"] == site
    configured = api(route + "/settings")
    assert configured["settings"]["web_server"] == "apache"
    result = json.loads(site_http(domain, "/c88.php"))
    assert result["php"] == "8.5.12" and result["sapi"] == "fpm-fcgi" and "Apache/2.4.68" in result["software"]
    assert result["answer"] == 133 and site_http(domain, "/c88.txt") == text.encode()
    conf = "/etc/panel/apache/httpd.conf"
    assert "Syntax OK" in system(apache, "-t", "-f", conf)
    assert "proxy_fcgi_module" in system(apache, "-M", "-f", conf)
    pid = int(system("/usr/bin/systemctl","show","panel-apache","--property=MainPID","--value"))
    assert pid > 1
    system("/usr/bin/systemctl","restart","panel-apache")
    new_pid = int(system("/usr/bin/systemctl","show","panel-apache","--property=MainPID","--value"))
    assert new_pid > 1 and new_pid != pid
    assert json.loads(site_http(domain, "/c88.php")) == result
    assert site_http(domain, "/c88.txt") == text.encode()
    retained = api(route + "/files/text?path=c88.php")
    assert retained["sha256"] == hashlib.sha256(php_code.encode()).hexdigest()
    save("apache-php-original-business.json",{"before":pre_switch,"after":result,"pid_changed":True})
    proof.update(ok=True,signed_native_app_install=True,apache_mod_proxy_fcgi=True,
                 actual_http_php_and_static=True,ordinary_site_settings=True,retained_after_restart=True)
except BaseException:
    import traceback
    proof["failure"] = traceback.format_exc()
finally:
    if csrf:
        with contextlib.suppress(Exception):
            api("/logout", {})
    save("original-proof.json",proof)
sys.exit(0 if proof["ok"] else 1)
