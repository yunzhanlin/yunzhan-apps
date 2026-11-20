"""Exercise one legacy PHP release on a disposable native host through the real panel."""
import contextlib
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
slot = sys.argv[2]
assert slot in plan['recipes']
recipe = plan['recipes'][slot]
target = recipe['target']
app_id = 'php-' + slot
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


def lifecycle(label, route, data):
    save(label + '-original-request.json', {'path': route, 'payload': data, 'maximum_posts': 1})
    answer = api(route, data, 202)
    id = answer['job_id']
    assert re.fullmatch('[0-9a-f]{32}', id)
    row = wait(lambda: api('/docker/job-observations/' + id),
               lambda row: row['state'] in ('succeeded', 'failed', 'needs_attention'))
    save(label + '-original-outcome.json', row)
    assert row['state'] == 'succeeded', label
    assert row['project_id'] == answer['project_id']
    return answer


def project(id):
    return next((x for x in api('/docker/projects')['projects'] if x['id'] == id), None)


def compose_live(id):
    return wait(lambda: project(id),
                lambda p: p and p['state'] == 'running' and p['services'] == p['healthy'] == p['running'] == 2)


def docker(*args, input=None):
    return subprocess.check_output(['/usr/bin/docker', *args], input=input, text=True, timeout=35).strip()


def inspect(p):
    ids = docker('ps', '-aq', '--filter', 'label=com.docker.compose.project=' + p['engine_name']).splitlines()
    assert len(ids) >= 1 and all(re.fullmatch('[0-9a-f]{12,64}', id) for id in ids)
    records = json.loads(docker('inspect', *ids))
    return {r['Config']['Labels']['com.docker.compose.service']: r for r in records}


def mount_identity(container):
    result = {mount['Destination']: mount for mount in container['Mounts']}
    assert len(result) == len(container['Mounts'])
    return result


def http(port, path='/', expected=200):
    assert isinstance(port, int) and port in (26778, 26779)
    try:
        with client.open(f'http://127.0.0.1:{port}{path}', timeout=25) as response:
            assert response.status == expected
            return response.read(1 << 20)
    except urllib.error.HTTPError as error:
        assert error.code == expected
        return error.read(4096)


def site_file(record, name, contents):
    assert name in ('retained.txt', '.private.php') and contents in ('original', 'retained')
    command = 'printf %s "$1" > "/var/www/html/$2"'
    docker('exec', record['Id'], 'sh', '-c', command, '--', contents, name)


def current_catalogue():
    for delay in (15, 60, 60, 0):
        try:
            data = api('/app-registry?refresh=1')
            assert not data['source']['stale'] and data['host'] == {'platform': 'ubuntu-24.04', 'architecture': arch}
            return data
        except urllib.error.HTTPError as error:
            raw = error.read(4096)
            try:
                details = json.loads(raw)
                reason = str(details.get('error', ''))[:500]
            except (TypeError, ValueError):
                reason = 'catalogue response was not JSON'
            with (out / 'catalogue-refusals.jsonl').open('a') as log:
                log.write(json.dumps({'status':error.code,'reason':reason}) + '\n')
            if error.code != 503 or not delay:
                raise
            time.sleep(delay)



proof = {'ok': False, 'application': app_id, 'architecture': arch, 'source_inputs_sha256': plan['source_inputs_sha256'], 'Main_changed': False, 'all50_commercial': False}
def module_install(id):
    item=plan['apps'][id]
    result=api('/app-registry/'+id+'/install',{'expected_version':item['version'],'expected_sha256':item['sha256'],'settings':{}},202)
    row=wait(lambda:api('/jobs/'+result['job_id']),lambda v:v['state']in('succeeded','failed','needs_attention'))
    save('signed-'+id+'-module-job.json',row);assert row['state']=='succeeded';return result['job_id']
try:
    login=json.loads(Path('/etc/panel/first-login.json').read_bytes());csrf=api('/login',{k:login[k]for k in('username','password')})['csrf'];login.clear()
    data=current_catalogue();assert data['source']['resolved_commit']==plan['served_head']
    item,=[v for v in data['catalog']['apps']if v['id']==app_id];assert item==plan['apps'][app_id]
    status,=[v for v in data['status']if v['id']==app_id];assert status['supported']and status['state_known']and not status['installed']
    original_job=lifecycle('original-static-project','/docker/projects',{'name':'c220-original-static','template_id':'nginx-static','host_port':26778,'compose':''})
    original=wait(lambda:project(original_job['project_id']),lambda p:p and p['state']=='running'and p['services']==p['running']==p['healthy']==1)
    before=inspect(original);original_http=http(26778)
    job=lifecycle('current-signed-php-install','/app-registry/'+app_id+'/install',{'expected_version':item['version'],'expected_sha256':item['sha256'],'name':'c220-current-php','host_port':26779})
    id=job['project_id'];owned=compose_live(id);running=inspect(owned);php,web=running['php'],running['web'];assert owned['template_id']==target and php['Config']['Image']==recipe['image']
    assert docker('image','inspect','-f','{{.Os}}/{{.Architecture}}',php['Image'])=='linux/'+arch
    assert php['HostConfig']['ReadonlyRootfs']and web['HostConfig']['ReadonlyRootfs']and not php['HostConfig']['PortBindings']
    assert web['HostConfig']['PortBindings']=={'8080/tcp':[{'HostIp':'127.0.0.1','HostPort':'26779'}]}
    assert all(not v['HostConfig']['Privileged']for v in running.values())
    result=json.loads(http(26779));save('actual-fastcgi-response.json',result);assert result['version']==recipe['version']and result['sapi']==('cgi-fcgi'if slot=='52'else'fpm-fcgi')and result['mysqli']and result['pdo_mysql'];assert result['mysql']is(slot in('52','53','54','55','56'))
    old_volumes={m['Name']for v in before.values()for m in v['Mounts']if m['Type']=='volume'};new_volumes={m['Name']for v in running.values()for m in v['Mounts']if m['Type']=='volume'};assert old_volumes and new_volumes and old_volumes.isdisjoint(new_volumes)
    module_install('files-sync')
    slug='c220-source-'+slot;src=api('/sites',{'name':slug,'slug':slug,'domain':slug+'.example.test','php_version_id':''},202);srcjob=wait(lambda:api('/jobs/'+src['job_id']),lambda v:v['state']in('succeeded','failed','needs_attention'));save('source-site-job.json',srcjob);assert srcjob['state']=='succeeded'
    source_site,=[v for v in api('/sites')if v['slug']==slug]
    content="<?php header('Content-Type: text/plain'); echo 'c220-synced-' . PHP_VERSION; ?>\n"
    static='c220-static-'+slot+'-'+arch+'\n'
    for name,text in [('roundtrip.php',content),('c220-proof.txt',static)]:
        created=api('/sites/'+source_site['id']+'/files/action',{'action':'create','path':name,'content':text});assert created['path']==name
    sync={'site_id':source_site['id'],'target_project_id':id,'excludes':['index.html']}
    preview=api('/app-modules/files-sync/preview',sync);save('actual-legacy-preview.json',preview);assert preview['preview']and not preview['conflicts']and {'roundtrip.php','c220-proof.txt'}.issubset(set(preview['copied']))
    http(26779,'/roundtrip.php',404)
    synced=api('/app-modules/files-sync/sync',sync);save('actual-legacy-sync.json',synced);assert not synced['preview']and not synced['conflicts']and {'roundtrip.php','c220-proof.txt'}.issubset(set(synced['copied']))
    assert http(26779,'/roundtrip.php')==('c220-synced-'+recipe['version']).encode()and http(26779,'/c220-proof.txt')==static.encode()
    again=api('/app-modules/files-sync/preview',sync);save('actual-post-sync-preview.json',again);assert again['copied_count']==again['conflicts_count']==0
    domain='current-php'+slot+'.example.test';binding=api('/docker/projects/'+id+'/sites',{'name':domain,'slug':'c220-php'+slot,'domain':domain},202);bound=wait(lambda:api('/jobs/'+binding['job_id']),lambda v:v['state']in('succeeded','failed','needs_attention'));save('bound-domain-original-outcome.json',bound);assert bound['state']=='succeeded'
    with client.open(urllib.request.Request('http://127.0.0.1:19101/roundtrip.php',headers={'Host':domain}),timeout=25)as response:assert response.status==200 and response.read(1<<20)==('c220-synced-'+recipe['version']).encode()
    site_file(php,'retained.txt','retained');site_file(php,'.private.php','retained');http(26779,'/.private.php',403)
    lifecycle('current-stop','/docker/projects/'+id+'/stop',{});lifecycle('current-start','/docker/projects/'+id+'/start',{});latest=inspect(compose_live(id))
    assert all(latest[name]['Id']==running[name]['Id']and mount_identity(latest[name])==mount_identity(running[name])for name in('php','web'))
    assert http(26779,'/retained.txt')==b'retained'and http(26779,'/c220-proof.txt')==static.encode()and json.loads(http(26779))==result
    current=inspect(project(original['id']));assert set(current)==set(before)
    assert all(before[name]['Id']==current[name]['Id']and before[name]['State']['StartedAt']==current[name]['State']['StartedAt']and mount_identity(before[name])==mount_identity(current[name])for name in before)
    assert http(26778)==original_http
    final=api('/app-registry');state,=[v for v in final['status']if v['id']==app_id];assert state['installed']and state['installed_version']==recipe['app_version']and not state['update_available']
    proof.update(ok=True,signed_app_version=recipe['app_version'],actual_version=recipe['version'],actual_fastcgi_http=True,mysql_drivers=True,actual_verified_directory_source_sync=True,actual_managed_domain_synced_php=True,hidden_file_denied=True,retained_synced_files_and_named_volumes=True,original_static_container_and_data_preserved=True,signed_store_install=True,original_job=job['job_id'],source_site_id=source_site['id'],target_project_id=id,source_and_target_independent=True)
except BaseException:
    import traceback
    proof['failure']=traceback.format_exc()
finally:
    if csrf:
        with contextlib.suppress(Exception):api('/logout',{})
    save('original-proof.json',proof)
sys.exit(0 if proof['ok']else 1)
