"""Retrieve the exact signed baseline and upgrade for the native fixture."""

import hashlib
import json
import os
import pathlib
import platform
import subprocess
import sys


os.umask(0o077)
assert len(sys.argv) == 4 and os.environ['GITHUB_ACTIONS'] == 'true'
assert os.environ['GITHUB_REPOSITORY'] == 'yunzhanlin/yunzhan-apps'
arch = {'x86_64': 'amd64', 'aarch64': 'arm64'}[platform.machine()]
source = pathlib.Path(__file__).resolve().parent
old, new, private = map(pathlib.Path, sys.argv[1:])
for d in (old, new, private):
    d.mkdir(mode=0o700)


def read(name):
    return json.loads((source / name).read_bytes())


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def git(*args):
    return subprocess.check_output(['git', *args], timeout=30)


def save(name, data):
    with (private / (name + '.json')).open('x') as out:
        json.dump(data, out, indent=2)


cohort, dispatch, upgrade = (read(name) for name in ('cohort.json', 'dispatch.json', 'upgrade.json'))
assert git('rev-parse', 'HEAD^').decode().strip() == cohort['source_head'] == upgrade['source_head']
assert cohort['source_inputs_sha256'] == upgrade['source_inputs_sha256'] and cohort['version'] == dispatch['version']
changes = {os.fsdecode(path) for path in git('diff', '--name-only', '-z', 'HEAD^', 'HEAD').split(b'\0') if path}
assert changes == set(cohort['payload_files']) | {'scripts/native-openlitespeed-c74/cohort.json'}
assert all(sha(pathlib.Path(name)) == digest for name, digest in cohort['payload_files'].items())
sdk = 'candidate/panel-integration-compose-signed-image'
assert git('rev-parse', 'HEAD:' + sdk).decode().strip() == upgrade['source_sdk_tree']
assert git('rev-parse', 'HEAD^^:' + sdk).decode().strip() == dispatch['source_sdk_tree']


def download(label, spec, target):
    prefix = 'repos/yunzhanlin/yunzhan-apps/releases/'
    result = subprocess.run(['gh', 'api', prefix + str(spec['release_id'])], check=True,
                            capture_output=True, timeout=75)
    metadata = json.loads(result.stdout)
    assert metadata['id'] == spec['release_id'] and metadata['tag_name'] == spec['tag']
    assert not metadata['draft'] and metadata['prerelease'] and metadata['target_commitish'] == spec['source_head']
    assets = {item['name']: item for item in metadata['assets']}
    pins = spec['release_assets']
    assert set(assets) == set(pins) and len(assets) == len(metadata['assets'])
    save(label + '-release', metadata)
    archive = spec['cohorts'][arch]['archive']
    names = [archive + suffix for suffix in ('', '.manifest', '.sig')] + ['release-signing-dev.pub']
    for name in names:
        asset, pin = assets[name], pins[name]
        assert (asset['id'], asset['size'], asset['digest'], asset['state']) == (
            pin['id'], pin['bytes'], 'sha256:' + pin['sha256'], 'uploaded')
        file = target / name
        subprocess.run(['/usr/bin/curl', '--disable', '--fail', '--silent', '--show-error', '--location',
                        '--proto', '=https', '--proto-redir', '=https', '--connect-timeout', '15',
                        '--max-time', '150', '--retry', '2', '--retry-all-errors', '--output', str(file),
                        asset['browser_download_url']], check=True, timeout=470, capture_output=True)
        assert file.stat().st_size == pin['bytes'] and sha(file) == pin['sha256']
    assert sha(target / 'release-signing-dev.pub') == '4ccfcc861d56a41e3ba7f7ace7e2432c815f366c58448d783df92c6632f01339'
    save(label + '-download-proof', {'ok': True, 'architecture': arch, 'source_head': spec['source_head'],
         'source_inputs_sha256': spec['source_inputs_sha256'], 'release_id': spec['release_id'], 'assets': names})


download('original-baseline', dispatch, old)
download('original-upgrade', upgrade, new)
verifier = source / 'original-signed-release.py'
assert sha(verifier) == 'fe128e82b4e11345b320cd782134768bfe1a4df14947c425d7494873a7a7b7b5'
with (old / 'signed-release.py').open('xb') as f:
    f.write(verifier.read_bytes())
