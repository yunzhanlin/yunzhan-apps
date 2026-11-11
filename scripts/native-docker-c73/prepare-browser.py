"""Prepare the pinned, sandboxed Chromium and local login on a disposable host."""

import hashlib
import json
import os
import pathlib
import platform
import secrets
import shutil
import stat
import subprocess
import sys
import zipfile


os.umask(0o077)
assert os.geteuid() == 0 and len(sys.argv) == 3
assert os.environ.get('GITHUB_ACTIONS') == 'true'
assert os.environ.get('GITHUB_REPOSITORY') == 'yunzhanlin/yunzhan-apps'
archive_path, evidence = map(pathlib.Path, sys.argv[1:])
runner = evidence.stat()
assert runner.st_uid > 0 and stat.S_IMODE(runner.st_mode) == 0o700
source = pathlib.Path(__file__).resolve().parent
arch = {'x86_64': 'amd64', 'aarch64': 'arm64'}[platform.machine()]
pin = json.loads((source / 'browser-pins.json').read_bytes())[arch]
cohort = json.loads((source / 'cohort.json').read_bytes())


def digest(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


assert archive_path.stat().st_size == pin['bytes'] and digest(archive_path) == pin['sha256']
nonce = secrets.token_hex(16)
browser_root = pathlib.Path('/opt') / f'yunzhan-c72-browser-{nonce}'
browser_root.mkdir(mode=0o755)
seen = set()
total = 0
with zipfile.ZipFile(archive_path) as archive:
    for item in archive.infolist():
        relative = pathlib.PurePosixPath(item.filename)
        assert not relative.is_absolute() and '..' not in relative.parts and relative not in seen
        seen.add(relative)
        target = browser_root / relative
        if item.is_dir():
            target.mkdir(parents=True, exist_ok=True)
            continue
        mode = item.external_attr >> 16
        assert stat.S_IFMT(mode) in (0, stat.S_IFREG)
        total += item.file_size
        assert total < 1600 << 20
        target.parent.mkdir(parents=True, exist_ok=True)
        with archive.open(item) as src, target.open('xb') as dst:
            shutil.copyfileobj(src, dst, 1 << 20)
        target.chmod(0o755 if mode & 0o111 else 0o644)
for root, _, _ in os.walk(browser_root):
    pathlib.Path(root).chmod(0o755)
chrome, sandbox = (browser_root / pin[k] for k in ('chrome_path', 'sandbox_path'))
assert digest(chrome) == pin['chrome_sha256'] and digest(sandbox) == pin['sandbox_sha256']
sandbox.chmod(0o4755)

profile_name = f'yunzhan-c72-{nonce}'
profile_path = pathlib.Path('/etc/apparmor.d') / profile_name
with profile_path.open('x') as profile:
    profile.write(
        'abi <abi/4.0>,\ninclude <tunables/global>\n'
        f'profile {profile_name} "{chrome}" flags=(unconfined) {{\n  userns,\n}}\n'
    )
subprocess.run(
    ['/usr/sbin/apparmor_parser', '--add', '--skip-cache', str(profile_path)],
    check=True, timeout=30,
)
profiles = pathlib.Path('/sys/kernel/security/apparmor/profiles').read_text().splitlines()
assert f'{profile_name} (unconfined)' in profiles
secret = pathlib.Path('/etc/panel/first-login.json')
secret_stat = secret.lstat()
assert stat.S_ISREG(secret_stat.st_mode) and secret_stat.st_uid == 0
assert secret_stat.st_nlink == 1 and stat.S_IMODE(secret_stat.st_mode) == 0o600
access = json.loads(secret.read_bytes())
runtime = pathlib.Path('/opt/panel/current').resolve(strict=True)
assert runtime.name == cohort['version']
assert json.loads((runtime / 'SOURCE_INPUTS.json').read_bytes())['inputs_sha256'] == cohort['source_inputs_sha256']
for name, body in {
    'browser-credentials.json': {field: access[field] for field in ('username', 'password')},
    'browser-setup.json': {
        'architecture': arch,
        'kernel': platform.release(),
        'chrome': str(chrome),
        'sandbox': str(sandbox),
        'browser_version': pin['version'],
        'source_inputs_sha256': cohort['source_inputs_sha256'],
        'panel_version': cohort['version'],
        'apps': cohort['apps'],
    },
}.items():
    target = evidence / name
    with target.open('x') as output:
        json.dump(body, output)
    os.chown(target, runner.st_uid, runner.st_gid)
