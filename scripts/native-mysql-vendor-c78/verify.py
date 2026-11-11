"""Verify exact Oracle MySQL vendor artifacts using the pinned public key."""

import hashlib
import json
import os
import pathlib
import platform
import subprocess
import sys


os.umask(0o077)
assert os.environ['GITHUB_ACTIONS'] == 'true' and os.environ['GITHUB_REPOSITORY'] == 'yunzhanlin/yunzhan-apps'
arch = {'x86_64': 'amd64', 'aarch64': 'arm64'}[platform.machine()]
name = {'amd64': 'mysql-8.4.13-linux-glibc2.28-x86_64-minimal.tar.xz',
        'arm64': 'mysql-8.4.13-linux-glibc2.28-aarch64.tar.xz'}[arch]
source = pathlib.Path(__file__).resolve().parent
key = source / 'official-build-key.asc'
fingerprint = 'BCA43417C3B485DD128EC6D4B7B3B788A8D3785C'
assert hashlib.sha256(key.read_bytes()).hexdigest() == 'a4bcd9f16a53cc763f87b9955dbcdced33c7aa90296b157eb6ceef0f156f4327'
base = pathlib.Path(sys.argv[1])
base.mkdir(mode=0o700)
public = pathlib.Path(sys.argv[2])
public.mkdir(mode=0o700)
keyring = base / 'gnupg'
keyring.mkdir(mode=0o700)
gpg = ['/usr/bin/gpg', '--batch', '--homedir', str(keyring), '--no-auto-key-retrieve']
subprocess.run(gpg + ['--import', str(key)], capture_output=True, check=True, timeout=30)
identity = subprocess.check_output(gpg + ['--with-colons', '--list-keys'], text=True, timeout=30)
keys = [row.split(':')[9] for row in identity.splitlines() if row.startswith('fpr:')]
assert keys[0] == fingerprint and sum(row.startswith('pub:') for row in identity.splitlines()) == 1


def fetch(n, cap):
    url = 'https://cdn.mysql.com/Downloads/MySQL-8.4/' + n
    path = base / n
    args = ['/usr/bin/curl', '--disable', '--fail', '--silent', '--show-error', '--location', '--proto', '=https',
            '--proto-redir', '=https', '--connect-timeout', '20', '--max-time', '800', '--retry', '2',
            '--max-filesize', str(cap), '--output', str(path), '--write-out', '%{http_code} %{url_effective}', url]
    result = subprocess.run(args, capture_output=True, check=True, text=True, timeout=2440)
    assert result.stdout == '200 ' + url
    return path


artifact = fetch(name, 2 << 30)
signature = fetch(name + '.asc', 1 << 20)
result = subprocess.run(gpg + ['--status-fd', '1', '--verify', str(signature), str(artifact)], capture_output=True, timeout=150)
(public / 'original-gpg-status.txt').write_bytes(result.stdout)
(public / 'original-gpg-stderr.txt').write_bytes(result.stderr)
assert result.returncode == 0, 'Oracle detached signature verification failed'
lines = [row.split() for row in result.stdout.decode().splitlines()]
valid, = [row for row in lines if len(row) > 2 and row[1] == 'VALIDSIG']
assert valid[2] == fingerprint or valid[-1] == fingerprint
assert any(row[:2] == ['[GNUPG:]', 'GOODSIG'] for row in lines)
assert not any(row[1] in ('EXPKEYSIG', 'REVKEYSIG', 'BADSIG', 'ERRSIG') for row in lines if len(row) > 1)
with artifact.open('rb') as file:
    sha = hashlib.file_digest(file, 'sha256').hexdigest()
proof = {'ok': True, 'architecture': arch, 'name': name, 'bytes': artifact.stat().st_size, 'sha256': sha,
         'signature_sha256': hashlib.sha256(signature.read_bytes()).hexdigest(), 'fingerprint': fingerprint,
         'signature_valid': True, 'installed_or_published_vendor_package': False}
(public / 'original-proof.json').write_text(json.dumps(proof, indent=2) + '\n')
print(json.dumps(proof))
