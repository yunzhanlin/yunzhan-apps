"""Retain the GitHub runner's built-in Docker state and prepare a clean install."""
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys

assert os.geteuid() == 0 and os.environ.get('GITHUB_ACTIONS') == 'true'
assert os.environ.get('GITHUB_REPOSITORY') == 'yunzhanlin/yunzhan-apps'
assert os.environ.get('RUNNER_ENVIRONMENT') == 'github-hosted'
assert len(sys.argv) == 2
out = Path(sys.argv[1]).resolve(strict=True)
assert out.name == 'docker-container-metrics-private'
assert not Path('/opt/panel').exists()
os.umask(0o077)

packages = {
    'docker-ce', 'docker-ce-cli', 'docker-ce-rootless-extras', 'docker-buildx-plugin',
    'docker-compose-plugin', 'containerd.io', 'docker.io', 'docker-compose',
    'docker-compose-v2', 'docker-doc', 'docker-buildx', 'podman-docker', 'containerd', 'runc',
}


def run(*args, check=True):
    return subprocess.run(args, stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=120,
                          check=check, env={**os.environ, 'LC_ALL': 'C', 'DEBIAN_FRONTEND': 'noninteractive'})


def save(name, value):
    with (out / name).open('x') as handle:
        json.dump(value, handle, indent=2)
        handle.write('\n')


installed = {}
for name in sorted(packages):
    result = run('/usr/bin/dpkg-query', '-W', '-f=${Status} ${Version}', name, check=False)
    if result.stdout.startswith('install ok installed '):
        installed[name] = result.stdout.split()[-1]
save('runner-docker-original-packages.json', installed)

if installed:
    command = ['/usr/bin/apt-get', '--no-auto-remove']
    simulation = run(*command, '--simulate', 'remove', *sorted(installed)).stdout
    removals = set(re.findall(r'^Remv (\S+)', simulation, re.M))
    assert removals == set(installed) and not re.search(r'^(Inst|Conf|Purg) ', simulation, re.M)
    active = run('/usr/bin/systemctl', 'is-active', 'docker.service', check=False).stdout.strip()
    if active == 'active':
        assert run('/usr/bin/docker', 'ps', '--all', '--quiet').stdout == ''
    else:
        assert active in ('inactive', 'failed')
    for unit in ('docker.socket', 'docker.service', 'containerd.service'):
        load = run('/usr/bin/systemctl', 'show', '--property=LoadState', '--value', unit, check=False)
        assert load.stdout.strip() in ('loaded', 'not-found')
        if load.stdout.strip() == 'loaded':
            run('/usr/bin/systemctl', 'stop', unit)
    preserved = {}
    for name in ('docker', 'containerd'):
        source = Path('/var/lib') / name
        if not os.path.lexists(source):
            continue
        s = source.lstat()
        assert stat.S_ISDIR(s.st_mode) and s.st_uid == 0 and not s.st_mode & 0o022
        assert not os.path.ismount(source)
        dest = source.with_name('c106r3-original-runner-' + name)
        assert not os.path.lexists(dest)
        source.rename(dest)
        assert dest.lstat().st_ino == s.st_ino
        preserved[str(source)] = str(dest)
    save('runner-docker-original-state-retained.json', preserved)
    result = run(*command, '-y', 'remove', *sorted(installed), check=False)
    save('runner-docker-package-preparation.json', {'exit': result.returncode,
        'stdout': result.stdout, 'stderr': result.stderr})
    assert result.returncode == 0

assert not os.path.lexists('/var/lib/docker') and not os.path.lexists('/var/lib/containerd')
assert not os.path.lexists('/etc/apt/sources.list.d/docker.list')
