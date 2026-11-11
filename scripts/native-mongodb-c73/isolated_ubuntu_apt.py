"""Select a verified Ubuntu archive for a disposable test host's installer."""

import hashlib
import pathlib
import subprocess
import tempfile


KEYRING = pathlib.Path('/usr/share/keyrings/ubuntu-archive-keyring.gpg')
SUITES = ('jammy', 'jammy-updates', 'jammy-backports', 'jammy-security')
ARCHIVES = {
    'amd64': (
        'https://archive.ubuntu.com/ubuntu',
        'https://mirror.csclub.uwaterloo.ca/ubuntu',
    ),
    'arm64': (
        'https://mirror.csclub.uwaterloo.ca/ubuntu-ports',
        'https://ports.ubuntu.com/ubuntu-ports',
    ),
}


def isolated_ubuntu_apt(architecture, save):
    """Supply process-local APT configuration using the host archive keyring."""
    root = pathlib.Path(tempfile.mkdtemp(prefix='panel-qa-ubuntu-apt-', dir='/run'))
    observations = []
    try:
        for archive in ARCHIVES[architecture]:
            checks = []
            for suite in SUITES:
                metadata = root / f'{suite}.InRelease'
                try:
                    download = subprocess.run(
                        ['/usr/bin/curl', '--disable', '--silent', '--show-error', '--fail',
                         '--location', '--proto', '=https', '--proto-redir', '=https',
                         '--connect-timeout', '6', '--max-time', '15', '--max-filesize',
                         '1048576', '--output', str(metadata), f'{archive}/dists/{suite}/InRelease'],
                        capture_output=True, check=False, timeout=20,
                    )
                except subprocess.TimeoutExpired:
                    checks.append({'suite': suite, 'download_exit': 124, 'error': 'Archive probe timed out'})
                    break
                check = {'suite': suite, 'download_exit': download.returncode}
                checks.append(check)
                if download.returncode:
                    check['error'] = download.stderr.decode(errors='replace')[:500]
                    break
                signature = subprocess.run(
                    ['/usr/bin/gpgv', '--keyring', str(KEYRING), str(metadata)],
                    capture_output=True, check=False, timeout=10,
                )
                check['signature_exit'] = signature.returncode
                check['sha256'] = hashlib.sha256(metadata.read_bytes()).hexdigest()
                if signature.returncode:
                    break
            observations.append({'archive': archive, 'suite_checks': checks})
            if len(checks) != len(SUITES) or any(c.get('signature_exit') != 0 for c in checks):
                continue
            source = root / 'ubuntu.sources'
            source.write_text(
                f'Types: deb\nURIs: {archive}\nSuites: {" ".join(SUITES)}\n'
                'Components: main restricted universe multiverse\n'
                f'Architectures: {architecture}\nSigned-By: {KEYRING}\n'
            )
            config = root / 'apt.conf'
            config.write_text(
                f'Dir::Etc::sourcelist "{source}";\n'
                'Dir::Etc::sourceparts "-";\n'
            )
            return str(config)
        raise RuntimeError('No Ubuntu archive served all four signed suites')
    finally:
        save('isolated-Ubuntu-archive-observations.json', observations)
