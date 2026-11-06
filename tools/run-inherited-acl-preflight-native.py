"""Retain actual Root POSIX ACL and CLI fixtures; this is not installed acceptance."""
import ast
import hashlib
import json
import os
import pathlib
import platform
import pwd
import re
import stat
import subprocess
import sys
import time

os.umask(0o077)
ROOT = pathlib.Path(__file__).resolve().parents[1]
SDK = ROOT / 'candidate/panel-integration-load-balance'
SPEC = json.loads((ROOT / 'tools/inherited-acl-preflight-execution.json').read_bytes())


def source_files():
    index = json.loads((SDK / 'source-sha256.json').read_bytes())
    assert index['release']['frozen_inputs_sha256'] == SPEC['source_inputs_sha256']
    assert len(index['files']) == SPEC['source_sdk_files'] == 2467
    actual = {name: hashlib.sha256((SDK / name).read_bytes()).hexdigest()
              for name in SPEC['source_files']}
    assert actual == SPEC['source_files']
    assert all(index['files'][name] == digest for name, digest in actual.items())
    module = ast.parse((SDK / 'packaging/test_native_build_directories.py').read_bytes())
    methods = sorted(cls.name + '.' + method.name for cls in module.body
                     if isinstance(cls, ast.ClassDef) for method in cls.body
                     if isinstance(method, ast.FunctionDef) and method.name.startswith('test_'))
    assert methods == SPEC['python_methods'] and len(methods) == 20
    return actual


def main():
    assert len(sys.argv) == 2 and os.geteuid() == os.getegid() == 0
    assert platform.system() == 'Linux' and platform.machine() in ('x86_64', 'aarch64')
    assert pathlib.Path('/proc/1/comm').read_text().strip() == 'systemd'
    assert os.environ.get('GITHUB_ACTIONS') == 'true'
    assert os.environ.get('GITHUB_REPOSITORY') == 'yunzhanlin/yunzhan-apps'
    owner = ROOT.stat()
    assert owner.st_uid != 0 and pwd.getpwuid(owner.st_uid).pw_name == 'runner'
    before = source_files()
    out = pathlib.Path(sys.argv[1])
    out.mkdir(mode=0o700)
    assert stat.S_ISDIR(out.lstat().st_mode) and not out.is_symlink()
    created = []

    def save(name, value):
        target = out / name
        with target.open('x') as stream:
            json.dump(value, stream, indent=2, sort_keys=True)
            stream.write('\n')
            stream.flush()
            os.fsync(stream.fileno())
        created.append(target)

    started = time.monotonic()
    args = [sys.executable, '-I', '-B', '-m', 'unittest', 'discover', '-s',
            str(SDK / 'packaging'), '-p', 'test_native_build_directories.py', '-v']
    try:
        save('original-intent.json', {'args': args, 'maximum_submissions': 1,
             'source_inputs_sha256': SPEC['source_inputs_sha256'], 'source_files': before,
             'process_fixtures_only': True, 'actual_native_install_acceptance': False})
        stdout = out / 'original.stdout'
        stderr = out / 'original.stderr'
        with stdout.open('xb') as output, stderr.open('xb') as error:
            created.extend((stdout, stderr))
            try:
                result = subprocess.run(args, stdin=subprocess.DEVNULL, stdout=output,
                                        stderr=error, timeout=180)
            except subprocess.TimeoutExpired:
                save('original-exit.json', {'exit': None, 'timeout': True,
                     'elapsed_seconds': time.monotonic() - started})
                raise
        save('original-exit.json', {'exit': result.returncode, 'timeout': False,
             'elapsed_seconds': time.monotonic() - started})
        # The child outcome and original bytes are durable before interpretation.
        assert stdout.stat().st_size < 1 << 20 and stderr.stat().st_size < 1 << 20
        raw = stderr.read_text()
        passed = []
        for line in raw.splitlines():
            match = re.fullmatch(r'(test_\w+) \(test_native_build_directories\.(\w+)(?:\.(test_\w+))?\) \.\.\. ok', line)
            if match:
                method, cls, repeated = match.groups()
                assert repeated is None or repeated == method
                passed.append(cls + '.' + method)
        assert result.returncode == 0
        assert len(passed) == len(set(passed)) == 20 and sorted(passed) == SPEC['python_methods']
        assert re.search(r'\nRan 20 tests in [0-9.]+s\n\nOK\n?\Z', raw)
        assert not any(token in raw for token in ('... skipped ', '... FAIL', '... ERROR', 'expected failure', 'unexpected success'))
        after = source_files()
        assert before == after
        proof = {'ok': True, 'architecture': platform.machine(), 'uid': os.geteuid(),
                 'source_inputs_sha256': SPEC['source_inputs_sha256'], 'source_files': after,
                 'actual_PASS': 20, 'passed': sorted(passed), 'skips': 0,
                 'original_exit': result.returncode, 'actual_kernel_xattrs_and_original_CLI_fixtures': True,
                 'actual_native_systemd_install_acceptance': False,
                 'raw': {p.name: {'bytes': p.stat().st_size,
                        'sha256': hashlib.sha256(p.read_bytes()).hexdigest()}
                         for p in (stdout, stderr)}, 'all50_commercial': False}
        save('qualified.json', proof)
        print(json.dumps(proof, sort_keys=True))
    finally:
        # Only this newly created, synthetic fixture evidence is made readable
        # by its original checkout owner for upload; no tested paths are changed.
        for target in created:
            st = target.lstat()
            assert stat.S_ISREG(st.st_mode) and st.st_nlink == 1 and st.st_uid == 0
            os.chown(target, owner.st_uid, owner.st_gid)
        os.chown(out, owner.st_uid, owner.st_gid)


if __name__ == '__main__':
    main()
