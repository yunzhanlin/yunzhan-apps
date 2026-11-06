"""Run the real Root/Linux upgrade fixtures and retain every original output."""
import ast
import hashlib
import json
import os
import pathlib
import platform
import re
import subprocess
import sys


def main():
    if os.geteuid() != 0 or platform.system() != 'Linux' or platform.machine() not in ('x86_64', 'aarch64'):
        raise ValueError('actual native Linux Root execution is required')
    repository = pathlib.Path(__file__).resolve().parents[1]
    spec = json.loads((repository/'tools/files-sync-offline-recovery-execution.json').read_bytes())
    source = repository/'candidate/panel-integration-load-balance'
    index = json.loads((source/'source-sha256.json').read_bytes())
    assert index['release']['frozen_inputs_sha256'] == spec['source_inputs_sha256']
    assert len(index['files']) == spec['source_sdk_files'] == 2467 and not index.get('test_overrides')
    for name, digest in spec['source_files'].items():
        assert index['files'][name] == digest == hashlib.sha256((source/name).read_bytes()).hexdigest()
    output = pathlib.Path(sys.argv[1])
    output.mkdir(mode=0o700)
    results = {}
    for name, group in spec['python_groups'].items():
        module = ast.parse((source/'packaging'/name).read_bytes())
        methods = sorted(c.name+'.'+f.name for c in module.body if isinstance(c, ast.ClassDef) and c.name in group['classes']
                         for f in c.body if isinstance(f, ast.FunctionDef) and f.name.startswith('test_'))
        assert methods == group['methods'] and len(methods) == group['tests']
        arguments = [sys.executable, '-I', '-B', str(source/'packaging'/name), '-v', *group['classes']]
        stem = output/name.removesuffix('.py')
        with pathlib.Path(str(stem)+'.intent.json').open('x') as target:
            json.dump({'args':arguments, 'maximum_submissions':1, 'fixture_child_umask':0o022}, target)
        with pathlib.Path(str(stem)+'.stdout').open('xb') as stdout, pathlib.Path(str(stem)+'.stderr').open('xb') as stderr:
            child = subprocess.run(arguments, stdin=subprocess.DEVNULL, stdout=stdout, stderr=stderr, umask=0o022, timeout=600)
        raw = pathlib.Path(str(stem)+'.stderr').read_bytes()
        assert len(raw) <= 8 << 20
        text = raw.decode('utf8')
        actual = re.findall(r'^test_[a-zA-Z0-9_]+ \(__main__\.([a-zA-Z0-9_]+\.test_[a-zA-Z0-9_]+)\) \.\.\. ok$', text, re.M)
        summaries = re.findall(r'^Ran ([0-9]+) tests? in ', text, re.M)
        complete = len(summaries) == 1 and int(summaries[0]) == len(methods) and text.rstrip().endswith('OK')
        complete = complete and len(actual) == len(set(actual)) == len(methods) and sorted(actual) == methods
        complete = complete and not re.search(r'(?:\.\.\. skipped\b|\bskipped=\d|^SKIP:|expected failure|unexpected success)', text, re.I|re.M)
        results[name] = {'exit':child.returncode, 'methods':sorted(actual), 'tests':len(actual), 'complete':complete,
                         'stdout_sha256':hashlib.sha256(pathlib.Path(str(stem)+'.stdout').read_bytes()).hexdigest(),
                         'stderr_sha256':hashlib.sha256(raw).hexdigest()}
    proof = {'format':1, 'architecture':platform.machine(), 'uid':os.geteuid(), 'platform':'Linux',
             'source_inputs_sha256':spec['source_inputs_sha256'], 'groups':results,
             'actual_tests':sum(r['tests'] for r in results.values()), 'installed_acceptance':False}
    proof['ok'] = proof['actual_tests'] == 91 and all(r['exit'] == 0 and r['complete'] for r in results.values())
    with (output/'original-python-proof.json').open('x') as target:
        json.dump(proof, target, indent=2)
    print(json.dumps(proof), flush=True)
    return 0 if proof['ok'] else 1


if __name__ == '__main__':
    os.umask(0o077)
    sys.exit(main())
