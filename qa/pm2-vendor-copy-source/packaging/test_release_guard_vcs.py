"""Compile the actual release guard command in an owned temporary Git repository."""
import hashlib
import os
from pathlib import Path
import platform
import shlex
import shutil
import subprocess
import tempfile
import unittest


class ReleaseGuardVCSDeterminismTests(unittest.TestCase):
    def test_actual_release_command_keeps_v4_identical_with_inherited_vcs_and_new_commit(self):
        source = Path(__file__).resolve().parent.parent
        go, git = shutil.which('go'), shutil.which('git')
        self.assertIsNotNone(go, 'release packaging requires its real Go compiler')
        self.assertIsNotNone(git, 'the VCS regression requires a real temporary Git repository')
        lines = [line for line in (source/'packaging/build-release.sh').read_text().splitlines()
                 if line.startswith('(cd "$BUILD_ROOT" && ') and '"$STAGE/$NAME/bin/panel-start-guard"' in line]
        self.assertEqual(len(lines), 1)
        tokens = shlex.split(lines[0][len('(cd "$BUILD_ROOT" && '):-1])
        compiler = tokens.index('go')
        assignments = dict(token.split('=', 1) for token in tokens[:compiler])
        self.assertEqual(set(assignments), {'CGO_ENABLED', 'GOOS', 'GOARCH'})
        self.assertEqual(tokens[compiler+1], 'build')
        architecture = {'aarch64':'arm64', 'arm64':'arm64', 'x86_64':'amd64', 'AMD64':'amd64'}.get(platform.machine())
        self.assertIsNotNone(architecture, 'the release supports actual AMD64 and ARM64 compiler hosts')
        with tempfile.TemporaryDirectory(prefix='panel-owned-guard-vcs-') as tmp:
            root = Path(tmp)/'source'; root.mkdir()
            for name in ('go.mod', 'go.sum'):
                shutil.copyfile(source/name, root/name)
            for name in ('cmd/startguard', 'internal/upgradeguard'):
                shutil.copytree(source/name, root/name)
            empty_template = Path(tmp)/'empty-git-template'; empty_template.mkdir()
            env = {k:v for k,v in os.environ.items() if not k.startswith('GIT_')}
            env.update(GOFLAGS='-buildvcs=true -p=1', GOTOOLCHAIN='local',
                       GIT_CONFIG_GLOBAL=os.devnull, GIT_CONFIG_SYSTEM=os.devnull,
                       GIT_CONFIG_NOSYSTEM='1', GIT_TEMPLATE_DIR=str(empty_template))
            # This is a fixture-local identity; no user/global Git settings,
            # signing configuration, credentials, or application data are read.
            def run(args):
                return subprocess.check_output(args, cwd=root, env=env, stderr=subprocess.STDOUT, timeout=120)
            run([git, 'init', '-q'])
            run([git, 'add', '--', 'go.mod', 'go.sum', 'cmd', 'internal'])
            def commit(message):
                run([git, '-c', 'user.name=Owned Guard Fixture', '-c', 'user.email=fixture@invalid.local',
                     '-c', 'commit.gpgsign=false', 'commit', '-q', '-m', message])
            commit('owned original compiler inputs')
            def build(label, original_vcs=False):
                stage = Path(tmp)/label; (stage/'fixture/bin').mkdir(parents=True)
                values = {'$ARCH':architecture, '$STAGE':str(stage), '$NAME':'fixture'}
                args = list(tokens[compiler:]); args[0] = go
                args = [arg.replace('$ARCH',architecture).replace('$STAGE',str(stage)).replace('$NAME','fixture') for arg in args]
                if original_vcs:
                    args = [arg for arg in args if arg != '-buildvcs=false']
                build_env = dict(env, **{k:values.get(v,v) for k,v in assignments.items()})
                subprocess.check_output(args, cwd=root, env=build_env, stderr=subprocess.STDOUT, timeout=120)
                target = stage/'fixture/bin/panel-start-guard'
                metadata = run([go, 'version', '-m', str(target)])
                return hashlib.sha256(target.read_bytes()).hexdigest(), metadata
            first, first_metadata = build('original-commit')
            (root/'unrelated.txt').write_text('An unrelated tracked repository change.\n')
            run([git, 'add', '--', 'unrelated.txt']); commit('owned unrelated change')
            second, second_metadata = build('new-commit')
            stamped, stamped_metadata = build('original-stamped-control', original_vcs=True)
            self.assertEqual(first, second, 'unrelated Git history cannot replace immutable v4 bytes')
            self.assertNotIn(b'vcs=', first_metadata)
            self.assertNotIn(b'vcs=', second_metadata)
            self.assertIn(b'vcs=git', stamped_metadata, 'the real old-command control must reproduce VCS stamping')
            self.assertNotEqual(stamped, second)


if __name__ == '__main__':
    unittest.main()
