"""Execute the actual installer dispatch with exclusive isolated command stubs.

These fixtures test routing and fail-closed handoff, not native upgrade success.
Development transaction safety/Root/SQLite fixtures remain independent.
"""
import os
import pathlib
import subprocess
import tempfile
import unittest

SOURCE = pathlib.Path(__file__).with_name('install.sh').read_text()
BEGIN = SOURCE.index('DEVELOPMENT_MARKER="$(prefix /opt/panel/DEVELOPMENT_RELEASE)"')
END = SOURCE.index('# End verified development-layout dispatch;', BEGIN)
BLOCK = SOURCE[BEGIN:END]


class InstallDevelopmentDispatchTests(unittest.TestCase):
    def run_dispatch(self, *, preflight=0, services=0, target='/', development='file', marker=None, current=None, refused=0):
        with tempfile.TemporaryDirectory(prefix='panel-dispatch-fixture-') as temporary:
            root = pathlib.Path(temporary)
            (root / 'commands').mkdir()
            stub = root / 'commands/python3'
            stub.write_text('#!/bin/sh\nprintf "%s\\n" "$@" > "$CALL_LOG"\nexit "$GUARD_EXIT"\n')
            stub.chmod(0o755)
            for relative, kind in [('opt/panel/DEVELOPMENT_RELEASE', development), ('etc/panel-release', marker), ('opt/panel/current', current)]:
                if kind is None: continue
                file = root / relative; file.parent.mkdir(parents=True, exist_ok=True)
                if kind == 'file': file.write_text('original-not-rewritten\n')
                elif kind == 'directory': file.mkdir()
                elif kind == 'dangling-link': file.symlink_to('unresolved-foreign')
                else: raise AssertionError('unknown fixture kind')
            env = dict(os.environ, PATH=str(root / 'commands') + os.pathsep + os.environ['PATH'], FIXTURE_ROOT=str(root), HERE=str(root / 'verified-candidate'), CALL_LOG=str(root / 'calls'), GUARD_EXIT=str(refused), NO_SERVICES=str(services), TARGET_ROOT=target, PREFLIGHT_ONLY=str(preflight))
            before = {str(p.relative_to(root)): (p.read_bytes() if p.is_file() and not p.is_symlink() else os.readlink(p) if p.is_symlink() else None) for p in root.rglob('*') if p.name != 'calls'}
            # prefix maps only fixture paths. TARGET_ROOT remains the real-host
            # selector under test; no installer is given an alternate live root.
            script = 'prefix(){ printf "%s%s" "$FIXTURE_ROOT" "$1"; };\nMARKER="$(prefix /etc/panel-release)"\nCURRENT="$(prefix /opt/panel/current)"\n' + BLOCK + '\nprintf "ordinary-path\\n"\n'
            result = subprocess.run(['bash', '-eu', '-c', script], env=env, capture_output=True, text=True)
            calls = (root / 'calls').read_text().splitlines() if (root / 'calls').exists() else []
            after = {str(p.relative_to(root)): (p.read_bytes() if p.is_file() and not p.is_symlink() else os.readlink(p) if p.is_symlink() else None) for p in root.rglob('*') if p.name != 'calls'}
            self.assertEqual(before, after)
            return result, calls, str(root / 'verified-candidate')

    def test_existing_development_uses_original_check_or_run_and_never_falls_through(self):
        for preflight, expected in [(1, 'check'), (0, 'run')]:
            with self.subTest(preflight=preflight):
                result, calls, release = self.run_dispatch(preflight=preflight)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(calls, [release + '/development-upgrade.py', expected, release])
                self.assertNotIn('ordinary-path', result.stdout)

    def test_refusal_propagates_once_without_fresh_provision_or_retry(self):
        for code in (1, 2, 137):
            result, calls, _ = self.run_dispatch(refused=code)
            self.assertEqual(result.returncode, code); self.assertEqual(len(calls), 3)
            self.assertNotIn('ordinary-path', result.stdout)

    def test_only_absent_production_layout_can_select_development(self):
        for field in ('marker', 'current'):
            for kind in ('file', 'directory', 'dangling-link'):
                with self.subTest(field=field, kind=kind):
                    result, calls, _ = self.run_dispatch(**{field: kind})
                    self.assertEqual(result.returncode, 0, result.stderr); self.assertEqual(calls, [])
                    self.assertEqual(result.stdout, 'ordinary-path\n')

    def test_absent_development_and_no_services_or_alternate_root_preserve_normal_path(self):
        for flags in ({'development': None}, {'services': 1}, {'target': '/isolated-fixture-root'}):
            result, calls, _ = self.run_dispatch(**flags)
            self.assertEqual(result.returncode, 0, result.stderr); self.assertEqual(calls, [])
            self.assertEqual(result.stdout, 'ordinary-path\n')

    def test_foreign_development_marker_is_sent_only_to_original_strict_validator(self):
        for kind in ('directory', 'dangling-link'):
            result, calls, release = self.run_dispatch(development=kind, preflight=1, refused=1)
            self.assertEqual(result.returncode, 1)
            self.assertEqual(calls, [release + '/development-upgrade.py', 'check', release])
            self.assertNotIn('ordinary-path', result.stdout)

    def test_dispatch_order_and_original_checks_are_not_relaxed(self):
        self.assertLess(SOURCE.index('"$HERE/verify-release.sh" "$HERE"'), BEGIN)
        self.assertLess(SOURCE.index('"$HERE/bin/panel-executor" --check-apache-body-cache-upgrade'), BEGIN)
        self.assertLess(END, SOURCE.index('existing host configuration blocks first install'))
        self.assertLess(END, SOURCE.index('fresh_apt_acquire apt-get update'))
        self.assertNotIn('apt-get', BLOCK); self.assertNotIn('systemctl', BLOCK)
        self.assertNotIn('touch ', BLOCK); self.assertNotIn('mkdir ', BLOCK)
        self.assertIn('python3 "$HERE/upgrade-release.py" check "$HERE"', SOURCE)
        self.assertIn('exec python3 "$HERE/upgrade-release.py" run "$HERE"', SOURCE)


if __name__ == '__main__': unittest.main(verbosity=2)
