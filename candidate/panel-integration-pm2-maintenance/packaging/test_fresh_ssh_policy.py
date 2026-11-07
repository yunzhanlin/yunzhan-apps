"""Exercise effective-port, original ban lifetime and preconfigured first-start contracts.
Native distro packages, SSH and nft enforcement remain separate hardware gates.
"""
import importlib.util
import errno
import os
import pathlib
import hashlib
import runpy
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

PATH = pathlib.Path(__file__).with_name('fresh-ssh-policy.py')
SPEC = importlib.util.spec_from_file_location('fresh_ssh_policy', PATH)
POLICY = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(POLICY)
TIMED = '192.0.2.2 \t2099-01-01 00:00:00 + 3600 = 2099-01-01 01:00:00'
V6_TIMED = '2001:db8::2 \t2099-01-01 00:00:00 + 3600 = 2099-01-01 01:00:00'


class PolicyTest(unittest.TestCase):
    def test_actual_assembled_installer_contains_and_hashes_its_helper(self):
        source_root = PATH.parent.parent
        builder = (PATH.parent / 'build-release.sh').read_text()
        copy = next(line for line in builder.splitlines()
                    if line.startswith('cp "$BUILD_ROOT/packaging/install.sh"'))
        checksum = next(line.strip() for line in builder.splitlines()
                        if line.strip().startswith('{ find bin web systemd config '))
        marker = "<<'PY_CHECK_INSTALLER_HELPERS'"
        body = builder[builder.index('\n', builder.index(marker)) + 1:]
        checker = body.split('\nPY_CHECK_INSTALLER_HELPERS', 1)[0]
        with tempfile.TemporaryDirectory() as directory:
            release = pathlib.Path(directory) / 'release'
            release.mkdir()
            for name in ('bin', 'web', 'systemd', 'config'):
                (release / name).mkdir()
            for name in ('RELEASE', 'SOURCE_INPUTS.json', 'BUILD_CHECKS.txt'):
                (release / name).write_bytes(b'bounded packaging fixture\n')
            (release / 'RELEASE').write_text('PANEL_FORMAT=1\nPANEL_VERSION=0.1.0-candidate\nPANEL_OS=linux\nPANEL_ARCH=amd64\n')
            env = dict(os.environ, BUILD_ROOT=str(source_root), STAGE=directory, NAME='release')
            copied = subprocess.run(['bash', '-eu', '-c', copy], env=env, capture_output=True, text=True)
            self.assertEqual(copied.returncode, 0, copied.stderr)
            helper = release / 'fresh-ssh-policy.py'
            self.assertEqual(helper.read_bytes(), PATH.read_bytes())
            check = subprocess.run([sys.executable, '-I', '-B', '-c', checker, str(release)], capture_output=True, text=True)
            self.assertEqual(check.returncode, 0, check.stderr)
            self.assertIn('packaged installer helpers verified:', check.stdout)
            assembled = runpy.run_path(str(helper))
            self.assertEqual(assembled['ssh_ports']('port 2222\nport 22\n'), '22,2222')
            sums = subprocess.run(['bash', '-eu', '-c', checksum], cwd=release, capture_output=True, text=True)
            self.assertEqual(sums.returncode, 0, sums.stderr)
            records = dict((line.split(None, 1)[1], line.split(None, 1)[0])
                           for line in (release / 'SHA256SUMS').read_text().splitlines())
            self.assertEqual(records['fresh-ssh-policy.py'], hashlib.sha256(PATH.read_bytes()).hexdigest())
            normalized = subprocess.run([sys.executable, str(release / 'release-file-modes.py'), 'normalize', str(release)],
                                        capture_output=True, text=True)
            self.assertEqual(normalized.returncode, 0, normalized.stderr)
            # Run the real second copy and metadata commands, not just the
            # builder's first copy. The installed tree must pass the same
            # checksum/mode verifier before release publication can proceed.
            installer = (release / 'install.sh').read_text()
            install_copy = next(line for line in installer.splitlines()
                                if line.startswith('cp -a "$HERE/bin"'))
            metadata_start = installer.index('for metadata in SOURCE_INPUTS.json BUILD_CHECKS.txt; do')
            metadata_end = installer.index('\ndone', metadata_start) + len('\ndone')
            installed = pathlib.Path(directory) / 'installed.tmp'
            install_umask = next(line for line in installer.splitlines() if line.startswith('umask '))
            install_mkdir = next(line for line in installer.splitlines() if line == 'mkdir -p "$RELEASE_DIR.tmp"')
            install_env = dict(os.environ, HERE=str(release), RELEASE_DIR=str(pathlib.Path(directory) / 'installed'))
            copied = subprocess.run(['bash', '-eu', '-c', install_umask + '\n' + install_mkdir + '\n' + install_copy + '\n' + installer[metadata_start:metadata_end]],
                                    env=install_env, capture_output=True, text=True)
            self.assertEqual(copied.returncode, 0, copied.stderr)
            self.assertEqual((installed / 'fresh-ssh-policy.py').read_bytes(), PATH.read_bytes())
            verified = subprocess.run(['bash', str(installed / 'verify-release.sh'), str(installed)],
                                      capture_output=True, text=True)
            self.assertEqual(verified.returncode, 0, verified.stderr)
            self.assertIn('release checksums verified', verified.stdout)
            # The package can contain the helper while the install copy omits
            # it. This exact original native failure must now fail pre-sign.
            broken_copy = install_copy.replace('"$HERE/fresh-ssh-policy.py" ', '')
            self.assertNotEqual(broken_copy, install_copy)
            (release / 'install.sh').write_text(installer.replace(install_copy, broken_copy))
            missing_stage = subprocess.run([sys.executable, '-I', '-B', '-c', checker, str(release)],
                                           capture_output=True, text=True)
            self.assertNotEqual(missing_stage.returncode, 0)
            self.assertIn('installer does not stage required helper: fresh-ssh-policy.py', missing_stage.stderr)
            (release / 'install.sh').write_text(installer)
            (installed / 'fresh-ssh-policy.py').unlink()
            missing_installed = subprocess.run(['bash', str(installed / 'verify-release.sh'), str(installed)],
                                              capture_output=True, text=True)
            self.assertNotEqual(missing_installed.returncode, 0)
            helper.unlink()
            missing = subprocess.run([sys.executable, '-I', '-B', '-c', checker, str(release)], capture_output=True, text=True)
            self.assertNotEqual(missing.returncode, 0)
            self.assertIn('fresh-ssh-policy.py', missing.stderr)
            digest = subprocess.run(['shasum', '-a', '256', '-c', 'SHA256SUMS'], cwd=release, capture_output=True, text=True)
            self.assertNotEqual(digest.returncode, 0)

    @unittest.skipUnless(os.name == 'posix', 'actual POSIX terminal required')
    def test_interactive_success_footer_uses_a_validated_numeric_listen_port(self):
        import pty
        import select
        source = PATH.with_name('install.sh').read_text()
        footer = source[source.index('echo "panel $PANEL_VERSION installed successfully"'):]
        for ports, first in (('22', '22'), ('2222,65535', '2222')):
            master, slave = pty.openpty()
            try:
                env = dict(os.environ, FRESH='1', PANEL_VERSION='0.1.0-candidate', FRESH_SSH_PORTS=ports)
                code = 'unset SSH_LISTEN_PORT; python3(){ return 0; };\n' + footer
                process = subprocess.Popen(['bash', '-eu', '-c', code], env=env,
                                           stdin=subprocess.DEVNULL, stdout=slave, stderr=slave)
                os.close(slave)
                slave = None
                chunks = []
                while True:
                    ready, _, _ = select.select([master], [], [], 5)
                    self.assertTrue(ready, 'interactive footer exceeded its deadline')
                    try:
                        block = os.read(master, 4096)
                    except OSError as error:
                        if error.errno == errno.EIO:
                            break
                        raise
                    if not block:
                        break
                    chunks.append(block)
                    self.assertLess(sum(map(len, chunks)), 16384)
                output = b''.join(chunks).decode()
                self.assertEqual(process.wait(timeout=5), 0, output)
                self.assertIn('SSH tunnel command: ssh -p ' + first + ' -N -L ', output)
                self.assertNotIn('unbound variable', output)
            finally:
                if 'process' in locals() and process.poll() is None:
                    process.kill()
                    process.wait(timeout=5)
                os.close(master)
                if slave is not None:
                    os.close(slave)

    def test_all_effective_ports_not_just_the_first(self):
        self.assertEqual(POLICY.ssh_ports('port 2222\naddressfamily any\nport 22\nport 2222\n'), '22,2222')
        self.assertEqual(POLICY.ssh_ports('port 65535\nport 1\n'), '1,65535')
        for text in ('', 'listenaddress 0.0.0.0\n', 'port ssh\n', 'port 0\n',
                     'port 65536\n', 'port 022\n', 'port 22 extra\n', 'port -1\n'):
            with self.subTest(text=text), self.assertRaises(ValueError):
                POLICY.ssh_ports(text)
        for ports in ('22,22', '2222,22', '22;touch /tmp/bad', ',22', '22,', 22):
            with self.subTest(ports=ports), self.assertRaises(ValueError):
                POLICY.rendered(ports)

    def test_excessive_or_nontext_ports_refused(self):
        for ports in ([], ['22'] * 33, [22], ('22',), ['22\x00']):
            with self.subTest(ports=ports), self.assertRaises(ValueError):
                POLICY.canonical_ports(ports)

    def test_original_active_bans_must_retain_creation_and_expiry(self):
        before = POLICY.bans(TIMED + '\n' + V6_TIMED + '\n')
        self.assertEqual(POLICY.preserved_bans(before, before, 0), 0)
        with self.assertRaises(ValueError):
            POLICY.preserved_bans(before, {}, 0)
        changed = dict(before)
        changed['192.0.2.2'] = TIMED.replace('01:00:00', '02:00:00')
        with self.assertRaises(ValueError):
            POLICY.preserved_bans(before, changed, 0)
        # A new legitimate ban is retained, never unbanned as fixture cleanup.
        extra = dict(before, **{'192.0.2.3': TIMED.replace('192.0.2.2', '192.0.2.3')})
        self.assertEqual(POLICY.preserved_bans(before, extra, 0), 0)

    def test_actual_empty_ban_list_and_blank_separator_output(self):
        for text in ('', '\n', ' \t\n\n'):
            with self.subTest(text=text):
                self.assertEqual(POLICY.bans(text), {})
        self.assertEqual(POLICY.bans('\n' + TIMED + '\n\n'), POLICY.bans(TIMED))

    def test_only_proved_natural_expiry_may_disappear(self):
        expired = TIMED.replace('2099-', '2000-')
        self.assertEqual(POLICY.preserved_bans(POLICY.bans(expired), {}, 1700000000), 1)
        for line in ('192.0.2.2 \tpermanent', TIMED.replace('+ 3600', '+ -1')):
            with self.assertRaises(ValueError):
                POLICY.preserved_bans(POLICY.bans(line), {}, 9999999999)
        for text in (TIMED + '\n' + TIMED, 'not-an-IP data', '192.0.2.2', '2001:0db8::2 data'):
            with self.subTest(text=text), self.assertRaises((ValueError, TypeError)):
                POLICY.bans(text)

    def test_configure_never_overwrites_an_existing_file_or_link(self):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            original = root / 'original'
            original.write_bytes(b'foreign configuration\n')
            target = root / 'panel-sshd.local'
            for link in (False, True):
                if link:
                    target.symlink_to(original)
                else:
                    target.write_bytes(b'keep me\n')
                # Only test the real exclusive-open behavior here. The actual
                # /etc parent ownership check has an independent negative test.
                with mock.patch.object(POLICY, 'package_absent'), mock.patch.object(POLICY, 'CONFIG', target), mock.patch.object(POLICY, 'parents'), mock.patch.object(POLICY, 'run', return_value='port 22\n'):
                    with self.assertRaises(FileExistsError):
                        POLICY.configure()
                self.assertEqual(original.read_bytes(), b'foreign configuration\n')
                if not link:
                    self.assertEqual(target.read_bytes(), b'keep me\n')
                target.unlink()

    def test_parent_symlink_foreign_owner_and_writable_mode_refused(self):
        for mode, uid in ((0o120755, 0), (0o040777, 0), (0o040755, 501)):
            node = mock.Mock()
            node.lstat.return_value = mock.Mock(st_mode=mode, st_uid=uid)
            path = mock.Mock(parents=[node])
            with self.subTest(mode=mode, uid=uid), self.assertRaises(ValueError):
                POLICY.parents(path)

    def test_fixed_client_exec_has_no_shell_or_custom_socket(self):
        response = subprocess.CompletedProcess([], 0, stdout=b'OK\n', stderr=b'')
        with mock.patch.object(POLICY.subprocess, 'run', return_value=response) as call:
            self.assertEqual(POLICY.client('get', 'sshd', 'actions'), 'OK\n')
        args, options = call.call_args
        self.assertEqual(args, (['/usr/bin/fail2ban-client', 'get', 'sshd', 'actions'],))
        self.assertNotIn('shell', options)
        self.assertEqual(options['stdin'], subprocess.DEVNULL)
        self.assertEqual(options['timeout'], 8)
        self.assertEqual(options['env']['PATH'], '/usr/sbin:/usr/bin:/sbin:/bin')
        self.assertNotIn('PYTHONPATH', options['env'])

    def activation(self, initial='nftables-multiport', native='22,2222', refuse=False, lose_ban=False, replace_pid=False):
        calls = []
        state = {'name': initial, 'port': native, 'reloads': 0, 'ban_reads': 0}
        lifetimes = {}
        def client(*args):
            calls.append(args)
            if args == ('-t',):
                return 'OK\n'
            if args == ('get', 'sshd', 'actions'):
                if not state['name']:
                    return 'No actions for jail sshd\n'
                return 'The jail sshd has the following actions:\n' + state['name'] + '\n'
            if args == ('get', 'sshd', 'banip', '--with-time'):
                state['ban_reads'] += 1
                return '\n' if lose_ban and state['ban_reads'] > 1 else TIMED + '\n' + V6_TIMED + '\n'
            if len(args) == 5 and args[:3] == ('get', 'sshd', 'action') and args[-1] == 'port':
                return ('ssh' if refuse else state['port']) + '\n'
            if args[:2] == ('get', 'sshd') and len(args) == 3 and args[2] in POLICY.FILTER_FIELDS:
                return 'original-' + args[2]
            raise AssertionError('unexpected command, including any live migration: ' + repr(args))
        def lifetime(unit):
            lifetimes[unit] = lifetimes.get(unit, 0) + 1
            return {'unit': unit, 'pid': 333 if replace_pid and lifetimes[unit] > 1 else 222, 'start_ticks': '100'}
        with mock.patch.object(POLICY, 'run', return_value='port 2222\nport 22\n'), mock.patch.object(POLICY, 'config_bytes', return_value=POLICY.rendered('22,2222')), mock.patch.object(POLICY, 'identities', return_value={'original': 'unchanged'}), mock.patch.object(POLICY, 'lifetime', side_effect=lifetime), mock.patch.object(POLICY, 'client', side_effect=client):
            try:
                return POLICY.activate('22,2222'), calls, state
            finally:
                self.assertFalse(any(x[0] in ('reload', 'restart', 'set', 'unban') for x in calls))

    def test_stock_or_empty_actions_are_refused_without_live_migration(self):
        for action in ('nftables', 'iptables-multiport', ''):
            with self.subTest(action=action), self.assertRaises(ValueError):
                self.activation(action, 'ssh')

    def test_preconfigured_first_start_needs_no_reload(self):
        result, calls, state = self.activation()
        self.assertTrue(result['ok'])
        self.assertFalse(result['targeted_reload'])
        self.assertEqual(result['runtime_reload_restart_or_unban_calls'], 0)
        self.assertEqual(result['original_active_bans'], 2)
        self.assertEqual(result['fail2ban_start_ticks'], 100)
        self.assertGreater(result['clock_ticks_per_second'], 0)
        self.assertEqual(state['reloads'], 0)

    def test_refused_readback_lost_ban_or_replaced_daemon_never_retried(self):
        for flags in ({'refuse': True}, {'lose_ban': True}, {'replace_pid': True}):
            with self.subTest(flags=flags), self.assertRaises(ValueError):
                self.activation(**flags)

    def test_preseed_rejects_preexisting_client_unit_or_state_before_reading_sshd(self):
        for name in ('/usr/bin/fail2ban-client', '/run/fail2ban', '/var/lib/fail2ban',
                     '/etc/systemd/system/fail2ban.service', '/run/systemd/system/fail2ban.service'):
            with self.subTest(path=name), mock.patch.object(POLICY.os.path, 'lexists', side_effect=lambda p: p == name), mock.patch.object(POLICY, 'run') as run:
                with self.assertRaises(ValueError):
                    POLICY.configure()
                run.assert_not_called()

    def test_actual_install_orders_prerequisites_and_preseed_before_first_fail2ban_start(self):
        installer = PATH.with_name('install.sh').read_text()
        start = installer.index('    FRESH_PREPARE_PACKAGES=()')
        end = installer.index('\n  fi', start)
        block = installer[start:end]
        with tempfile.TemporaryDirectory() as directory:
            events = pathlib.Path(directory) / 'events'
            ready = pathlib.Path(directory) / 'ready'
            env = dict(os.environ, EVENTS=str(events), READY=str(ready))
            stubs = r"""
apt-get(){
  if [[ "${@: -1}" == fail2ban ]];then
    [[ -f "$READY" ]] || return 91
    printf 'fail2ban-first-start\n' >> "$EVENTS"
  else
    [[ "$*" != *fail2ban* ]] || return 92
    printf 'prerequisites\n' >> "$EVENTS"
  fi
}
mkdir(){
  [[ "$1" == -m && "$2" == 0755 ]] || return 93
  [[ "$3" == /etc/fail2ban || "$3" == /etc/fail2ban/jail.d ]] || return 94
  printf 'directory:%s\n' "$3" >> "$EVENTS"
}
/usr/bin/python3(){
  [[ "$*" == '-I -B /owned-release/fresh-ssh-policy.py configure' ]] || return 95
  printf 'preseed\n' >> "$EVENTS"; : > "$READY"; printf '22,2222\n'
}
REQUIRED_PACKAGES=(nginx fail2ban openssh-server python3-systemd)
HERE=/owned-release
"""
            options = next(line.strip() for line in installer.splitlines() if line.strip().startswith('APT_ACQUIRE_OPTIONS=('))
            result = subprocess.run(['bash', '-eu', '-c', stubs + options + '\n' + block + '\n[[ "$FRESH_SSH_PORTS" == 22,2222 ]]'],
                                    env=env, capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(events.read_text().splitlines(), ['prerequisites', 'directory:/etc/fail2ban',
                             'directory:/etc/fail2ban/jail.d', 'preseed', 'fail2ban-first-start'])

    def test_existing_fail2ban_is_rejected_before_first_install_apt(self):
        source = PATH.with_name('install.sh').read_text()
        start = source.index('  for existing in ')
        end = source.index('\nfi', start)
        block = source[start:end]
        self.assertIn('/etc/fail2ban', block)
        self.assertIn('/usr/bin/fail2ban-client', block)
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            (root / 'etc' / 'fail2ban').mkdir(parents=True)
            env = dict(os.environ, TARGET_ROOT=directory)
            result = subprocess.run(['bash', '-eu', '-c', 'prefix(){ printf "%s%s" "$TARGET_ROOT" "$1"; };\n' + block], env=env, capture_output=True, text=True)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn('/etc/fail2ban', result.stderr)
            self.assertEqual(list((root / 'etc' / 'fail2ban').iterdir()), [])

    def test_existing_upgrade_does_not_invoke_fresh_configure_or_activation(self):
        source = PATH.with_name('install.sh').read_text()
        block = source[source.index('if ((FRESH));then\n  systemctl enable --now fail2ban'):]
        block = block[:block.index('\nfor _ in')]
        stubs = 'python3(){ echo forbidden-helper >&2; return 95; }; systemctl(){ echo forbidden-service >&2; return 96; };\n'
        result = subprocess.run(['bash', '-eu', '-c', stubs + 'FRESH=0;FAILED=0;\n' + block], capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout + result.stderr, '')


if __name__ == '__main__':
    unittest.main()
