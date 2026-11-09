"""Actual installer function fixtures; not native service or traffic acceptance."""
import os
import pathlib
import subprocess
import sys
import tempfile
import unittest

SOURCE = pathlib.Path(__file__).with_name('install.sh').read_text()
START = SOURCE.index('enable_program_services(){')
END = SOURCE.index('\nsystemctl daemon-reload', START)
FUNCTIONS = SOURCE[START:END]
STUB = 'systemctl(){ printf "%s\\n" "$*"; };\n'

class InstallGatewayPolicyTest(unittest.TestCase):
    def run_functions(self, fresh, commands):
        env = dict(os.environ, FRESH=str(fresh))
        result = subprocess.run(['/bin/bash', '-eu', '-c', STUB+FUNCTIONS+'\n'+commands], env=env, text=True, capture_output=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        return result.stdout.splitlines()

    def test_upgrade_and_rollback_never_mutate_existing_gateway_enablement_or_master(self):
        lines = self.run_functions(0, 'enable_program_services\nrestart_release_services\nrestart_previous_services')
        self.assertEqual(len(lines), 3)
        self.assertTrue(lines[0].startswith('enable panel-terminal '))
        for line in lines:
            self.assertNotIn('nginx', line.split()[1:])
            self.assertNotIn('nginx.service', line.split()[1:])
        self.assertEqual(lines[1:], ['restart panel-terminal panel-terminal-root panel-executor panel']*2)

    def test_fresh_install_still_explicitly_provisions_gateway(self):
        lines = self.run_functions(1, 'enable_program_services\nrestart_release_services')
        self.assertEqual(len(lines), 3)
        self.assertEqual(lines[1], 'enable nginx')
        self.assertEqual(lines[2], 'restart panel-terminal panel-terminal-root panel-executor panel nginx')

    def test_actual_upgrade_and_failure_sites_call_checked_functions_without_hidden_restart(self):
        after = SOURCE[END:]
        self.assertIn('enable_program_services\n', after)
        self.assertIn('restart_release_services || FAILED=1', after)
        self.assertIn('if [[ -n "$PREVIOUS" ]];then restart_previous_services || true;', after)
        self.assertNotIn('systemctl enable nginx ', after)
        self.assertNotIn('systemctl restart panel-terminal panel-terminal-root panel-executor panel nginx', after)
        # Existing syntax validation and pending-state recovery are retained.
        self.assertIn('/usr/sbin/nginx -t || FAILED=1', after)
        self.assertIn('systemctl restart panel-nginx-recovery', after)

class FirstInstallStartupTest(unittest.TestCase):
    """Execute the installer activation flow against a real SQLite readiness fixture.

    These process stubs exercise startup ordering and failure propagation only;
    normal signed installations on native systemd hosts remain a separate gate.
    """
    def startup(self, docker=True, core_failure=False, recovery_failure=False):
        begin = SOURCE.index('\nsystemctl daemon-reload\n') + 1
        end = SOURCE.index('\nif ((FAILED));then', begin)
        flow = SOURCE[begin:end]
        nginx = '/usr/sbin/nginx -t'
        ssh = '/usr/bin/python3 -I -B "$HERE/fresh-ssh-policy.py" activate "$FRESH_SSH_PORTS"'
        self.assertEqual(flow.count(nginx), 1)
        self.assertEqual(flow.count(ssh), 1)
        flow = flow.replace(nginx, 'qa_nginx_check -t').replace(ssh, 'qa_ssh_policy_check "$FRESH_SSH_PORTS"')
        helper = '''import os,pathlib,sqlite3,sys
os.umask(0o077)
p=pathlib.Path(os.environ['QA_DATABASE'])
try:
 if sys.argv[1]=='initialise':
  with sqlite3.connect(p) as db:
   db.execute('CREATE TABLE readiness(value INTEGER NOT NULL CHECK(value=1))')
   db.execute('INSERT INTO readiness VALUES(1)')
 else:
  db=sqlite3.connect(p.as_uri()+'?mode=ro',uri=True)
  assert db.execute('SELECT value FROM readiness').fetchall()==[(1,)]
  db.close()
except (sqlite3.Error,AssertionError):
 raise SystemExit(1)
'''
        shims = r'''
systemctl(){
  printf 'systemctl %s\n' "$*" >> "$QA_EVENTS"
  case "$*" in
    'cat docker.service') test "$QA_DOCKER" = 1;;
    'restart panel-terminal panel-terminal-root panel-executor panel nginx')
      test "$QA_CORE_FAILURE" = 0 || return 1
      "$QA_PYTHON" -I -B "$QA_HELPER" initialise;;
    'restart panel-compose-recovery')
      printf 'recovery\n' >> "$QA_EVENTS"
      "$QA_PYTHON" -I -B "$QA_HELPER" verify || return 1
      test "$QA_RECOVERY_FAILURE" = 0;;
    *) return 0;;
  esac
}
curl(){ "$QA_PYTHON" -I -B "$QA_HELPER" verify; }
sleep(){ :; }
install(){ test "$*" = '-d -m 0755 /run/panel-nginx'; }
qa_nginx_check(){ test "$*" = '-t'; }
qa_ssh_policy_check(){ test "$*" = '22'; }
python3(){
  test "$*" = "$HERE/first-install.py" || return 97
  printf 'bootstrap\n' >> "$QA_EVENTS"
}
'''
        with tempfile.TemporaryDirectory(prefix='panel-first-startup-') as tmp:
            root = pathlib.Path(tmp)
            script = root / 'readiness.py'
            script.write_text(helper)
            events = root / 'events'
            env = dict(os.environ, FRESH='1', HERE=tmp, FRESH_SSH_PORTS='22',
                       QA_DATABASE=str(root / 'panel.db'), QA_EVENTS=str(events),
                       QA_PYTHON=sys.executable, QA_HELPER=str(script),
                       QA_DOCKER=str(int(docker)), QA_CORE_FAILURE=str(int(core_failure)),
                       QA_RECOVERY_FAILURE=str(int(recovery_failure)))
            result = subprocess.run(['/bin/bash', '-eu', '-c', shims + FUNCTIONS + '\n' + flow + '\nexit "$FAILED"\n'],
                                    env=env, text=True, capture_output=True)
            return result, events.read_text().splitlines()

    def test_preinstalled_docker_recovery_waits_for_ready_database(self):
        result, events = self.startup()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(events.count('recovery'), 1)
        self.assertEqual(events.count('bootstrap'), 1)

    def test_no_docker_does_not_start_compose_recovery(self):
        result, events = self.startup(docker=False)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertNotIn('recovery', events)
        self.assertEqual(events.count('bootstrap'), 1)

    def test_unready_core_never_runs_recovery_or_issues_credentials(self):
        result, events = self.startup(core_failure=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn('recovery', events)
        self.assertNotIn('bootstrap', events)

    def test_recovery_refusal_remains_an_install_failure(self):
        result, events = self.startup(recovery_failure=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(events.count('recovery'), 1)
        self.assertNotIn('bootstrap', events)


if __name__ == '__main__':
    unittest.main()
