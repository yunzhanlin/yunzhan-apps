"""Actual installer function fixtures; not native service or traffic acceptance."""
import os
import pathlib
import subprocess
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

if __name__ == '__main__':
    unittest.main()
