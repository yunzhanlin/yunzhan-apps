import os
import pathlib
import subprocess
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts/upgrade-running-development.sh"


class DevelopmentUpgradeSafetyTests(unittest.TestCase):
    def test_both_queues_and_retained_stages_are_checked_before_writes(self):
        source = SCRIPT.read_text()
        self.assertIn("for queue in jobs runtime_jobs; do", source)
        self.assertIn("for pending in /opt/panel/web.new /opt/panel/bin/panel.new /opt/panel/bin/panel-executor.new; do", source)
        self.assertLess(source.index("check_queues\n"), source.index('BACKUP='))
        self.assertLess(source.index("SERVICES_STOPPED=1\n"), source.index("systemctl stop panel panel-executor\ncheck_queues\nsqlite3"))
        self.assertLess(source.index("systemctl stop panel panel-executor\ncheck_queues\nsqlite3"), source.index("CHANGED=1\n"))
        self.assertIn('cp -a "$BACKUP/DEVELOPMENT_RELEASE" /opt/panel/DEVELOPMENT_RELEASE', source)
        self.assertNotIn('rm -rf', source)

    def test_actual_queue_function_refuses_active_or_unverifiable_runtime_before_mutation(self):
        source = SCRIPT.read_text()
        function = source[source.index("check_queues() {"):source.index("\ncheck_queues\n")]
        # Run the real shell function with bounded deterministic SQL output.
        # This is a guard fixture, not a live production job or upgrade proof.
        with tempfile.TemporaryDirectory(prefix="panel-development-queues-") as temporary:
            root = pathlib.Path(temporary)
            sqlite = root / "sqlite3"
            sqlite.write_text('#!/bin/bash\ncase "$2" in *runtime_jobs*) printf "%s\\n" "$QA_RUNTIME_COUNT";; *) printf "%s\\n" "$QA_JOB_COUNT";; esac\n')
            sqlite.chmod(0o700)
            for jobs, runtimes, accepted in (("0", "0", True), ("1", "0", False), ("0", "1", False), ("0", "unknown", False), ("0", "", False)):
                with self.subTest(jobs=jobs, runtimes=runtimes):
                    env = dict(os.environ, PATH=str(root)+os.pathsep+os.environ["PATH"], QA_JOB_COUNT=jobs, QA_RUNTIME_COUNT=runtimes)
                    result = subprocess.run(["/bin/bash", "-c", "set -euo pipefail\n"+function+"\ncheck_queues\nprintf accepted"], env=env, capture_output=True, text=True)
                    self.assertEqual(result.returncode == 0, accepted)
                    self.assertEqual(result.stdout == "accepted", accepted)

    def test_actual_pre_swap_failure_trap_restarts_original_services_without_touching_data(self):
        source = SCRIPT.read_text()
        function = source[source.index("rollback() {"):source.index("\ntrap rollback EXIT")]
        with tempfile.TemporaryDirectory(prefix="panel-development-rollback-") as temporary:
            root = pathlib.Path(temporary)
            log = root / "commands"
            for name in ("systemctl", "cp", "mv", "rm", "install", "sqlite3"):
                command = root / name
                command.write_text('#!/bin/bash\nprintf "%s\\n" "'+name+' $*" >> "$QA_COMMAND_LOG"\n')
                command.chmod(0o700)
            env = dict(os.environ, PATH=str(root)+os.pathsep+os.environ["PATH"], QA_COMMAND_LOG=str(log))
            result = subprocess.run(["/bin/bash", "-c", "set -euo pipefail\nCHANGED=0\nSERVICES_STOPPED=1\n"+function+"\ntrap rollback EXIT\nexit 17"], env=env, capture_output=True, text=True)
            self.assertEqual(result.returncode, 17)
            self.assertEqual(log.read_text().splitlines(), ["systemctl restart panel-executor panel"])
            self.assertIn("before program changes", result.stderr)

    def test_fixture_and_actual_migration_remain_independent_evidence(self):
        builder = (ROOT / "packaging/build-release.sh").read_text()
        self.assertIn("python3 -m unittest discover -s packaging -p 'test_*.py'", builder)
        self.assertIn("systemctl stop panel panel-executor\ncheck_queues\nsqlite3", SCRIPT.read_text())
