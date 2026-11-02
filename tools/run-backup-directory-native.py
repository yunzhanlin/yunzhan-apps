#!/usr/bin/env python3
"""Run the exact Root backup-directory source fixtures; not normal installed acceptance."""
import hashlib
import io
import json
import os
import pathlib
import platform
import sys
import time
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
SDK = ROOT / "candidate/panel-integration-load-balance"
SPEC = json.loads((ROOT / "tools/backup-directory-native-execution.json").read_bytes())


def source_files():
    values = {name: hashlib.sha256((SDK / name).read_bytes()).hexdigest() for name in SPEC["source_files"]}
    if values != SPEC["source_files"]:
        raise ValueError("Root test inputs do not match the reviewed source cohort")
    index = json.loads((SDK / "source-sha256.json").read_bytes())
    if index["release"]["frozen_inputs_sha256"] != SPEC["source_inputs_sha256"]:
        raise ValueError("exported SDK belongs to a different programme cohort")
    if any(index["files"][name] != digest for name, digest in values.items()):
        raise ValueError("Root test input differs from exported source manifest")
    return values


class RecordedResult(unittest.TextTestResult):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.passed = []

    def addSuccess(self, test):
        super().addSuccess(test)
        self.passed.append(test.id())


def main():
    if len(sys.argv) != 1 or platform.system() != "Linux" or os.geteuid() != 0:
        raise ValueError("the original Linux Root test process is required")
    before = source_files()
    started = time.monotonic()
    suite = unittest.defaultTestLoader.discover(str(SDK / "packaging"), pattern="test_backup_directories.py")
    if suite.countTestCases() != len(SPEC["expected_test_ids"]) or len(SPEC["expected_test_ids"]) != 13:
        raise ValueError("Root test discovery is empty or differs from the reviewed thirteen methods")
    result = unittest.TextTestRunner(stream=sys.stderr, verbosity=2, resultclass=RecordedResult).run(suite)
    after = source_files()
    if before != after:
        raise ValueError("Root test inputs changed during actual execution")
    record = {
        "format": 1,
        "system": platform.system(),
        "architecture": platform.machine(),
        "uid": os.geteuid(),
        "source_inputs_sha256": SPEC["source_inputs_sha256"],
        "source_files": after,
        "tests_run": result.testsRun,
        "passed": sorted(result.passed),
        "failures": [[test.id(), reason] for test, reason in result.failures],
        "errors": [[test.id(), reason] for test, reason in result.errors],
        "skipped": [[test.id(), reason] for test, reason in result.skipped],
        "expected_failures": [[test.id(), reason] for test, reason in result.expectedFailures],
        "unexpected_successes": [test.id() for test in result.unexpectedSuccesses],
        "elapsed_seconds": time.monotonic() - started,
    }
    print(json.dumps(record, sort_keys=True))
    if not result.wasSuccessful() or result.skipped or sorted(result.passed) != SPEC["expected_test_ids"]:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
