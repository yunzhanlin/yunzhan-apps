"""A zero systemd-run result is not proof that the Go suite completed.

Explicit unit stops can return success while the test process died by SIGTERM.
Callers must independently verify the frozen binary and preservation snapshots.
"""
import re


def complete_native_suite(log, expected, required_markers, allowed_skips=()):
    if not expected or len(expected) > 256 or len(expected) != len(set(expected)):
        return False
    if any(not re.fullmatch(r'Test[A-Za-z0-9_]+', name) for name in expected):
        return False
    if any(token in log for token in ('code=killed', 'status=15/TERM', 'status=9/KILL', 'Finished with result: timeout')):
        return False
    started = re.findall(r'^=== RUN   (Test[A-Za-z0-9_]+)$', log, re.M)
    passed = re.findall(r'^--- PASS: (Test[A-Za-z0-9_]+) \(', log, re.M)
    skipped = re.findall(r'^--- SKIP: (Test[A-Za-z0-9_]+) \(', log, re.M)
    if len(started) != len(expected) or set(started) != set(expected):
        return False
    if len(passed) + len(skipped) != len(expected) or len(set(passed + skipped)) != len(expected):
        return False
    if set(passed + skipped) != set(expected) or not set(skipped) <= set(allowed_skips):
        return False
    return len(re.findall(r'^PASS$', log, re.M)) == 1 and all(marker in log for marker in required_markers)
