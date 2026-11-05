#!/usr/bin/env python3
"""Record the real zero-capability CI identity, then run the native SFTP suite.

The fixture still restricts itself to this repository's ephemeral Linux runner,
explicit opt-in and the measured OpenSSH SFTP executable. This is source
regression evidence, not installed app, external server or browser acceptance.
"""
import hashlib
import json
import os
from pathlib import Path
import platform
import stat
import sys


def main():
    if len(sys.argv) != 3 or platform.system() != "Linux":
        raise ValueError("expected actual Linux native test executable and new identity receipt")
    if os.getuid() <= 0 or os.getuid() != os.geteuid() or os.getgroups():
        raise ValueError("unprivileged native SFTP requires a real non-root user and no supplementary groups")
    status = Path("/proc/self/status").read_text()
    fields = dict(line.split(":", 1) for line in status.splitlines() if ":" in line)
    for key in ("CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb"):
        if fields[key].strip() != "0000000000000000":
            raise ValueError("native SFTP must run with every capability set empty")
    if fields["NoNewPrivs"].strip() != "1":
        raise ValueError("native SFTP requires NoNewPrivileges")
    if (os.environ.get("GITHUB_ACTIONS") != "true"
            or os.environ.get("GITHUB_REPOSITORY") != "yunzhanlin/yunzhan-apps"
            or os.environ.get("PANEL_REMOTE_SYNC_CI_SOURCE") != "files-sync-root-independent-backup-v1"
            or os.environ.get("PANEL_REMOTE_SYNC_NATIVE_SFTP_QA") != "1"):
        raise ValueError("explicit owned ephemeral repository fixture is required")
    native = Path("/usr/lib/openssh/sftp-server")
    native_digest = hashlib.sha256(native.read_bytes()).hexdigest()
    binary = Path(sys.argv[1])
    info = binary.lstat()
    if not binary.is_absolute() or not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or not os.access(binary, os.X_OK):
        raise ValueError("expected the actual compiled native test executable")
    data = binary.read_bytes()
    expected_machine = {"x86_64": 62, "aarch64": 183}[platform.machine()]
    if data[:4] != b"\x7fELF" or int.from_bytes(data[18:20], "little") != expected_machine:
        raise ValueError("test executable does not match the actual runner architecture")
    receipt = {
        "system": platform.system(), "architecture": platform.machine(),
        "uid": os.getuid(), "euid": os.geteuid(), "gid": os.getgid(),
        "groups": os.getgroups(), "status": status,
        "native_sftp_sha256": native_digest,
        "executor_test_binary_sha256": hashlib.sha256(data).hexdigest(),
        "installed_or_store_acceptance": False,
    }
    os.umask(0o077)
    with Path(sys.argv[2]).open("x") as f:
        json.dump(receipt, f, indent=2)
        f.write("\n")
        f.flush()
        os.fsync(f.fileno())
    os.environ["PANEL_REMOTE_SYNC_NATIVE_SFTP_SHA256"] = native_digest
    os.execv(binary, [str(binary), "-test.v", "-test.run=^TestRemote(Sync|IndependentCopy)", "-test.count=1", "-test.timeout=20m"])


if __name__ == "__main__":
    main()
