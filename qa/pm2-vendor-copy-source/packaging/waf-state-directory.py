#!/usr/bin/env python3
"""Check/provision the fixed WAF state directory, never repair foreign paths."""
import argparse
import grp
import os
import pathlib
import stat


def prepare(root, create):
    if os.geteuid() != 0:
        raise ValueError("WAF state provisioning requires root")
    root = pathlib.Path(root)
    if not root.is_absolute() or str(root) != os.path.normpath(str(root)):
        raise ValueError("target root must be an absolute normalized path")
    target = root / "var/lib/panel-waf"
    current = root
    missing = False
    for component in (None, "var", "lib", "panel-waf"):
        if component is not None:
            current /= component
        try:
            info = current.lstat()
        except FileNotFoundError:
            if not create:
                missing = True
                continue
            if current == root:
                raise ValueError("target root is missing")
            current.mkdir(mode=0o750 if current == target else 0o755)
            if current == target:
                os.chown(current, 0, grp.getgrnam("www-data").gr_gid)
                os.chmod(current, 0o750)  # Only our newly created directory.
            info = current.lstat()
            descriptor = os.open(current.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            try:
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
        if missing or not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
            raise ValueError("WAF path is foreign, linked or writable; not repaired")
        if current == target and (stat.S_IMODE(info.st_mode) != 0o750 or info.st_gid != grp.getgrnam("www-data").gr_gid):
            raise ValueError("existing WAF state permissions/group differ; not repaired")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=("check", "create"))
    parser.add_argument("--root", default="/")
    args = parser.parse_args()
    try:
        prepare(args.root, args.mode == "create")
    except (OSError, ValueError, KeyError) as error:
        parser.exit(1, "WAF state directory refused: " + str(error) + "\n")


if __name__ == "__main__":
    main()
