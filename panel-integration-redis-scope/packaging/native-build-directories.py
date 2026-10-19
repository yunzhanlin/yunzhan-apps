#!/usr/bin/env python3
"""Provision fixed root native directories before systemd confinement."""
import argparse
import grp
import os
import pathlib
import stat


def prepare(root, create):
    if os.geteuid() != 0:
        raise ValueError("native build cache provisioning requires root")
    root = pathlib.Path(root)
    if root.anchor != "/" or str(root) != os.path.normpath(str(root)):
        raise ValueError("target root must be an absolute normalized ordinary directory")
    for parts, mode in (
        (("var", "cache", "panel-runtime-build"), 0o755),
        (("var", "cache", "panel-analytics-html-build"), 0o755),
        (("var", "lib", "panel-network-ids"), 0o755),
        (("opt", "panel", "network-rule-feeds"), 0o755),
        (("var", "cache", "panel-apache-body-build"), 0o755),
        (("var", "cache", "panel-apache-body"), 0o755),
        (("var", "lib", "panel-apache-body"), 0o755),
        (("var", "lib", "panel-executor", "apache-body-builds"), 0o700),
        (("var", "lib", "panel-executor", "apache-body-requests"), 0o700),
        (("var", "lib", "panel-executor", "apache-body-cancellations"), 0o700),
        (("opt", "panel", "app-modules", "apache-waf", "engines"), 0o755),
    ):
        prepare_target(root, parts, create, mode)
    prepare_build_lock(root, create)


def prepare_target(root, parts, create, mode=0o755):
    target = root.joinpath(*parts)
    current = root
    missing = False
    for component in (None, *parts):
        if component is not None:
            current /= component
        try:
            info = current.lstat()
        except FileNotFoundError:
            if current == root:
                raise ValueError("target root does not exist")
            if not create:
                missing = True
                continue
            current_mode = mode if current == target else 0o755
            current.mkdir(mode=current_mode)
            # Only directories newly created by this invocation are assigned
            # ownership/mode. Never repair, follow or recursively chown an
            # existing path selected by another administrator or program.
            os.chown(current, 0, 0)
            os.chmod(current, current_mode)
            descriptor = os.open(current.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            try:
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
            info = current.lstat()
        if missing or not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
            raise ValueError("native build cache ancestor is foreign, linked or writable; not repaired")
        if current == target and (stat.S_IMODE(info.st_mode) != mode or info.st_gid != 0):
            raise ValueError("existing native build cache permissions/group differ; not repaired")


def prepare_build_lock(root, create):
    # The narrow worker mount must exist before systemd starts. Preserve a
    # valid shared lock's inode/content; never truncate or repair an old lock.
    path = root / "var/lib/panel-executor/build.lock"
    try:
        info = path.lstat()
    except FileNotFoundError:
        if not create:
            return
        descriptor = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o600)
        try:
            os.fchown(descriptor, 0, 0)
            os.fchmod(descriptor, 0o600)
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        parent = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            os.fsync(parent)
        finally:
            os.close(parent)
        info = path.lstat()
    # The fixed executor runs User=root, Group=panel. Its legitimate existing
    # 0600 lock therefore has the named panel GID on older installations.
    # Accept only root or that fixed NSS identity; never infer authority from
    # the parent GID, caller's group, a numeric CLI option or arbitrary groups.
    groups = {0}
    try:
        groups.add(grp.getgrnam('panel').gr_gid)
    except KeyError:
        pass  # Fresh preflight may precede creation of the panel account.
    if not stat.S_ISREG(info.st_mode) or stat.S_IMODE(info.st_mode) != 0o600 or info.st_uid != 0 or info.st_gid not in groups or info.st_nlink != 1 or info.st_size > 1024:
        raise ValueError("existing native build lock is foreign, linked or invalid; not repaired")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=("check", "create"))
    parser.add_argument("--root", default="/")
    args = parser.parse_args()
    try:
        prepare(args.root, args.mode == "create")
    except (OSError, ValueError) as error:
        parser.exit(1, "native build directory refused: " + str(error) + "\n")


if __name__ == "__main__":
    main()
