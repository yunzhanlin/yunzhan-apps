#!/usr/bin/env python3
"""Provision fixed root native directories before systemd confinement."""
import argparse
import os
import pathlib
import stat


def prepare(root, create):
    if os.geteuid() != 0:
        raise ValueError("native build cache provisioning requires root")
    root = pathlib.Path(root)
    if root.anchor != "/" or str(root) != os.path.normpath(str(root)):
        raise ValueError("target root must be an absolute normalized ordinary directory")
    for parts in (("var", "cache", "panel-analytics-html-build"), ("var", "lib", "panel-network-ids"), ("opt", "panel", "network-rule-feeds")):
        prepare_target(root, parts, create)


def prepare_target(root, parts, create):
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
            current.mkdir(mode=0o755)
            # Only directories newly created by this invocation are assigned
            # ownership/mode. Never repair, follow or recursively chown an
            # existing path selected by another administrator or program.
            os.chown(current, 0, 0)
            os.chmod(current, 0o755)
            descriptor = os.open(current.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            try:
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
            info = current.lstat()
        if missing or not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
            raise ValueError("native build cache ancestor is foreign, linked or writable; not repaired")
        if current == target and (stat.S_IMODE(info.st_mode) != 0o755 or info.st_gid != 0):
            raise ValueError("existing native build cache permissions/group differ; not repaired")


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
