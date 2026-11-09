#!/usr/bin/env python3
"""Provision private backup roots only during fresh installation.

Check is read-only. Create never repairs existing directories or their contents.
Ordinary programme upgrades intentionally do not invoke this fresh-install tool.
"""
import argparse
import os
import pathlib
import stat


TARGETS = ("system", "mysql", "mariadb", "sites")
FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC


def open_root(root):
    # Pin every component of the explicitly selected staging boundary, too;
    # O_NOFOLLOW on only its final component would follow an earlier symlink.
    descriptor = os.open("/", FLAGS)
    try:
        for name in root.parts[1:]:
            child = os.open(name, FLAGS, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = child
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def directory(descriptor, private=False):
    info = os.fstat(descriptor)
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
        raise ValueError("backup ancestor is foreign, linked or writable; not repaired")
    if private and (stat.S_IMODE(info.st_mode) != 0o700 or info.st_gid != 0):
        raise ValueError("existing backup directory is not root:root 0700; inspect and migrate it separately; not repaired")


def walk(root, parts, create):
    parent = os.dup(root)
    try:
        for index, name in enumerate(parts):
            private = index == len(parts) - 1
            created = False
            try:
                child = os.open(name, FLAGS, dir_fd=parent)
            except FileNotFoundError:
                if not create:
                    return
                try:
                    os.mkdir(name, 0o700 if private else 0o755, dir_fd=parent)
                    created = True
                except FileExistsError:
                    # Another installer may have created it. Validate without
                    # changing its mode/group or replaying any operation.
                    pass
                child = os.open(name, FLAGS, dir_fd=parent)
            try:
                if created:
                    # These descriptors refer only to this invocation's new
                    # directories. A restrictive umask or setgid/default ACL
                    # on an ancestor must not change the intended ownership.
                    os.fchown(child, 0, 0)
                    os.fchmod(child, 0o700 if private else 0o755)
                    os.fsync(child)
                    os.fsync(parent)
                directory(child, private)
                visible = os.stat(name, dir_fd=parent, follow_symlinks=False)
                opened = os.fstat(child)
                if (visible.st_dev, visible.st_ino) != (opened.st_dev, opened.st_ino):
                    raise ValueError("backup directory identity changed; not repaired")
            except BaseException:
                os.close(child)
                raise
            os.close(parent)
            parent = child
    finally:
        os.close(parent)


def prepare(root, create=False):
    if os.geteuid() != 0:
        raise ValueError("backup directory provisioning requires root")
    root = pathlib.Path(root)
    if root.anchor != "/" or str(root) != os.path.normpath(str(root)):
        raise ValueError("target root must be an absolute normalized ordinary directory")
    descriptor = open_root(root)
    try:
        directory(descriptor)
        # Validate all existing targets before creating even the first missing
        # directory. Never chmod/chown an old empty or populated backup root.
        for name in TARGETS:
            walk(descriptor, ("var", "backups", "panel", name), False)
        if create:
            for name in TARGETS:
                walk(descriptor, ("var", "backups", "panel", name), True)
    finally:
        os.close(descriptor)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=("check", "create"))
    parser.add_argument("--root", default="/")
    args = parser.parse_args()
    try:
        prepare(args.root, args.mode == "create")
    except (OSError, ValueError) as error:
        parser.exit(1, "backup directory refused: " + str(error) + "\n")


if __name__ == "__main__":
    main()
