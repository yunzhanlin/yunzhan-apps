"""Bound the root socket peer to its kernel process lifetime, not PID alone.

Only the already verified numeric Fail2ban PID selects a fixed /proc stat.
No caller path, command, process signaling, writes or retry is available.
"""
import os
import pathlib
import re
import stat


def canonical_process_ticks(value):
    if type(value) is not str or re.fullmatch(r"[1-9][0-9]{0,19}", value) is None or int(value) > 18446744073709551615:
        raise ValueError("noncanonical process start ticks")
    return value


def parse_process_stat(raw, wanted):
    if type(wanted) is not int or not 2 <= wanted <= 1 << 22 or type(raw) is not bytes or not 1 <= len(raw) <= 4096 or raw.count(b"\n") != 1 or not raw.endswith(b"\n") or b"\x00" in raw or b"\r" in raw:
        raise ValueError("bounded process stat required")
    text = raw.decode("ascii", "strict")
    if not text.startswith(str(wanted) + " (") or ") " not in text:
        raise ValueError("process stat PID identity")
    # comm may contain spaces and parentheses. Numeric kernel fields follow
    # its LAST closing parenthesis; whitespace splitting the whole line is
    # not a valid parser for field22 (starttime).
    fields = text.rsplit(") ", 1)[1].split()
    if not 20 <= len(fields) <= 128 or fields[0] not in ("R", "S", "D", "I"):
        raise ValueError("process not in a qualified live state")
    return canonical_process_ticks(fields[19])


def process_start_ticks(wanted):
    if type(wanted) is not int or not 2 <= wanted <= 1 << 22:
        raise ValueError("fixed trusted service PID required")
    if os.readlink("/proc/self") != str(os.getpid()):
        raise ValueError("proc mount does not represent this PID namespace")
    target = pathlib.Path("/proc") / str(wanted) / "stat"
    parents = {}

    def identity(info):
        # /proc directory link counts may change as unrelated processes exit.
        # They are not identity. The one opened regular stat remains nlink1.
        return info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid

    for parent in target.parents:
        info = parent.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o7022:
            raise ValueError("untrusted process stat parent")
        parents[str(parent)] = identity(info)
    before = target.lstat()
    if not stat.S_ISREG(before.st_mode) or before.st_uid != 0 or before.st_nlink != 1 or before.st_mode & 0o7022:
        raise ValueError("untrusted process stat inode")
    descriptor = os.open(target, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    with os.fdopen(descriptor, "rb") as file:
        if identity(os.fstat(file.fileno())) != identity(before) or os.fstat(file.fileno()).st_nlink != 1:
            raise ValueError("process stat changed before open")
        raw = file.read(4097)
        if identity(os.fstat(file.fileno())) != identity(before) or os.fstat(file.fileno()).st_nlink != 1 or identity(target.lstat()) != identity(before):
            raise ValueError("process stat named identity changed")
    for name, old in parents.items():
        if identity(pathlib.Path(name).lstat()) != old:
            raise ValueError("process stat parent changed")
    return parse_process_stat(raw, wanted)
