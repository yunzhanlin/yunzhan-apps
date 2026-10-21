"""Fixed offline projection through the installed upstream base Filter.

Never instantiate FilterSystemd, a Jail, a server or an action. Never replay
the configuration stream. Only the seven fixed in-memory filter setters below
are available, in their declared order. No thread is started and no matcher
processes a log or address. Private flags remain outside getter attestation.
"""
import pathlib
import stat
import sys


def filter_projection_trusted_package():
    root = pathlib.Path("/usr/lib/python3/dist-packages/fail2ban")
    for value in (root, *root.parents):
        info = value.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o7022:
            raise ValueError("untrusted fixed upstream package parent")
    count, total = 0, 0
    for value in root.rglob("*"):
        count += 1
        info = value.lstat()
        if count > 1024 or info.st_uid != 0 or info.st_mode & 0o7022 or not (stat.S_ISDIR(info.st_mode) or stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and info.st_size <= 262144):
            raise ValueError("untrusted fixed upstream package member")
        if stat.S_ISREG(info.st_mode):
            total += info.st_size
            if total > 16 << 20:
                raise ValueError("upstream package capacity")
    return root


def project_filter_metadata(commands):
    # The child performing the official test+dump has already exited. This
    # process is isolated Python (-I -B), with only trusted system imports.
    root = filter_projection_trusted_package()
    from fail2ban.version import version
    from fail2ban.server.filter import Filter
    if version not in ("1.0.2", "1.1.0"):
        raise ValueError("unverified upstream projection version")
    for name, module in tuple(sys.modules.items()):
        if name == "fail2ban" or name.startswith("fail2ban."):
            filename = getattr(module, "__file__", None)
            if filename is None or not pathlib.Path(filename).is_relative_to(root):
                raise ValueError("projection imported nonfixed package")
    import threading
    if threading.active_count() != 1:
        raise ValueError("projection must be single threaded")

    def no_thread(*args, **kwargs):
        raise ValueError("offline filter cannot start a thread")

    original_start = threading.Thread.start
    threading.Thread.start = no_thread
    active = True

    def deny_side_effect(event, arguments):
        if not active:
            return
        if event.startswith(("socket.", "subprocess.", "os.exec", "os.spawn", "os.posix_spawn", "os.fork")) or event in ("os.system", "os.kill", "os.remove", "os.unlink", "os.rename", "os.rmdir", "os.mkdir", "os.chmod", "os.chown", "os.truncate", "os.link", "os.symlink", "os.utime"):
            raise ValueError("offline filter side effect forbidden")
        if event == "open":
            mode, flags = arguments[1:3]
            if mode is not None and any(v in mode for v in "wax+") or type(flags) is int and flags & 3 != 0:
                raise ValueError("offline filter write forbidden")

    sys.addaudithook(deny_side_effect)
    try:
        instance = Filter(None)
        seen = set()
        # These setters compile/hold data only. No command dispatcher,
        # dynamic attribute name, server protocol, file or journal backend.
        for command in commands:
            if len(command) < 4 or command[1] != "sshd" or command[2] not in ("usedns", "prefregex", "maxlines", "addfailregex", "datepattern", "ignorecommand", "logencoding"):
                continue
            key = command[2]
            if key in seen or len(command) != 4:
                raise ValueError("projection duplicate or nonfixed setter")
            seen.add(key)
            value = command[3]
            if key == "addfailregex":
                if command[0] != "multi-set" or type(value) is not list or not 1 <= len(value) <= 128 or any(type(v) is not str for v in value):
                    raise ValueError("projection regex declarations")
                for regex in value:
                    instance.addFailRegex(regex)
                continue
            if command[0] != "set" or key == "maxlines" and (type(value) is not int or not 1 <= value <= 1024) or key != "maxlines" and type(value) is not str:
                raise ValueError("projection literal setter")
            if key == "usedns":
                if value not in ("yes", "warn", "no", "raw"):
                    raise ValueError("projection DNS mode")
                instance.setUseDns(value)
            elif key == "prefregex":
                instance.prefRegex = value
            elif key == "maxlines":
                instance.setMaxLines(value)
            elif key == "datepattern":
                instance.setDatePattern(value)
            elif key == "ignorecommand":
                if value:
                    raise ValueError("projection external ignore command")
                instance.ignoreCommand = value
            elif key == "logencoding":
                instance.setLogEncoding(value)
        if len(seen) != 7:
            raise ValueError("projection incomplete filter declarations")
        values = {
            "usedns": instance.getUseDns(),
            "prefregex": instance.prefRegex.getRegex() if instance.prefRegex is not None else None,
            "failregex": instance.getFailRegex(), "ignoreregex": instance.getIgnoreRegex(),
            "maxlines": instance.getMaxLines(), "datepattern": instance.getDatePattern(),
            "ignorecommand": instance.ignoreCommand, "ignorecache": instance.ignoreCache,
            "ignoreself": instance.ignoreSelf, "ignoreip": instance.getIgnoreIP(),
            "logencoding": instance.getLogEncoding(), "logtimezone": instance.getLogTimeZone(),
        }
        if threading.active_count() != 1:
            raise ValueError("offline projection started a thread")
        return filter_metadata_fingerprint(version, values)
    finally:
        active = False
        threading.Thread.start = original_start
