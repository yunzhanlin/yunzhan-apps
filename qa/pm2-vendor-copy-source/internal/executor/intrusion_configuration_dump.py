"""Strict, bounded configuration observation. NEVER sends a server command.

The fixed installed client is invoked with test+dump only. Its declarations
are parsed as a closed literal grammar, not evaluated or replayed. After that
child exits, only seven fixed in-memory base-Filter setters project the public
metadata; never a live backend, server, Jail, action or command dispatcher.
"""
import ast
import configparser
import ctypes
import errno
import json
import os
import pathlib
import re
import selectors
import signal
import stat
import subprocess
import sys
import time


def parse_dump(raw):
    if type(raw) is not bytes or not 1 <= len(raw) <= 32768 or b"\x00" in raw:
        raise ValueError("configuration capacity")
    lines = raw.decode("utf-8", "strict").splitlines()
    if not 2 <= len(lines) <= 513 or lines[-1] != "OK: configuration test is successful":
        raise ValueError("strict test incomplete")
    commands, nodes = [], 0

    def literal(node, depth):
        nonlocal nodes
        nodes += 1
        if nodes > 8192 or depth > 12:
            raise ValueError("configuration tree capacity")
        if type(node) is ast.List and len(node.elts) <= 512:
            return [literal(v, depth + 1) for v in node.elts]
        if type(node) is ast.Constant:
            value = node.value
            if type(value) is str and len(value.encode("utf-8")) <= 24576 and "\x00" not in value:
                return value
            if type(value) is bool or type(value) is int and -(1 << 53) < value < 1 << 53:
                return value
        if type(node) is ast.UnaryOp and type(node.op) is ast.USub and type(node.operand) is ast.Constant and type(node.operand.value) is int and 0 < node.operand.value < 1 << 53:
            return -node.operand.value
        raise ValueError("nonliteral configuration")

    for line in lines[:-1]:
        if not 1 <= len(line.encode("utf-8")) <= 24576:
            raise ValueError("configuration line capacity")
        tree = ast.parse(line, mode="eval")
        value = literal(tree.body, 0)
        if type(value) is not list or not 2 <= len(value) <= 16:
            raise ValueError("configuration command shape")
        commands.append(value)
    return {"format": 1, "commands": commands}


def candidate_identity(raw):
    if type(raw) is not str or not 1 <= len(raw) <= 4096:
        raise ValueError("candidate path capacity")
    value = pathlib.Path(raw)
    if not value.is_absolute() or value.anchor != "/" or str(value) != raw or any(part in (".", "..") for part in value.parts) or len(value.parts) < 4 or value.parent.name != ".intrusion-removal-candidates" or re.fullmatch(r"candidate-[a-f0-9]{32}", value.name) is None:
        raise ValueError("fixed generated candidate required")
    result = {}
    for parent in (value, *value.parents):
        info = parent.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o7022:
            raise ValueError("candidate ancestor principal")
        if parent in (value, value.parent) and stat.S_IMODE(info.st_mode) != 0o700:
            raise ValueError("candidate must remain private")
        result[str(parent)] = (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid)
    return result


def child_lifetime_guard():
    # This fixed single-thread helper owns exactly one read-only client.
    # A request cancellation may SIGKILL us before Python's finally runs.
    # Bind ONLY that newly forked child to this parent, including across its
    # ordinary interpreter exec. Never kill or signal a caller-selected PID.
    info = os.stat("/usr/bin/python3")
    if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o7022:
        raise ValueError("unqualified fixed child interpreter")
    try:
        os.getxattr("/usr/bin/python3", "security.capability")
    except OSError as error:
        if error.errno not in (errno.ENODATA, errno.ENOTSUP):
            raise
    else:
        # Capability/set-ID exec clears the parent-death contract on Linux.
        raise ValueError("privileged child interpreter not supported")
    libc = ctypes.CDLL(None, use_errno=True)
    prctl = libc.prctl
    prctl.argtypes = [ctypes.c_int, ctypes.c_ulong, ctypes.c_ulong, ctypes.c_ulong, ctypes.c_ulong]
    prctl.restype = ctypes.c_int
    if len(os.listdir("/proc/self/task")) != 1:
        raise ValueError("fixed read helper must be single threaded before fork")
    parent = os.getpid()

    def bind_child():
        # Check AFTER installing the signal to close the parent-death race.
        if prctl(1, int(signal.SIGKILL), 0, 0, 0) != 0 or os.getppid() != parent:
            os._exit(127)

    return bind_child


def candidate_include_targets(resource, value):
    # Match only bounded literal relative includes. The official reader also
    # expands the corresponding .local sibling. Never interpolate an unknown
    # path or let a private -c tree read the original owned Jail via /etc/...
    if type(resource) is not str or not resource or len(resource.encode("utf-8")) > 1024 or os.path.isabs(resource) or os.path.normpath(resource) != resource or any(part in (".", "..") for part in resource.split("/")) or any(c in resource for c in "\\\x00\r\n"):
        raise ValueError("candidate include source")
    if type(value) is not str or len(value.encode("utf-8")) > 16384 or any(c in value for c in "%\\\x00\r") or "://" in value:
        raise ValueError("unqualified candidate include expression")
    result = []
    for line in value.split("\n"):
        line = line.strip()
        if not line:
            continue
        if os.path.isabs(line):
            raise ValueError("absolute candidate include forbidden")
        target = os.path.normpath(os.path.join(os.path.dirname(resource), line))
        if target in (".", "..") or target.startswith("../") or os.path.isabs(target) or len(target.encode("utf-8")) > 1024 or len(target.split("/")) > 8:
            raise ValueError("candidate include escaped replica")
        for name in (target, os.path.splitext(target)[0] + ".local"):
            if name not in result:
                result.append(name)
        if len(result) > 1024:
            raise ValueError("candidate include capacity")
    return result


def candidate_includes(raw):
    # A conservative provenance preflight, not a replacement for the upstream
    # parser. All config/local files and recursively included literal files
    # must remain in this private replica. Unsupported variable/absolute
    # includes refuse the candidate BEFORE the official client is started.
    before = candidate_identity(raw)
    root = pathlib.Path(raw)
    files = {}
    total = 0
    count = 1
    for value in root.rglob("*"):
        count += 1
        name = str(value.relative_to(root))
        info = value.lstat()
        if count > 512 or len(name.encode("utf-8")) > 1024 or len(value.relative_to(root).parts) > 8 or info.st_uid != 0 or any(c in name for c in "\\\x00\r\n"):
            raise ValueError("candidate inventory capacity or identity")
        if stat.S_ISDIR(info.st_mode) and stat.S_IMODE(info.st_mode) == 0o700:
            continue
        if not stat.S_ISREG(info.st_mode) or stat.S_IMODE(info.st_mode) != 0o600 or info.st_nlink != 1 or not 0 <= info.st_size <= 262144:
            raise ValueError("candidate config is not an ordinary private file")
        total += info.st_size
        if total > 8 << 20:
            raise ValueError("candidate config total capacity")
        files[name] = value
    pending = sorted(name for name in files if pathlib.PurePosixPath(name).suffix in (".conf", ".local"))
    queued = set(pending)
    seen = set()
    while pending:
        name = pending.pop()
        queued.remove(name)
        if name in seen:
            continue
        seen.add(name)
        value = files[name]
        initial = value.lstat()

        def identity(info):
            return (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid, info.st_nlink, info.st_size, info.st_mtime_ns, info.st_ctime_ns)

        with os.fdopen(os.open(value, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC), "rb") as file:
            opened = os.fstat(file.fileno())
            if not stat.S_ISREG(opened.st_mode) or opened.st_uid != 0 or stat.S_IMODE(opened.st_mode) != 0o600 or opened.st_nlink != 1 or identity(opened) != identity(initial):
                raise ValueError("candidate include file changed before read")
            data = file.read(262145)
            if len(data) != opened.st_size or len(data) > 262144 or identity(os.fstat(file.fileno())) != identity(opened) or identity(value.lstat()) != identity(opened):
                raise ValueError("candidate include file changed during read")
        parser = configparser.RawConfigParser(interpolation=None, inline_comment_prefixes=(";",), strict=True)
        parser.read_string(data.decode("utf-8", "strict"), source=name)
        if parser.has_section("INCLUDES"):
            for key in ("before", "after"):
                if parser.has_option("INCLUDES", key):
                    for target in candidate_include_targets(name, parser.get("INCLUDES", key, raw=True)):
                        if target in files and target not in seen and target not in queued:
                            pending.append(target)
                            queued.add(target)
    if candidate_identity(raw) != before:
        raise ValueError("candidate include root changed")


def main():
    if os.geteuid() != 0:
        raise ValueError("fixed configuration observation required")
    candidate = None
    command = ["/usr/bin/python3", "-I", "-B", "/usr/bin/fail2ban-client", "-t", "-d"]
    if len(sys.argv) == 3 and sys.argv[1] == "--owned-removal-candidate":
        candidate = candidate_identity(sys.argv[2])
        candidate_includes(sys.argv[2])
        command = ["/usr/bin/python3", "-I", "-B", "/usr/bin/fail2ban-client", "-c", sys.argv[2], "-t", "-d"]
    elif len(sys.argv) != 1:
        raise ValueError("unknown configuration observation mode")
    with subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True, start_new_session=True, preexec_fn=child_lifetime_guard(), env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8"}) as child:
        try:
            with selectors.DefaultSelector() as selector:
                selector.register(child.stdout, selectors.EVENT_READ, "stdout")
                selector.register(child.stderr, selectors.EVENT_READ, "stderr")
                buffers = {"stdout": bytearray(), "stderr": bytearray()}
                deadline = time.monotonic() + 5
                while selector.get_map():
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        raise ValueError("configuration deadline")
                    for key, event in selector.select(remaining):
                        value = os.read(key.fd, 4096)
                        if not value:
                            selector.unregister(key.fileobj)
                            continue
                        buffer = buffers[key.data]
                        if len(buffer) + len(value) > (32768 if key.data == "stdout" else 8192):
                            raise ValueError("configuration output capacity")
                        buffer.extend(value)
                remaining = deadline - time.monotonic()
                if remaining <= 0 or child.wait(timeout=remaining) != 0:
                    raise ValueError("configuration test failed")
            result = parse_dump(bytes(buffers["stdout"]))
        finally:
            if child.poll() is None:
                # This is ONLY the helper's own fixed read-only child group.
                os.killpg(child.pid, signal.SIGKILL)
                child.wait()
    if candidate is not None and candidate_identity(sys.argv[2]) != candidate:
        raise ValueError("named candidate changed during fixed test")
    result["filter_metadata"] = project_filter_metadata(result["commands"])
    raw = json.dumps(result, ensure_ascii=False, allow_nan=False, separators=(",", ":"))
    if len(raw.encode("utf-8")) > 32767:
        raise ValueError("complete configuration capacity")
    print(raw)


if __name__ == "__main__":
    try:
        main()
    except BaseException:
        print('{"format":0}')
        sys.exit(1)
