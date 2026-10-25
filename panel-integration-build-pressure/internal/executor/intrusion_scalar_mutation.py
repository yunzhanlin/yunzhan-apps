"""Fixed single-scalar setter for a separately verified original transaction.

Independent standard-library wire adapter; no Fail2ban library is imported.
This helper is NOT a controller or permission to mutate. Only the executor's
future durable original-record/CAS controller may invoke it. One SET at most;
unknown outcomes are never retried. No reload, action verb, ban or unban.
"""
import io
import json
import os
import pathlib
import pickle
import pickletools
import re
import socket
import stat
import struct
import sys

END = b"<F2B_END_COMMAND>"
MAX_REPLY = 65536
OPS = frozenset("PROTO FRAME STOP MARK NONE NEWTRUE NEWFALSE INT BININT BININT1 BININT2 LONG LONG1 LONG4 FLOAT BINFLOAT UNICODE BINUNICODE SHORT_BINUNICODE BINUNICODE8 STRING BINSTRING SHORT_BINSTRING EMPTY_LIST LIST APPEND APPENDS EMPTY_TUPLE TUPLE TUPLE1 TUPLE2 TUPLE3 EMPTY_DICT DICT SETITEM SETITEMS PUT BINPUT LONG_BINPUT GET BINGET LONG_BINGET MEMOIZE".split())


class Primitives(pickle.Unpickler):
    def find_class(self, module, name):
        raise ValueError("nonprimitive reply")

    def persistent_load(self, pid):
        raise ValueError("persistent reply")


def decode_reply(raw):
    if not 1 <= len(raw) <= MAX_REPLY:
        raise ValueError("reply capacity")
    count, stopped = 0, False
    for op, argument, position in pickletools.genops(raw):
        count += 1
        if count > 8192 or op.name not in OPS or op.name == "FRAME" and not 0 <= argument <= len(raw):
            raise ValueError("reply grammar")
        if op.name in ("PUT", "GET", "BINPUT", "LONG_BINPUT", "BINGET", "LONG_BINGET") and not 0 <= int(argument) <= 8192:
            raise ValueError("reply memo capacity")
        if op.name == "STOP":
            stopped = position + 1 == len(raw)
    if not stopped:
        raise ValueError("reply trailing data")
    value = Primitives(io.BytesIO(raw)).load()
    seen, used = set(), 0

    def inspect(item, depth):
        nonlocal used
        used += 1
        if depth > 12 or used > 8192:
            raise ValueError("reply tree capacity")
        kind = type(item)
        if kind in (str, int, bool, float, type(None)):
            if kind is str and (len(item.encode("utf-8")) > 24576 or "\x00" in item):
                raise ValueError("reply string capacity")
            return
        if kind not in (list, tuple, dict) or id(item) in seen or len(item) > 1024:
            raise ValueError("nonprimitive, aliased or oversized container")
        seen.add(id(item))
        for child in item:
            inspect(child, depth + 1)
            if kind is dict:
                inspect(item[child], depth + 1)

    inspect(value, 0)
    if type(value) not in (tuple, list) or len(value) != 2 or type(value[0]) is not int or value[0] != 0:
        raise ValueError("unsuccessful reply")
    return value[1]


def scalar_request(arguments):
    if len(arguments) != 6:
        raise ValueError("fixed scalar arguments")
    pid, field, action, before, after, start = arguments
    canonical_process_ticks(start)
    if re.fullmatch(r"[1-9][0-9]{0,6}", pid) is None or not 2 <= int(pid) <= 1 << 22 or before == after:
        raise ValueError("scalar identity")
    if field == "port":
        if action not in ("nftables", "nftables-multiport"):
            raise ValueError("scalar action identity")
        for value in (before, after):
            parts = value.split(",")
            if not 1 <= len(parts) <= 16 or any(re.fullmatch(r"[1-9][0-9]{0,4}", p) is None for p in parts):
                raise ValueError("scalar port grammar")
            ports = [int(p) for p in parts]
            if any(not 1 <= p <= 65535 for p in ports) or ports != sorted(set(ports)):
                raise ValueError("scalar port scope")
        getter = ["get", "sshd", "action", action, "port"]
        setter = ["set", "sshd", "action", action, "port", after]
        return int(pid), getter, setter, str
    bounds = {"maxretry": (2, 20, 1), "findtime": (60, 86400, 60), "bantime": (600, 604800, 60)}
    if field not in bounds or action != "-":
        raise ValueError("scalar field forbidden")
    low, high, factor = bounds[field]
    for value in (before, after):
        if re.fullmatch(r"[1-9][0-9]{0,5}", value) is None or not low <= int(value) <= high or int(value) % factor:
            raise ValueError("scalar limit grammar")
    return int(pid), ["get", "sshd", field], ["set", "sshd", field, after], int


def main():
    if os.geteuid() != 0:
        raise ValueError("fixed scalar service principal")
    wanted, getter, setter, kind = scalar_request(sys.argv[1:])
    field, action, before, after = sys.argv[2:6]
    wanted_start = canonical_process_ticks(sys.argv[6])
    path = pathlib.Path("/run/fail2ban/fail2ban.sock")
    parents = {}
    for parent in path.parents:
        s = parent.lstat()
        if not stat.S_ISDIR(s.st_mode) or s.st_uid != 0 or s.st_mode & 0o022:
            raise ValueError("untrusted socket parent")
        parents[str(parent)] = (s.st_dev, s.st_ino, s.st_mode, s.st_uid, s.st_gid)
    s = path.lstat()
    identity = (s.st_dev, s.st_ino, s.st_mode, s.st_uid, s.st_gid)
    # Upstream binds under umask 077, producing mode 0700 on both native VMs.
    if not stat.S_ISSOCK(s.st_mode) or s.st_uid != 0 or stat.S_IMODE(s.st_mode) not in (0o600, 0o660, 0o700):
        raise ValueError("untrusted socket")
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
        connection.settimeout(3)
        connection.connect(str(path))

        def current_peer():
            pid, uid, gid = struct.unpack("3i", connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i")))
            if pid != wanted or uid != 0:
                raise ValueError("unexpected service peer")
            if process_start_ticks(wanted) != wanted_start:
                raise ValueError("original service process lifetime changed")
            for name, before in parents.items():
                info = pathlib.Path(name).lstat()
                if (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid) != before:
                    raise ValueError("socket parent changed")
            info = path.lstat()
            if (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid) != identity:
                raise ValueError("named socket changed")

        def rpc(args):
            if args not in (["version"], getter, setter):
                raise ValueError("nonfixed scalar operation forbidden")
            current_peer()  # Before sending or decoding ANY service data.
            connection.sendall(pickle.dumps(args, protocol=2) + END)
            reply = bytearray()
            while not reply.endswith(END):
                remaining = MAX_REPLY + len(END) + 1 - len(reply)
                if remaining <= 0:
                    raise ValueError("reply exceeds fixed capacity")
                chunk = connection.recv(min(4096, remaining))
                if not chunk:
                    raise ValueError("incomplete reply")
                reply.extend(chunk)
            current_peer()
            return decode_reply(bytes(reply[:-len(END)]))

        if rpc(["version"]) not in ("1.0.2", "1.1.0"):
            raise ValueError("unverified service protocol")
        value = rpc(getter)
        if type(value) is not kind:
            raise ValueError("scalar current type")
        applied = False
        if str(value) != after:
            if str(value) != before:
                raise ValueError("scalar compare failed")
            # The ONLY possible mutating request. An error or lost reply is
            # UNKNOWN, not permission for another send or an implicit retry.
            reply = rpc(setter)
            applied = True
            if type(reply) is not kind or str(reply) != after:
                raise ValueError("scalar reply unknown")
        final = rpc(getter)
        if type(final) is not kind or str(final) != after:
            raise ValueError("scalar postcondition unknown")
        current_peer()
        print(json.dumps({"format": 1, "pid": str(wanted), "start_ticks": wanted_start, "field": field, "action": action, "from": before, "to": after, "applied": applied, "already_target": not applied}, separators=(",", ":")))


if __name__ == "__main__":
    try:
        main()
    except BaseException:
        print('{"format":0}')
        sys.exit(1)
