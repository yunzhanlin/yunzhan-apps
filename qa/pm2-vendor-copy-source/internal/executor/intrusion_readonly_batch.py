"""Independent, read-only Fail2ban wire adapter; standard library only.

Protocol reference: fail2ban/fail2ban protocol.py, transmitter.py and
banmanager.py in upstream 0.11.2/1.0.2/1.1.0. No Fail2ban library or plugin is imported.
Only builtin primitive replies are accepted. No pickle globals, reducers,
constructors, persistent objects, arbitrary commands or socket paths are allowed.
"""
import io
import ipaddress
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
PROPERTIES = ("name", "port", "protocol", "chain", "table", "table_family", "addr_set", "addr_set?family=inet6", "actionstart")
FULL_PROPERTIES = ("actionstart", "actionstop", "actionflush", "actioncheck", "actionban", "actionunban", "port", "protocol", "chain", "name", "actname", "table", "table_family", "chain_type", "chain_hook", "chain_priority", "addr_type", "blocktype", "nftables", "addr_set", "addr_family", "addr_family?family=inet6", "addr_type?family=inet6", "addr_set?family=inet6", "actionreban", "actionreload", "actionrepair", "timeout", "banEpoch")
PROPERTY_NAMES = tuple(sorted(FULL_PROPERTIES + ("ESCAPE_CRE", "ESCAPE_VN_CRE")))
ACTIONS = ("nftables", "nftables-multiport")
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


def allowed(args):
    if args == ["version"]:
        return True
    if len(args) == 3 and args[:2] == ["get", "sshd"] and args[2] in ("actions", "journalmatch", "maxretry", "findtime", "bantime", "maxmatches", *FILTER_METADATA_FIELDS):
        return True
    if args == ["get", "sshd", "banip", "--with-time"]:
        return True
    if len(args) == 4 and args[:3] == ["get", "sshd", "actionproperties"] and args[3] in ACTIONS:
        return True
    return len(args) == 5 and args[:3] == ["get", "sshd", "action"] and args[3] in ACTIONS and args[4] in FULL_PROPERTIES


def action_names(value):
    if type(value) is not list or len(value) > 8:
        raise ValueError("action list capacity")
    if any(type(v) is not str or re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,63}", v) is None for v in value):
        raise ValueError("action identity")
    if len(set(value)) != len(value):
        raise ValueError("duplicate action identity")
    return value


def ban_addresses(value):
    # The official --with-time response is a list of plain strings, unlike
    # pickle's potentially class-bearing IP address objects in other APIs.
    if type(value) is not list or len(value) > 512:
        raise ValueError("ban list capacity")
    result = []
    for line in value:
        if type(line) is not str or len(line) > 300 or "\n" in line or "\r" in line or "\x00" in line:
            raise ValueError("ban observation shape")
        parts = line.split(" \t", 1)
        if len(parts) != 2 or not parts[1] or "%" in parts[0]:
            raise ValueError("ban observation identity")
        address = ipaddress.ip_address(parts[0])
        if address.version == 6 and address.ipv4_mapped is not None or str(address) != parts[0] or parts[0] in result:
            raise ValueError("ban observation duplicate or noncanonical address")
        result.append(parts[0])
    return " ".join(result) + "\n"


def main():
    if os.geteuid() != 0 or len(sys.argv) != 2 or re.fullmatch(r"[1-9][0-9]{0,6}", sys.argv[1]) is None or not 2 <= int(sys.argv[1]) <= 1 << 22:
        raise ValueError("fixed service principal required")
    wanted = int(sys.argv[1])
    wanted_start = process_start_ticks(wanted)
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
                raise ValueError("service PID was reused by a different process lifetime")
            for name, before in parents.items():
                info = pathlib.Path(name).lstat()
                if (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid) != before:
                    raise ValueError("socket parent changed")
            info = path.lstat()
            if (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid) != identity:
                raise ValueError("named socket changed")

        def rpc(args):
            if not allowed(args):
                raise ValueError("non-read operation forbidden")
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

        version = rpc(["version"])
        if version not in ("0.11.2", "1.0.2", "1.1.0"):
            raise ValueError("unverified service protocol version")
        names = action_names(rpc(["get", "sshd", "actions"]))
        records = [{"args": ["get", "sshd", "process-start"], "ok": True, "value": wanted_start + "\n"},
                   {"args": ["status", "sshd"], "ok": True, "value": "Status for the jail: sshd\n"},
                   {"args": ["get", "sshd", "actions"], "ok": True, "value": ("The jail sshd has the following actions:\n" + ", ".join(names) if names else "No actions for jail sshd") + "\n"}]
        # The status compatibility entry conveys ONLY verified Jail existence,
        # derived from the successful real get-actions reply, not fake counters.
        for prop in ("journalmatch", "maxretry", "findtime", "bantime", "maxmatches"):
            args = ["get", "sshd", prop]
            value = rpc(args)
            if prop == "journalmatch":
                if type(value) is not list or not 1 <= len(value) <= 8 or any(type(group) is not list or not 1 <= len(group) <= 8 or any(type(v) is not str or len(v) > 128 or any(c in v for c in "\r\n\x00") for v in group) for group in value):
                    raise ValueError("journal match shape")
                text = "Current match filter:\n" + " + ".join(" ".join(group) for group in value)
            else:
                if type(value) is not int or not 1 <= value <= 604800:
                    raise ValueError("numeric jail limit shape")
                text = str(value)
            records.append({"args": args, "ok": True, "value": text + "\n"})
        # These are actual primitive-only getters on the same authenticated
        # peer. The synthetic key is NEVER transmitted as a server command.
        metadata = filter_metadata_fingerprint(version, {prop: rpc(["get", "sshd", prop]) for prop in FILTER_METADATA_FIELDS})
        records.append({"args": ["get", "sshd", "filter-metadata"], "ok": True, "value": json.dumps(metadata, separators=(",", ":"))})
        for name in names:
            if name not in ACTIONS:
                continue
            surface_args = ["get", "sshd", "actionproperties", name]
            surface = rpc(surface_args)
            if type(surface) is not list or any(type(v) is not str for v in surface) or tuple(sorted(surface)) != PROPERTY_NAMES:
                raise ValueError("unknown complete action property surface")
            values = {}
            for prop in FULL_PROPERTIES:
                args = ["get", "sshd", "action", name, prop]
                value = rpc(args)
                if type(value) not in (str, int) or len(str(value).encode("utf-8")) > 24575:
                    raise ValueError("action property shape")
                values[prop] = str(value)
                if prop in PROPERTIES:
                    records.append({"args": args, "ok": True, "value": str(value) + "\n"})
            # This private entry is an explicit structured observation of the
            # real property names AND fixed getters, not CLI pretty printing.
            # Keeping one bounded value preserves the original 32-record cap.
            detail = json.dumps({"format": 1, "action": name, "properties": sorted(surface), "values": values}, ensure_ascii=False, allow_nan=False, separators=(",", ":"))
            if len(detail.encode("utf-8")) > 24576:
                raise ValueError("complete action detail capacity")
            records.append({"args": surface_args, "ok": True, "value": detail})
        records.append({"args": ["get", "sshd", "banip"], "ok": True, "value": ban_addresses(rpc(["get", "sshd", "banip", "--with-time"]))})
        current_peer()
        result = {"format": 1, "pid": str(wanted), "version": version, "observations": records}
        raw = json.dumps(result, ensure_ascii=False, allow_nan=False, separators=(",", ":"))
        if len(raw.encode("utf-8")) > 32767:
            raise ValueError("complete observation exceeds fixed capacity")
        print(raw)


if __name__ == "__main__":
    try:
        main()
    except BaseException:
        # No exception object, action command, address or private backend data
        # is allowed to turn into an error response or an implicit CLI retry.
        print('{"format":0}')
        sys.exit(1)
