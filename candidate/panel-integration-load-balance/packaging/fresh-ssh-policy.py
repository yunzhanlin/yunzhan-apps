#!/usr/bin/env python3
"""Initialize only a newly provisioned first-install SSH jail.

The installer refuses pre-existing Fail2ban before package or service writes.
Ordinary upgrades never call this helper. A distro postinst may already have
started its default jail; load our exact policy without restarting the daemon
or unbanning addresses. See the upstream fail2ban-client(1) reload contract.
"""
import datetime
import hashlib
import ipaddress
import json
import os
import pathlib
import re
import stat
import subprocess
import sys
import time

CONFIG = pathlib.Path('/etc/fail2ban/jail.d/panel-sshd.local')
FILTER_FIELDS = ('usedns', 'prefregex', 'failregex', 'ignoreregex', 'maxlines',
                 'maxmatches', 'ignorecommand', 'ignorecache', 'ignoreself',
                 'ignoreip', 'logencoding', 'logtimezone')


def require(condition, message):
    if not condition:
        raise ValueError(message)


def run(args):
    env = {'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LC_ALL': 'C', 'LANG': 'C'}
    if 'TZ' in os.environ:
        env['TZ'] = os.environ['TZ']
    result = subprocess.run(args, stdin=subprocess.DEVNULL, capture_output=True,
                            timeout=8, env=env)
    require(result.returncode == 0, 'fixed SSH policy command refused: ' + args[0])
    require(len(result.stdout) <= 1 << 20 and len(result.stderr) <= 1 << 16,
            'SSH policy response exceeds bound')
    return result.stdout.decode('utf-8', errors='strict')


def canonical_ports(values):
    require(type(values) is list and 1 <= len(values) <= 32, 'expected 1..32 SSH listen ports')
    require(all(type(v) is str and re.fullmatch('[1-9][0-9]{0,4}', v) and int(v) <= 65535
                for v in values), 'SSH listen port is not a canonical number')
    return ','.join(str(v) for v in sorted(set(map(int, values))))


def ssh_ports(text):
    require(len(text.encode()) <= 1 << 20, 'effective sshd configuration exceeds bound')
    ports = []
    for line in text.splitlines():
        fields = line.split()
        if fields and fields[0] == 'port':
            require(len(fields) == 2, 'malformed effective SSH port')
            ports.append(fields[1])
    return canonical_ports(ports)


def rendered(ports):
    require(type(ports) is str and 0 < len(ports) <= 192, 'SSH port list exceeds bound')
    require(canonical_ports(ports.split(',')) == ports, 'SSH ports changed or are not sorted')
    return ('[sshd]\nenabled = true\nbackend = systemd\n'
            'banaction = nftables-multiport\nport = ' + ports + '\n').encode()


def parents(path):
    for p in path.parents:
        value = p.lstat()
        require(stat.S_ISDIR(value.st_mode) and value.st_uid == 0
                and not value.st_mode & 0o022, 'unsafe first-install SSH policy parent')


def config_bytes(path):
    parents(path)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    with os.fdopen(fd, 'rb') as f:
        value = os.fstat(f.fileno())
        require(stat.S_ISREG(value.st_mode) and value.st_uid == value.st_gid == 0
                and value.st_nlink == 1 and stat.S_IMODE(value.st_mode) == 0o644
                and 0 < value.st_size <= 4096, 'unsafe first-install SSH policy file')
        raw = f.read(4097)
        after = os.fstat(f.fileno())
        require(len(raw) == value.st_size and
                (value.st_dev, value.st_ino, value.st_size, value.st_mtime_ns, value.st_ctime_ns)
                == (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns),
                'first-install SSH policy changed during read')
        return raw


def configure():
    ports = ssh_ports(run(['/usr/sbin/sshd', '-T']))
    raw = rendered(ports)
    parents(CONFIG)
    # Never follow or overwrite even a pre-existing empty file or dangling link.
    fd = os.open(CONFIG, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o644)
    with os.fdopen(fd, 'wb') as f:
        os.fchmod(f.fileno(), 0o644)
        f.write(raw)
        f.flush()
        os.fsync(f.fileno())
    fd = os.open(CONFIG.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)
    require(config_bytes(CONFIG) == raw, 'written first-install SSH policy differs')
    return ports


def lifetime(unit):
    require(unit in ('ssh.service', 'fail2ban.service'), 'unknown protected service')
    raw = run(['/usr/bin/systemctl', 'show', unit, '--property=MainPID,InvocationID,ActiveState,SubState'])
    fields = dict(line.split('=', 1) for line in raw.splitlines())
    require(set(fields) == {'MainPID', 'InvocationID', 'ActiveState', 'SubState'}
            and fields['ActiveState'] == 'active' and fields['MainPID'].isdigit()
            and int(fields['MainPID']) > 1 and re.fullmatch('[a-f0-9]{32}', fields['InvocationID']),
            'protected SSH service is not active')
    proc = pathlib.Path('/proc') / fields['MainPID']
    fields['start_ticks'] = (proc / 'stat').read_text().rsplit(')', 1)[1].split()[19]
    # This is the kernel-owned /proc/PID/exe link, not an input configuration path.
    fields['exe_sha256'] = hashlib.sha256((proc / 'exe').read_bytes()).hexdigest()
    return fields


def client(*args):
    return run(['/usr/bin/fail2ban-client', *args])


def action():
    lines = client('get', 'sshd', 'actions').strip().splitlines()
    require(len(lines) == 2 and lines[0] == 'The jail sshd has the following actions:'
            and lines[1].strip() in ('nftables', 'nftables-multiport', 'iptables-multiport'),
            'unexpected first-install SSH action; no action migration attempted')
    return lines[1].strip()


def bans(text):
    require(len(text.encode()) <= 1 << 20, 'initial SSH bans exceed bound')
    result = {}
    for line in text.splitlines():
        if not line.strip():
            continue
        require(len(result) < 1024 and len(line) <= 512, 'initial SSH ban list exceeds bound')
        fields = line.split(None, 1)
        require(len(fields) == 2 and str(ipaddress.ip_address(fields[0])) == fields[0]
                and fields[0] not in result, 'unexpected initial SSH ban record')
        result[fields[0]] = line
    return result


def preserved_bans(before, after, now):
    expired = 0
    for address, original in before.items():
        if address in after:
            require(after[address] == original, 'first-install reload altered original ban lifetime')
            continue
        # A normal expiry is not an unban. Permanent or unparseable records may
        # never disappear; use the same local timezone as the client's output.
        match = re.fullmatch(r'\S+\s+\d{4}-\d\d-\d\d \d\d:\d\d:\d\d \+ ([0-9]+) = (\d{4}-\d\d-\d\d \d\d:\d\d:\d\d)', original)
        require(match is not None and int(match[1]) > 0, 'original SSH ban disappeared')
        end = datetime.datetime.strptime(match[2], '%Y-%m-%d %H:%M:%S').timestamp()
        require(end <= now, 'original SSH ban disappeared before its expiry')
        expired += 1
    return expired


def activate(ports):
    expected = rendered(ports)
    require(ssh_ports(run(['/usr/sbin/sshd', '-T'])) == ports and config_bytes(CONFIG) == expected,
            'first-install effective SSH ports or owned policy changed')
    client('-t')
    original_lifetimes = {n: lifetime(n) for n in ('ssh.service', 'fail2ban.service')}
    original_bans = bans(client('get', 'sshd', 'banip', '--with-time'))
    original_filters = {n: client('get', 'sshd', n) for n in FILTER_FIELDS}
    nss = identities()
    name = action()
    reload_needed = name != 'nftables-multiport' or client('get', 'sshd', 'action', name, 'port').strip() != ports
    if reload_needed:
        # One targeted reload. No --restart, --unban, global reload or retry.
        client('reload', 'sshd')
    require(action() == 'nftables-multiport'
            and client('get', 'sshd', 'action', 'nftables-multiport', 'port').strip() == ports,
            'first-install SSH policy not active after original load attempt')
    after_bans = bans(client('get', 'sshd', 'banip', '--with-time'))
    expired = preserved_bans(original_bans, after_bans, time.time())
    require({n: client('get', 'sshd', n) for n in FILTER_FIELDS} == original_filters,
            'first-install load altered stock SSH detection filters')
    require({n: lifetime(n) for n in original_lifetimes} == original_lifetimes,
            'first-install load replaced a protected SSH daemon')
    require(identities() == nss and config_bytes(CONFIG) == expected,
            'first-install load changed identities or owned policy')
    return {'ok': True, 'ports': ports, 'targeted_reload': reload_needed,
            'original_active_bans': len(original_bans), 'naturally_expired': expired,
            'original_daemons_filters_and_identities_preserved': True}


def identities():
    return {n: hashlib.sha256(pathlib.Path('/etc', n).read_bytes()).hexdigest()
            for n in ('passwd', 'group', 'shadow', 'gshadow', 'nsswitch.conf')}


def main():
    require(os.geteuid() == 0, 'fresh SSH policy setup requires root')
    require(len(sys.argv) in (2, 3), 'expected configure or activate')
    if sys.argv[1:] == ['configure']:
        print(configure())
    else:
        require(len(sys.argv) == 3 and sys.argv[1] == 'activate', 'unknown fresh SSH policy operation')
        print(json.dumps(activate(sys.argv[2]), sort_keys=True))


if __name__ == '__main__':
    try:
        main()
    except (ValueError, OSError, subprocess.SubprocessError, UnicodeError) as error:
        print('fresh SSH policy initialization refused: ' + str(error), file=sys.stderr)
        sys.exit(1)
