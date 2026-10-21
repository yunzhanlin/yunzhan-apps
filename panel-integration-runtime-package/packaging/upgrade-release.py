#!/usr/bin/env python3
"""Fail-closed ordinary production upgrade; never provision a website gateway.

Only the real / host is supported by the CLI. Tests instantiate the transaction
with an isolated filesystem and command runner; those are not runtime switches.
An interrupted journal is retained for inspection, not silently retried.
"""
import argparse
import contextlib
import ctypes
import fcntl
import hashlib
import importlib.util
import json
import os
import pathlib
import re
import shutil
import signal
import sqlite3
import stat
import subprocess
import sys
import tempfile
import time
import types
import uuid

PROGRAMS = ('panel-terminal.service', 'panel-terminal-root.service', 'panel-executor.service', 'panel.service')
TIMER = 'panel-mysql-overwrite-recovery.timer'
QUEUES = ('jobs', 'runtime_jobs', 'mysql_jobs', 'acme_orders')
NATIVE_PREREQUISITES = ('waf-state-directory.py', 'native-build-directories.py')
VERSION = re.compile(r'[0-9]+\.[0-9]+\.[0-9]+([.-][a-z0-9]+)*\Z')
UNIT = re.compile(r'(?:panel-[a-z0-9@.-]+|panel|var-cache-panel\\x2dapache\\x2dbody)\.(?:service|timer|mount)\Z')


class CommandFailure(RuntimeError):
    """Keep console errors closed; output is available only to private evidence."""
    def __init__(self, program, code, stdout, stderr):
        super().__init__('command failed: ' + pathlib.Path(program).name + ' ' + str(code))
        self.program = pathlib.Path(program).name
        self.code = code
        self.output = {}
        for name, value in (('stdout', stdout), ('stderr', stderr)):
            raw = value.encode('utf-8')
            self.output[name] = {'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest(),
                                 'text': raw[:8192].decode('utf-8', errors='replace'), 'truncated': len(raw) > 8192}


class ServiceStateFailure(ValueError):
    """Preserve a refused ORIGINAL observation without publishing raw output."""
    def __init__(self, unit, raw, properties):
        super().__init__('service has a masked, failed, transitional or unsupported state')
        units = PROGRAMS + (TIMER, 'panel-mysql-overwrite-recovery.service', 'nginx.service')
        known = {
            'LoadState': ('loaded', 'masked', 'not-found', 'error', 'bad-setting', 'stub', 'merged'),
            'ActiveState': ('active', 'inactive', 'activating', 'deactivating', 'failed', 'reloading', 'maintenance', 'refreshing'),
            'SubState': ('running', 'waiting', 'dead', 'exited', 'start', 'start-pre', 'start-post', 'stop', 'stop-post', 'stop-sigterm', 'stop-sigkill', 'failed', 'auto-restart', 'condition', 'reload', 'cleaning'),
            'UnitFileState': ('enabled', 'disabled', 'static', 'indirect', 'enabled-runtime', 'masked', 'masked-runtime', 'linked', 'linked-runtime', 'generated', 'transient', 'bad', 'not-found'),
        }
        self.public_metadata = {'format': 1, 'kind': 'service-state-refusal-public-metadata',
            'unit': unit if unit in units else 'unrecognized',
            'original_observation_only': True, 'retry_or_state_exemption': False,
            'properties': {name: properties[name] if properties.get(name) in allowed else 'unrecognized'
                           for name, allowed in known.items()},
            'fields_complete': set(properties) == set(known),
            'original_output_bytes': len(raw.encode('utf8')),
            'original_output_sha256': hashlib.sha256(raw.encode('utf8')).hexdigest()}


def public_service_refusal_diagnostic(error):
    return error.public_metadata if isinstance(error, ServiceStateFailure) else None


def original_native_queue_observation_reason(text):
    """Recognize only the complete producer's two-line original observation.

    This is diagnostic classification, not task closure or upgrade permission.
    No service query may replace the original refused inventory or state.
    """
    first, separator, encoded = text.partition('\n')
    if not separator or '\n' in encoded or '\r' in text or not 1 <= len(encoded) <= 1024:
        return None
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError('duplicate native observation key')
            result[key] = value
        return result
    try:
        value = json.loads(encoded, object_pairs_hook=unique)
    except (ValueError, TypeError):
        return None
    if not isinstance(value, dict) or type(value.get('format')) is not int or value['format'] != 1:
        return None
    unit, digest = value.get('unit'), value.get('inventory_sha256')
    if not isinstance(unit, str) or not re.fullmatch(r'panel-[a-z0-9@_.-]{1,127}\.(service|scope)', unit):
        return None
    if not isinstance(digest, str) or not re.fullmatch(r'[a-f0-9]{64}', digest):
        return None
    common = {'format', 'kind', 'unit', 'inventory_sha256'}
    if (first == 'native program operation is active, failed or transitional; upgrade refused'
            and value.get('kind') == 'native-program-unit-refusal-v1'
            and set(value) == common | {'load_state', 'active_state', 'sub_state'}):
        states = [value[key] for key in ('load_state', 'active_state', 'sub_state')]
        if all(isinstance(state, str) and re.fullmatch(r'[a-z][a-z0-9-]{0,31}', state) for state in states):
            return 'native-operation-not-closed'
    if (first == 'native program operation is queued; upgrade refused'
            and value.get('kind') == 'native-program-job-refusal-v1'
            and set(value) == common | {'job_id', 'job_type', 'job_state'}):
        identity = value['job_id']
        if (isinstance(identity, str) and re.fullmatch(r'[1-9][0-9]{0,19}', identity)
                and int(identity) <= 18446744073709551615
                and all(isinstance(value[key], str) and re.fullmatch(r'[a-z][a-z0-9-]{0,31}', value[key]) for key in ('job_type', 'job_state'))):
            return 'native-operation-queued'
    return None


def public_queue_refusal_diagnostic(error):
    """Original-child metadata only, including write-free preflight failures.

    Never print child text, arguments, paths or table values. A reason code is
    recognized only from a complete exact fixed source message and optional
    closed versioned original-observation line, preceded at most by Go's
    standard log timestamp. Unknown output stays unknown; a
    later successful reader cannot replace the original failed observation.
    """
    if not isinstance(error, CommandFailure) or error.program != 'panel-executor':
        return None
    fixed = {
        'context deadline exceeded': 'reader-deadline',
        'native program unit inventory cannot be verified': 'native-unit-inventory-unavailable',
        'native program pending jobs cannot be verified': 'native-job-inventory-unavailable',
        'native upgrade queue inventory unavailable or exceeds budget': 'native-inventory-budget-or-unavailable',
        'invalid native program unit inventory': 'native-unit-inventory-invalid',
        'unknown, duplicate or excessive native program unit inventory': 'native-unit-inventory-invalid',
        'native program operation is active, failed or transitional; upgrade refused': 'native-operation-not-closed',
        'native program operation is queued; upgrade refused': 'native-operation-queued',
        'program queue inventory changed; not a drain proof': 'queue-changed-during-read',
        'program queue contains unknown or unfinished record': 'queue-record-not-closed',
        'program queue exceeds complete inventory budget': 'queue-inventory-budget',
        'program queue directory is not private': 'queue-directory-not-private',
    }
    stderr = error.output['stderr']
    reason = 'unclassified-original-refusal'
    if not stderr['truncated']:
        text = stderr['text'][:-1] if stderr['text'].endswith('\n') else stderr['text']
        text = re.sub(r'\A[0-9]{4}/[0-9]{2}/[0-9]{2} [0-9]{2}:[0-9]{2}:[0-9]{2} ', '', text, count=1)
        reason = fixed.get(text, reason)
        if reason == 'unclassified-original-refusal' and error.output['stdout']['bytes'] == 0:
            reason = original_native_queue_observation_reason(text) or reason
    return {'format': 1, 'kind': 'native-program-queue-refusal-public-metadata',
            'program': 'panel-executor', 'exit': error.code, 'reason_code': reason,
            'original_child_only': True, 'retry_or_queue_exemption': False,
            'output': {name: {key: value[key] for key in ('bytes', 'sha256', 'truncated')}
                       for name, value in error.output.items()}}


def original_periodic_recovery_can_be_observed_again(error):
    """Only a complete ORIGINAL fixed timer-worker observation is eligible.

    This grants no drain proof: the next complete guard must succeed. Legacy
    messages, other jobs, failures, unknown states and partial output refuse.
    """
    if (not isinstance(error, CommandFailure) or error.program != 'panel-executor'
            or type(error.code) is not int or error.code != 1
            or error.output['stdout']['bytes'] != 0 or error.output['stderr']['truncated']):
        return False
    text = error.output['stderr']['text']
    text = text[:-1] if text.endswith('\n') else text
    text = re.sub(r'\A[0-9]{4}/[0-9]{2}/[0-9]{2} [0-9]{2}:[0-9]{2}:[0-9]{2} ', '', text, count=1)
    if original_native_queue_observation_reason(text) is None:
        return False
    value = json.loads(text.partition('\n')[2])  # Closed/unique schema above.
    if value['unit'] != 'panel-mysql-overwrite-recovery.service':
        return False
    if value['kind'] == 'native-program-job-refusal-v1':
        return value['job_type'] == 'start' and value['job_state'] in ('waiting', 'running')
    return (value['load_state'] == 'loaded'
            and (value['active_state'], value['sub_state']) in
            (('activating','condition'), ('activating','start-pre'),
             ('activating','start'), ('activating','start-post'),
             ('active','running'), ('deactivating','stop-post')))


def command(*args, timeout=60):
    result = subprocess.run(args, capture_output=True, text=True, timeout=timeout)
    if result.returncode:
        # No raw unit, credential, configuration or database output is exposed.
        raise CommandFailure(args[0], result.returncode, result.stdout, result.stderr)
    return result.stdout.strip()


def rename_noreplace(source, target):
    # Linux renameat2 RENAME_NOREPLACE publishes a complete fsynced marker
    # without ever replacing an independently created path. No link/write
    # fallback is safe for an interrupted transaction, so unsupported hosts
    # refuse. See https://man7.org/linux/man-pages/man2/rename.2.html .
    if not sys.platform.startswith('linux'):
        raise ValueError('atomic exclusive maintenance markers require Linux')
    library = ctypes.CDLL(None,use_errno=True)
    rename = getattr(library,'renameat2',None)
    if rename is None:
        raise ValueError('atomic exclusive marker primitive unavailable')
    rename.argtypes = [ctypes.c_int,ctypes.c_char_p,ctypes.c_int,ctypes.c_char_p,ctypes.c_uint]
    rename.restype = ctypes.c_int
    if rename(-100,os.fsencode(source),-100,os.fsencode(target),1)!=0:
        raise OSError(ctypes.get_errno(),'atomic exclusive maintenance marker refused')


class Upgrade:
    def __init__(self, release, root=pathlib.Path('/'), runner=command):
        self.release = pathlib.Path(release)
        self.root = pathlib.Path(root)
        self.run_command = runner
        self.locks = []
        self.stopping = False
        self.changed = False
        self.committed = False
        self.backup = None
        self.states = {}
        self.original_units = {}
        self.pending_created = False
        self.replaced_units = {}
        self.failed_stop_snapshots = 0
        self.file_mutations = {}
        self.pointer_mutations = []
        self.mutation_sequence = 0
        self.layout = 'production'
        self.database_mutations = {}
        self.timer_deferred = False

    def path(self, value):
        value = pathlib.Path(value)
        if not value.is_absolute() or '..' in value.parts or str(value).startswith('//'):
            raise ValueError('privileged upgrade target is not canonical absolute')
        return self.scoped_path(self.root/str(value).lstrip('/'))

    def scoped_path(self, path):
        # Do not resolve here: resolving would follow a privileged link before
        # the ordinary-parent checks. Relative paths previously skipped those
        # checks entirely when a helper was invoked directly from a cwd.
        path = pathlib.Path(path)
        if (not self.root.is_absolute() or '..' in self.root.parts or str(self.root).startswith('//')
                or not path.is_absolute() or '..' in path.parts or str(path).startswith('//')
                or '\x00' in str(path) or (path != self.root and self.root not in path.parents)):
            raise ValueError('upgrade path is relative, noncanonical or outside its fixed scope')
        return path

    def directory(self, path, owner=0, private=False):
        path = self.scoped_path(path)
        info = path.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != owner or info.st_mode & 0o022 or (private and stat.S_IMODE(info.st_mode) != 0o700):
            raise ValueError('untrusted upgrade directory')
        return info

    def parents(self, path):
        path = self.scoped_path(path)
        # Every traversed privileged parent must be ordinary and root controlled.
        for parent in reversed(path.parents):
            if parent == self.root or self.root in parent.parents:
                if parent == self.path('/tmp'):
                    # The original out-of-band signed verifier creates a root
                    # 0700 TemporaryDirectory beneath the ordinary sticky /tmp.
                    # Permit only that anchor, not arbitrary writable parents.
                    info = parent.lstat()
                    relative = path.relative_to(parent)
                    if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or stat.S_IMODE(info.st_mode) != 0o1777 or len(relative.parts) < 2:
                        raise ValueError('unsafe signed-upgrade temporary parent')
                    self.directory(parent/relative.parts[0], private=True)
                    continue
                self.directory(parent)

    def file(self, path, owner=0, mode=None, limit=2*1024*1024):
        path = self.scoped_path(path)
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        try:
            before = os.fstat(descriptor)
            if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or before.st_uid != owner or before.st_mode & 0o022 or (mode is not None and stat.S_IMODE(before.st_mode) != mode) or before.st_size > limit:
                raise ValueError('untrusted upgrade file')
            data = b''
            while len(data) <= limit:
                block = os.read(descriptor, min(65536, limit+1-len(data)))
                if not block:
                    break
                data += block
            after = os.fstat(descriptor)
            identity = lambda s: (s.st_dev, s.st_ino, s.st_mode, s.st_uid, s.st_gid, s.st_nlink, s.st_size, s.st_mtime_ns, s.st_ctime_ns)
            if len(data) != before.st_size or identity(before) != identity(after):
                raise ValueError('upgrade file changed while reading')
            return data, before
        finally:
            os.close(descriptor)

    def payload_size(self):
        self.scoped_path(self.release)
        paths = [self.release]+list(self.release.rglob('*'))
        if len(paths) > 10000:
            raise ValueError('upgrade payload exceeds tree-check budget')
        size = 0
        for path in paths:
            info = path.lstat()
            if info.st_uid != 0 or info.st_mode & 0o022:
                raise ValueError('upgrade payload is not exclusively root controlled')
            if stat.S_ISDIR(info.st_mode):
                continue
            if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
                raise ValueError('linked or special upgrade payload')
            size += info.st_size
        return size

    def atomic(self, target, data, mode, uid=0, gid=0, *, exclusive=False):
        target = self.scoped_path(target)
        tracked = self.managed_file_original(target)
        before = None
        if tracked is not False:
            before = self.validate_managed_file(target)
        descriptor, name = tempfile.mkstemp(prefix='.program-upgrade-'+target.name+'-', dir=target.parent)
        temporary = pathlib.Path(name)
        try:
            os.fchmod(descriptor, mode)
            os.fchown(descriptor, uid, gid)
            with os.fdopen(descriptor, 'wb', closefd=False) as stream:
                stream.write(data)
                stream.flush()
                os.fsync(descriptor)
            candidate = self.file_snapshot(data, os.fstat(descriptor))
        finally:
            os.close(descriptor)
        intent = None
        if tracked is not False:
            intent = {'kind':'file-replace','target':str(target),'stage':str(temporary),
                      'before':before,'candidate':candidate}
            self.mutation_evidence(intent)
            self.file_mutations.setdefault(str(target), []).append(intent)
            # The durable intent binds this fsynced temporary inode, not just
            # candidate bytes. A failed replace can leave either owned state.
            if self.current_file_snapshot(target) != before or self.current_file_snapshot(temporary, mode=mode) != candidate:
                raise ValueError('managed file changed after durable mutation intent')
        if exclusive:
            if tracked is False or before is not None:
                raise ValueError('exclusive managed replacement requires an absent owned target')
            rename_noreplace(temporary,target)
        else:
            os.replace(temporary, target)
        if intent is not None:
            intent['applied'] = True
        if target == getattr(self,'pending',None):
            self.pending_bytes = data
            self.pending_identity = target.lstat()
            self.pending_created = True
        self.sync_directory(target.parent)

    @staticmethod
    def file_snapshot(data, info):
        return {'sha256':hashlib.sha256(data).hexdigest(),
                'identity':[info.st_dev,info.st_ino,info.st_mode,info.st_uid,info.st_gid,info.st_nlink,info.st_size,info.st_mtime_ns,info.st_ctime_ns]}

    @staticmethod
    def same_owned_snapshot(actual, expected):
        if actual is None or expected is None:
            return actual is expected
        # rename changes ctime; all other descriptor identities remain bound.
        return actual['sha256'] == expected['sha256'] and actual['identity'][:-1] == expected['identity'][:-1]

    def current_file_snapshot(self, target, mode=0o644):
        self.parents(target)
        if not self.exists(target):
            return None
        return self.file_snapshot(*self.file(target, mode=mode, limit=65536))

    def managed_file_original(self, target):
        # Evidence, guards, databases and arbitrary paths are never admitted
        # to this fixed code/config lineage by a filename prefix or caller flag.
        if self.backup is None:
            return False
        unit = self.path('/etc/systemd/system')
        if target.parent == unit and target.name in self.original_units:
            value = self.original_units[target.name]
            return self.file_snapshot(*value) if value is not None else None
        if hasattr(self, 'marker') and target == self.marker:
            return self.file_snapshot(self.marker_bytes, self.marker_info) if self.marker_bytes is not None else None
        if target == getattr(self,'pending',None):
            return None
        return False

    def validate_managed_file(self, target):
        original = self.managed_file_original(target)
        if original is False:
            raise ValueError('file outside fixed transaction lineage')
        actual = self.current_file_snapshot(target)
        mutations = self.file_mutations.get(str(target), [])
        if mutations:
            latest = mutations[-1]
            valid = self.same_owned_snapshot(actual, latest['candidate'])
            if not latest.get('applied'):
                valid = valid or actual == latest['before']
        else:
            valid = actual == original
        if not valid:
            raise ValueError('managed file inode or content changed outside this transaction; rollback refused')
        return actual

    def mutation_evidence(self, intent):
        if self.backup is None or self.mutation_sequence >= 160:
            raise ValueError('managed mutation lacks bounded private evidence')
        self.parents(self.backup)
        self.directory(self.backup, private=True)
        target = self.backup/('mutation-'+str(self.mutation_sequence+1).zfill(3)+'.json')
        if self.exists(target):
            raise ValueError('retained mutation intent must not be overwritten')
        self.atomic(target, (json.dumps({'format':1,'version':self.version,**intent},sort_keys=True)+'\n').encode(), 0o600)
        self.mutation_sequence += 1

    def read_record(self, target, limit=8*1024*1024):
        self.parents(target)
        raw, _ = self.file(target,mode=0o600,limit=limit)
        def closed(pairs):
            result = {}
            for name,value in pairs:
                if name in result:
                    raise ValueError('duplicate private recovery record field')
                result[name] = value
            return result
        def invalid(value):
            raise ValueError('nonfinite private recovery value')
        result = json.loads(raw.decode('utf-8','strict'),object_pairs_hook=closed,parse_constant=invalid)
        if not isinstance(result,dict):
            raise ValueError('private recovery record is not an object')
        return result

    @staticmethod
    def valid_snapshot(value, *, mode=0o644, owner=0, link=False):
        if (not isinstance(value,dict) or set(value)!={'sha256','identity'}
                or not isinstance(value['sha256'],str) or not re.fullmatch('[0-9a-f]{64}',value['sha256'])
                or not isinstance(value['identity'],list) or len(value['identity'])!=9
                or any(type(item) is not int or item<0 for item in value['identity'])):
            raise ValueError('invalid closed recovery file snapshot')
        info = value['identity']
        if ((not stat.S_ISLNK(info[2]) if link else not stat.S_ISREG(info[2]))
                or info[3]!=owner or info[5]!=1 or (not link and stat.S_IMODE(info[2])!=mode)):
            raise ValueError('unsafe recovery file snapshot identity')
        return value

    @staticmethod
    def snapshot_info(snapshot):
        names = ('st_dev','st_ino','st_mode','st_uid','st_gid','st_nlink','st_size','st_mtime_ns','st_ctime_ns')
        return types.SimpleNamespace(**dict(zip(names,snapshot['identity'])))

    def current_database_snapshot(self, path):
        if path not in (self.database,self.database.with_name(self.database.name+'-wal'),self.database.with_name(self.database.name+'-shm')):
            raise ValueError('database lineage outside fixed database scope')
        return self.stream_database_snapshot(path)

    def stream_database_snapshot(self, path):
        self.parents(self.database.parent)
        self.directory(self.database.parent,owner=self.db_owner)
        if not self.exists(path):
            return None
        descriptor = os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
        try:
            before = os.fstat(descriptor)
            if (not stat.S_ISREG(before.st_mode) or before.st_nlink!=1 or before.st_uid!=self.db_owner
                    or before.st_gid!=self.db_group or stat.S_IMODE(before.st_mode)!=0o600
                    or before.st_size>16*1024*1024*1024):
                raise ValueError('unsafe stopped database lineage file')
            identity = self.file_snapshot(b'',before)['identity']
            digest,size,deadline = hashlib.sha256(),0,time.monotonic()+60
            while True:
                if time.monotonic()>deadline:
                    raise ValueError('stopped database lineage read exceeded deadline')
                block = os.read(descriptor,1024*1024)
                if not block:
                    break
                digest.update(block)
                size += len(block)
                if size>before.st_size:
                    raise ValueError('stopped database lineage grew while reading')
            if size!=before.st_size or self.file_snapshot(b'',os.fstat(descriptor))['identity']!=identity:
                raise ValueError('stopped database lineage changed while reading')
            return {'sha256':digest.hexdigest(),'identity':identity}
        finally:
            os.close(descriptor)

    def validate_database_lineage(self, *, preserve_restored=False):
        for target in (self.database,self.database.with_name(self.database.name+'-wal'),self.database.with_name(self.database.name+'-shm')):
            actual = self.current_database_snapshot(target)
            history = self.database_mutations.get(str(target),[])
            if preserve_restored and target!=self.database:
                # Initialization may recreate WAL/SHM. Finalization neither
                # removes nor replays them; ordinary owner/mode checks above
                # still apply, and the main restored inode remains bound.
                continue
            if history:
                latest = history[-1]
                preserved = (preserve_restored and target==self.database and actual is not None and latest['candidate']is not None
                             and actual['identity'][:6]==latest['candidate']['identity'][:6])
                if not (preserved or self.same_owned_snapshot(actual,latest['candidate']) or actual==latest['before']):
                    raise ValueError('database inode changed outside retained recovery intent')
            elif target==self.database and (actual is None or actual['identity'][:6]!=self.original_database_inode):
                raise ValueError('original database inode replaced outside transaction')

    def remove_database_sidecars(self):
        self.validate_database_lineage()
        before = {suffix:self.current_database_snapshot(self.database.with_name(self.database.name+suffix)) for suffix in ('-wal','-shm')}
        for suffix,value in before.items():
            if value is None:
                continue
            target = self.database.with_name(self.database.name+suffix)
            intent = {'kind':'database-remove','target':str(target),'stage':None,'before':value,'candidate':None}
            self.mutation_evidence(intent)
            self.database_mutations.setdefault(str(target),[]).append(intent)
            if self.current_database_snapshot(target)!=value:
                raise ValueError('database sidecar changed after durable remove intent')
            target.unlink()
            intent['applied'] = True
            self.sync_directory(self.database.parent)

    def remove_managed_file(self, target):
        before = self.validate_managed_file(target)
        if before is None:
            return
        intent = {'kind':'file-remove','target':str(target),'stage':None,'before':before,'candidate':None}
        self.mutation_evidence(intent)
        self.file_mutations.setdefault(str(target), []).append(intent)
        if self.current_file_snapshot(target) != before:
            raise ValueError('managed removal identity changed after durable intent')
        target.unlink()
        intent['applied'] = True
        self.sync_directory(target.parent)

    def pointer_snapshot(self, target):
        self.parents(target)
        info = target.lstat()
        if not stat.S_ISLNK(info.st_mode) or info.st_uid != 0 or info.st_nlink != 1:
            raise ValueError('untrusted production pointer')
        value = os.readlink(target)
        after = target.lstat()
        snapshot = self.file_snapshot(value.encode('utf-8'), info)
        if snapshot != self.file_snapshot(os.readlink(target).encode('utf-8'), after):
            raise ValueError('production pointer changed while reading')
        return snapshot

    def validate_pointer(self):
        actual = self.pointer_snapshot(self.current)
        if self.pointer_mutations:
            latest = self.pointer_mutations[-1]
            valid = self.same_owned_snapshot(actual, latest['candidate'])
            if not latest.get('applied'):
                valid = valid or actual == latest['before']
        else:
            valid = actual == self.original_pointer
        if not valid:
            raise ValueError('production pointer inode changed outside transaction; rollback refused')
        return actual

    def validate_restore_lineage(self):
        if hasattr(self, 'current'):
            self.validate_pointer()
            if hasattr(self,'previous_inventory') and self.code_inventory(pathlib.Path(self.previous))!=self.previous_inventory:
                raise ValueError('original retained code changed before rollback')
        self.validate_managed_file(self.marker)
        for name in self.original_units:
            self.validate_managed_file(self.path('/etc/systemd/system')/name)
        self.validate_managed_file(self.pending)

    def code_inventory(self, base):
        """Complete retained candidate identities; no links, mounts or specials."""
        self.parents(base)
        origin = self.directory(base)
        mounts = set()
        if sys.platform.startswith('linux'):
            with open('/proc/self/mountinfo', 'rb') as source:
                raw = source.read(4*1024*1024+1)
            if len(raw) > 4*1024*1024:
                raise ValueError('candidate mount inventory exceeds complete budget')
            for line in raw.decode('utf-8', 'strict').splitlines():
                fields = line.split(' ')
                if len(fields) < 10 or '-' not in fields:
                    raise ValueError('unverifiable candidate mount inventory')
                mounts.add(pathlib.Path(re.sub(r'\\([0-7]{3})', lambda m:chr(int(m[1],8)), fields[4])))
        if any(point == base or base in point.parents for point in mounts):
            raise ValueError('mounted candidate code tree; refuse copy')
        values, pending, total = {}, [base], 0
        deadline = time.monotonic()+60
        while pending:
            path = pending.pop()
            info = path.lstat()
            if not stat.S_ISDIR(info.st_mode) and not stat.S_ISREG(info.st_mode):
                raise ValueError('linked, special or oversized candidate code file')
            if len(values) >= 10000 or time.monotonic() > deadline or info.st_dev != origin.st_dev or info.st_uid != 0 or info.st_mode&0o022:
                raise ValueError('candidate tree exceeds identity or complete copy budget')
            relative = str(path.relative_to(base))
            if stat.S_ISDIR(info.st_mode):
                values[relative] = {'kind':'directory','mode':stat.S_IMODE(info.st_mode),'identity':self.file_snapshot(b'',info)['identity']}
                with os.scandir(path) as entries:
                    for entry in entries:
                        pending.append(path/entry.name)
                        if len(pending)+len(values)>10000:
                            raise ValueError('candidate directory exceeds complete entry budget')
                continue
            if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_size > 256*1024*1024:
                raise ValueError('linked, special or oversized candidate code file')
            total += info.st_size
            if total > 1024*1024*1024:
                raise ValueError('candidate code exceeds one GiB copy budget')
            descriptor = os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
            try:
                before = os.fstat(descriptor)
                identity = self.file_snapshot(b'',info)['identity']
                if self.file_snapshot(b'',before)['identity'] != identity:
                    raise ValueError('candidate code changed before inventory read')
                digest, size = hashlib.sha256(), 0
                while True:
                    if time.monotonic() > deadline:
                        raise ValueError('candidate code inventory exceeded deadline')
                    block = os.read(descriptor,1024*1024)
                    if not block:
                        break
                    digest.update(block)
                    size += len(block)
                    if size > info.st_size:
                        raise ValueError('candidate code grew during inventory')
                if size != info.st_size or self.file_snapshot(b'',os.fstat(descriptor))['identity'] != identity:
                    raise ValueError('candidate code changed during complete inventory')
                values[relative] = {'kind':'file','mode':stat.S_IMODE(info.st_mode),'size':size,'sha256':digest.hexdigest(),'identity':identity}
            finally:
                os.close(descriptor)
        return values

    def retain_candidate_plan(self):
        """Retain a verified, fsynced complete candidate before live mutations.

        Explicit recover/recover-check reconstructs bounded transactions from
        these inputs. No interrupted transaction is silently replayed.
        """
        self.parents(self.backup)
        backup_info = self.directory(self.backup, private=True)
        destination = self.backup/'candidate'
        plan_path = self.backup/'recovery-plan.json'
        if self.exists(destination) or self.exists(plan_path):
            raise ValueError('retained candidate or recovery plan must not be replaced')
        original = self.code_inventory(self.release)
        copy_deadline = time.monotonic()+60
        for relative,value in sorted(original.items(),key=lambda pair:(len(pathlib.PurePath(pair[0]).parts),pair[0])):
            if time.monotonic()>copy_deadline:
                raise ValueError('retained candidate copy exceeded deadline')
            target = destination if relative == '.' else destination/relative
            if value['kind'] == 'directory':
                target.mkdir(mode=value['mode'])
                target.chmod(value['mode'])
                continue
            source = self.release/relative
            descriptor = os.open(source,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
            output = None
            try:
                if self.file_snapshot(b'',os.fstat(descriptor))['identity'] != value['identity']:
                    raise ValueError('candidate source inode changed before retained copy')
                output = os.open(target,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,value['mode'])
                os.fchmod(output,value['mode'])
                digest, size = hashlib.sha256(), 0
                with os.fdopen(output,'wb',closefd=False) as stream:
                    while True:
                        if time.monotonic()>copy_deadline:
                            raise ValueError('retained candidate copy exceeded deadline')
                        block = os.read(descriptor,1024*1024)
                        if not block:
                            break
                        digest.update(block)
                        size += len(block)
                        if size > value['size']:
                            raise ValueError('candidate source grew during retained copy')
                        stream.write(block)
                    stream.flush()
                    os.fsync(output)
                if (size != value['size'] or digest.hexdigest() != value['sha256']
                        or self.file_snapshot(b'',os.fstat(descriptor))['identity'] != value['identity']):
                    raise ValueError('candidate source content changed during retained copy')
            finally:
                os.close(descriptor)
                if output is not None:
                    os.close(output)
        for relative,value in sorted(original.items(),key=lambda pair:len(pathlib.PurePath(pair[0]).parts),reverse=True):
            if value['kind']=='directory':
                self.sync_directory(destination if relative=='.' else destination/relative)
        self.sync_directory(self.backup)
        candidate = self.code_inventory(destination)
        content = lambda inventory:{name:{k:v for k,v in record.items() if k!='identity'} for name,record in inventory.items()}
        if content(candidate) != content(original) or self.code_inventory(self.release) != original:
            raise ValueError('retained candidate is not the complete original verified payload')
        self.run_command(str(destination/'verify-release.sh'),str(destination))
        if len(self.locks) != 2:
            raise ValueError('durable plan requires both exact held transaction leases')
        leases = []
        for descriptor in self.locks:
            info = os.fstat(descriptor)
            if info.st_uid != 0 or not stat.S_ISREG(info.st_mode) or stat.S_IMODE(info.st_mode)!=0o600 or info.st_nlink!=1:
                raise ValueError('durable plan lease identity is unsafe')
            leases.append([info.st_dev,info.st_ino])
        process = pathlib.Path('/proc/self/stat').read_text()
        ticks = int(process[process.rindex(') ')+2:].split()[19])
        boot = pathlib.Path('/proc/sys/kernel/random/boot_id').read_text().strip()
        if ticks <= 0 or not re.fullmatch(r'[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}',boot):
            raise ValueError('durable plan owner identity unavailable')
        plan = {'format':1,'layout':self.layout,'version':self.version,'backup_device':backup_info.st_dev,'backup_inode':backup_info.st_ino,
                'owner':{'pid':os.getpid(),'start_ticks':ticks,'boot_id':boot,'leases':leases},'services':self.states,'nginx_pid':self.nginx_pid,
                'database_owner':self.db_owner,'database_group':self.db_group,'database_inode':self.original_database_inode,'candidate':candidate,
                'original_units':{name:self.file_snapshot(*value) if value is not None else None for name,value in self.original_units.items()},
                'original_marker':self.managed_file_original(self.marker)}
        if self.layout=='production':
            self.previous_inventory = self.code_inventory(pathlib.Path(self.previous))
            plan.update(previous=self.previous,original_pointer=self.original_pointer,previous_inventory=self.previous_inventory)
        else:
            plan.update(original_trees=self.original_tree_identities)
        raw = (json.dumps(plan,sort_keys=True)+'\n').encode()
        if len(raw)>8*1024*1024:
            raise ValueError('recovery plan exceeds complete metadata budget')
        self.atomic(plan_path,raw,0o600)
        self.private_candidate = destination

    def sync_directory(self, path):
        path = self.scoped_path(path)
        descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)

    def exists(self, path):
        path = self.scoped_path(path)
        return path.exists() or path.is_symlink()

    def state(self, unit):
        raw = self.run_command('/usr/bin/systemctl', 'show', unit, '--property=LoadState,ActiveState,SubState,UnitFileState')
        values = raw.splitlines()
        if len(raw.encode('utf8')) > 4096 or len(values) != 4 or any('=' not in line for line in values):
            raise ServiceStateFailure(unit, raw, {})
        result = dict(line.split('=', 1) for line in values)
        if set(result) != {'LoadState', 'ActiveState', 'SubState', 'UnitFileState'} or result['LoadState'] != 'loaded' or result['ActiveState'] not in ('active', 'inactive') or result['UnitFileState'] not in ('enabled', 'disabled', 'static', 'indirect', 'enabled-runtime'):
            raise ServiceStateFailure(unit, raw, result)
        return result

    @contextlib.contextmanager
    def connect(self):
        # SQLite must never be the first process to follow an unsafe database
        # or WAL/SHM link. Contents are read by SQLite, not loaded into memory.
        for path in (self.database, self.database.with_name(self.database.name+'-wal'), self.database.with_name(self.database.name+'-shm')):
            if self.exists(path):
                info = path.lstat()
                if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_uid != self.db_owner or stat.S_IMODE(info.st_mode) != 0o600:
                    raise ValueError('unsafe database or journal identity')
        connection = sqlite3.connect(self.database.as_uri()+'?mode=ro', uri=True, timeout=3)
        connection.execute('PRAGMA query_only=ON')
        deadline = time.monotonic()+10
        connection.set_progress_handler(lambda: int(time.monotonic()>deadline), 1000)
        try:
            yield connection
        finally:
            connection.close()

    def queue_check(self):
        with self.connect() as connection:
            if connection.execute('PRAGMA quick_check').fetchone() != ('ok',):
                raise ValueError('database integrity check failed')
            for table in QUEUES:
                if connection.execute(f"SELECT count(*) FROM {table} WHERE state IN ('queued','running')").fetchone() != (0,):
                    raise ValueError('wait for active panel, runtime, database or certificate jobs before upgrading')
            if connection.execute("SELECT count(*) FROM sqlite_master WHERE type='table' AND name='disk_host_jobs'").fetchone() == (1,):
                if connection.execute("SELECT count(*) FROM disk_host_jobs WHERE state IS NULL OR state NOT IN ('queued','dispatching','running','cancel_requested','uncertain','complete','partial','canceled','failed')").fetchone() != (0,):
                    raise ValueError('original host disk task state is invalid; not a drain proof')
                if connection.execute("SELECT count(*) FROM disk_host_jobs WHERE state IN ('queued','dispatching','running','cancel_requested','uncertain')").fetchone() != (0,):
                    raise ValueError('reconcile original host disk tasks before upgrading; cancellation intent is not exit proof')
            if connection.execute("SELECT count(*) FROM sqlite_master WHERE type='table' AND name='platform_maintenance_operations'").fetchone() == (1,):
                if connection.execute("SELECT count(*) FROM platform_maintenance_operations WHERE state IS NULL OR state NOT IN ('dispatched','needs_attention','completed','failed')").fetchone() != (0,):
                    raise ValueError('platform maintenance state is invalid; upgrade must not treat unknown work as complete')
                if connection.execute("SELECT count(*) FROM platform_maintenance_operations WHERE state IN ('dispatched','needs_attention')").fetchone() != (0,):
                    raise ValueError('reconcile original platform maintenance commands before upgrading; no automatic replay')
        # Execute only the already verified root-controlled candidate. This
        # fixed-path reader starts no Service or worker and edits no records.
        # Repeated at preflight, under the leases, after strict writer stop,
        # after candidate readiness and before any database rollback.
        try:
            self.run_command(str(self.release/'bin/panel-executor'), '--check-program-upgrade-queues', timeout=10)
        except CommandFailure as error:
            # A later read may succeed and cannot explain this ORIGINAL refusal.
            # Preserve that exact child's bounded output only in the already
            # owned private transaction; ordinary preflight remains write-free.
            self.record_native_queue_refusal(error)
            raise

    def preflight_admission_is_readonly(self):
        if (self.layout not in ('production','development')
                or self.backup is not None or self.pending_created or self.stopping
                or self.changed or len(self.locks) > 1):
            return False
        try:
            if hasattr(self, 'pending') and self.exists(self.pending):
                return False
            if self.locks:
                # A single arbitrary/runtime descriptor is NOT a release
                # serialization lease. Revalidate its exact named identity.
                name = (self.releases/'.release.lock' if self.layout == 'production'
                        else self.base/'.development-update.lock')
                self.parents(name)
                named, held = name.lstat(), os.fstat(self.locks[0])
                if any(not stat.S_ISREG(s.st_mode) or s.st_uid != 0 or s.st_nlink != 1
                       or stat.S_IMODE(s.st_mode) != 0o600 for s in (named, held)):
                    return False
                if (named.st_dev, named.st_ino) != (held.st_dev, held.st_ino):
                    return False
        except (OSError, ValueError, AttributeError):
            return False
        return True

    def preflight_queue_check(self):
        # Admission ONLY, before any backup, pending marker, runtime lease or
        # program change. Up to two further bounded READS allow an already
        # queued periodic recovery to finish naturally. No worker/installer
        # replay, service action, failed reset or queue exception is added.
        # Every read retains all original SQLite/filesystem/native checks and
        # their deadlines/capacities. Mutation/recovery paths use queue_check
        # directly and can NEVER use this admission protocol.
        for attempt in range(3):
            try:
                return self.queue_check()
            except CommandFailure as error:
                if (attempt == 2 or not self.preflight_admission_is_readonly()
                        or not original_periodic_recovery_can_be_observed_again(error)):
                    raise
                print(json.dumps({'format':1, 'kind':'native-periodic-recovery-admission',
                                  'operation':'periodic-database-recovery',
                                  'readonly_recheck':attempt+1, 'maximum_readonly_rechecks':2,
                                  'mutating_installer_replay':False,
                                  'original_observation':public_queue_refusal_diagnostic(error)},
                                 sort_keys=True), file=sys.stderr)
                time.sleep(0.25)

    def record_native_queue_refusal(self, error):
        if self.backup is None:
            return
        if (not isinstance(error, CommandFailure) or error.program != 'panel-executor'
                or type(error.code) is not int or error.code == 0
                or self.backup != self.backup_path):
            raise ValueError('native queue evidence lacks original command or owned transaction')
        self.parents(self.backup)
        self.directory(self.backup, private=True)
        value = {'format': 1, 'kind': 'native-program-queue-refusal', 'version': self.version,
                 'phase': getattr(self, 'last_phase', 'unknown'), 'exit': error.code,
                 'captured_at': time.time(), 'command': 'panel-executor --check-program-upgrade-queues',
                 'output': error.output, 'no_retry_or_queue_exemption': True}
        target = self.backup / ('native-queue-refusal-' + uuid.uuid4().hex + '.json')
        descriptor = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(descriptor, 'wb') as output:
            os.fchmod(output.fileno(), 0o600)
            output.write((json.dumps(value, sort_keys=True) + '\n').encode())
            output.flush()
            os.fsync(output.fileno())
        self.sync_directory(self.backup)

    def start_guard(self, install=False):
        location = pathlib.Path(__file__).with_name('start-guard-install.py')
        spec = importlib.util.spec_from_file_location('panel_fixed_start_guard', location)
        guard = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(guard)
        if install:
            guard.install(self)
            records = []
            for path, data, mode in guard.inventory(self):
                info = path.lstat()
                records.append({'path':str(path),'sha256':hashlib.sha256(data).hexdigest(),'mode':mode,'device':info.st_dev,'inode':info.st_ino})
            self.atomic(self.backup/'startup-interlock.json', (json.dumps({'format':1,'retained_on_rollback':True,'files':records}, sort_keys=True)+'\n').encode(), 0o600)
        else:
            guard.inventory(self)

    def native_prerequisite_record(self, source):
        return {'format':1, 'version':self.version,
                'policy':'create-missing-retain-on-rollback',
                'helpers':{name:hashlib.sha256(self.file(source/name,mode=0o644,limit=128*1024)[0]).hexdigest()
                           for name in NATIVE_PREREQUISITES}}

    def native_prerequisites(self, *, create=False):
        # Only the production transaction provisions these fixed namespaces.
        # No application, account, rule feed, config or service is installed.
        # Recovery never removes them: another valid job may have used them.
        source = self.release
        if create:
            if (self.layout!='production' or len(self.locks)!=2 or self.backup is None
                    or getattr(self,'last_phase',None)!='prepared' or self.stopping or self.changed):
                raise ValueError('native prerequisites require the prepared production transaction')
            source = self.private_candidate
        record = self.native_prerequisite_record(source)
        # Check every helper before creating anything. Each create also checks
        # existing paths and refuses to repair foreign ownership/mode/links.
        for name in NATIVE_PREREQUISITES:
            self.run_command('/usr/bin/python3',str(source/name),'check','--root',str(self.root))
        if not create:
            return
        target = self.backup/'native-prerequisites.json'
        if self.exists(target):
            raise ValueError('native prerequisite intent must not be overwritten')
        self.atomic(target,(json.dumps(record,sort_keys=True)+'\n').encode(),0o600)
        for name in NATIVE_PREREQUISITES:
            self.run_command('/usr/bin/python3',str(source/name),'create','--root',str(self.root))

    def preflight(self):
        self.parents(self.release)
        self.directory(self.release)
        payload_size = self.payload_size()
        self.file(self.release/'verify-release.sh', mode=0o755, limit=65536)
        self.run_command(str(self.release/'verify-release.sh'), str(self.release))
        fields = dict(line.split('=', 1) for line in self.file(self.release/'RELEASE')[0].decode('ascii').splitlines())
        if set(fields) != {'PANEL_FORMAT', 'PANEL_VERSION', 'PANEL_OS', 'PANEL_ARCH'} or fields['PANEL_FORMAT'] != '1' or fields['PANEL_OS'] != 'linux' or not VERSION.fullmatch(fields['PANEL_VERSION']) or fields['PANEL_ARCH'] not in ('amd64', 'arm64'):
            raise ValueError('invalid upgrade metadata')
        self.version = fields['PANEL_VERSION']
        if fields['PANEL_ARCH'] != self.run_command('/usr/bin/dpkg', '--print-architecture'):
            raise ValueError('upgrade architecture mismatch')
        self.native_prerequisites()
        self.current = self.path('/opt/panel/current')
        self.marker = self.path('/etc/panel-release')
        self.releases = self.path('/opt/panel/releases')
        self.pending = self.releases/'.program-upgrade.pending'
        self.database = self.path('/var/lib/panel/panel.db')
        for directory in (self.releases, self.marker.parent, self.path('/etc/systemd/system'), self.path('/var/backups/panel/system'), self.path('/var/lib/panel-executor')):
            self.parents(directory)
            self.directory(directory, private=directory == self.path('/var/backups/panel/system'))
        current_info = self.current.lstat()
        if not stat.S_ISLNK(current_info.st_mode) or current_info.st_uid != 0:
            raise ValueError('ordinary upgrade requires an owned production release pointer')
        self.previous = os.readlink(self.current)
        self.original_pointer = self.pointer_snapshot(self.current)
        previous_path = pathlib.Path(self.previous)
        if previous_path.parent != self.releases or not VERSION.fullmatch(previous_path.name):
            raise ValueError('production release pointer is outside retained releases')
        self.directory(previous_path)
        self.run_command(str(self.release/'verify-release.sh'), str(previous_path))
        self.marker_bytes, self.marker_info = self.file(self.marker, mode=0o644, limit=256)
        expected_marker = 'version='+previous_path.name+'\narch='+fields['PANEL_ARCH']+'\n'
        if self.marker_bytes.decode('ascii') != expected_marker:
            raise ValueError('production marker and current release disagree')
        self.destination = self.releases/self.version
        for path in (self.destination, self.destination.with_name(self.version+'.tmp'), self.current.with_name('current.new'), self.marker.with_name(self.marker.name+'.upgrade-new'), self.releases/'.program-upgrade.pending'):
            if self.exists(path):
                raise ValueError('retained upgrade target or interrupted transaction exists; inspect it before retrying')
        database_info = self.database.lstat()
        self.original_database_inode = self.file_snapshot(b'',database_info)['identity'][:6]
        self.db_owner, self.db_group = database_info.st_uid, database_info.st_gid
        if str(self.db_owner) != self.run_command('/usr/bin/id', '-u', 'panel') or str(self.db_group) != self.run_command('/usr/bin/id', '-g', 'panel'):
            raise ValueError('database does not belong to the fixed panel identity')
        self.parents(self.database.parent)
        self.directory(self.database.parent, owner=self.db_owner)
        if not stat.S_ISREG(database_info.st_mode) or database_info.st_nlink != 1 or stat.S_IMODE(database_info.st_mode) != 0o600 or self.db_owner == 0:
            raise ValueError('upgrade requires a private panel-owned ordinary database')
        if database_info.st_size > 16*1024*1024*1024:
            raise ValueError('panel database exceeds the bounded upgrade backup budget')
        for directory, required in ((self.releases, payload_size), (self.path('/var/backups/panel/system'), payload_size+database_info.st_size*2), (self.database.parent, database_info.st_size)):
            if shutil.disk_usage(directory).free < required+32*1024*1024:
                raise ValueError('insufficient free space for candidate, private backup and rollback')
        self.preflight_queue_check()
        self.backup_path = self.path('/var/backups/panel/system')/('production-'+self.version)
        if self.exists(self.backup_path):
            raise ValueError('retained production backup exists; select a new release')
        self.units = sorted((self.release/'systemd').iterdir())
        if not self.units or len(self.units) > 64:
            raise ValueError('upgrade unit inventory invalid')
        for source in self.units:
            if not UNIT.fullmatch(source.name):
                raise ValueError('unrecognized production unit')
            self.file(source, mode=0o644, limit=65536)
            target = self.path('/etc/systemd/system')/source.name
            if self.exists(target):
                self.original_units[source.name] = self.file(target, mode=0o644, limit=65536)
            else:
                self.original_units[source.name] = None
            if self.exists(target.with_name(target.name+'.upgrade-new')):
                raise ValueError('retained unit stage exists')
        for unit in PROGRAMS+(TIMER, 'panel-mysql-overwrite-recovery.service', 'nginx.service'):
            self.states[unit] = self.state(unit)
        self.nginx_pid = self.run_command('/usr/bin/systemctl', 'show', 'nginx.service', '--property=MainPID', '--value')
        if not self.nginx_pid.isascii() or not self.nginx_pid.isdigit():
            raise ValueError('unverifiable gateway process identity')
        if any(self.states[unit]['ActiveState'] != 'active' for unit in PROGRAMS):
            raise ValueError('ordinary upgrade requires all four program services active; stopped programs are not automatically started')
        if self.states['panel-mysql-overwrite-recovery.service']['ActiveState'] != 'inactive':
            raise ValueError('database replacement recovery is active; wait before upgrading')
        if self.run_command('/usr/bin/systemctl', 'show', 'panel.service', '--property=User', '--value') != 'panel':
            raise ValueError('unexpected production panel owner')
        self.run_command('/usr/sbin/nginx', '-t')
        self.start_guard()

    def lock(self, path, create=False):
        self.parents(path)
        flags = os.O_RDWR | os.O_NOFOLLOW | os.O_NONBLOCK
        if create and not self.exists(path):
            descriptor = os.open(path, flags | os.O_CREAT | os.O_EXCL, 0o600)
            os.fchmod(descriptor, 0o600)
        else:
            descriptor = os.open(path, flags)
        try:
            info = os.fstat(descriptor)
            allowed_modes = (0o600, 0o644) if create else (0o600,)
            if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_uid != 0 or stat.S_IMODE(info.st_mode) not in allowed_modes:
                raise ValueError('unsafe production upgrade lock')
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
            # Earlier installers created the trusted release lock with 0644.
            # Upgrade that exact locked descriptor, never truncate or follow it.
            if create:
                os.fchmod(descriptor, 0o600)
            self.locks.append(descriptor)
        except BaseException:
            os.close(descriptor)
            raise

    def journal(self, phase):
        record = {'format': 1, 'version': self.version, 'previous': self.previous, 'phase': phase, 'services': self.states}
        self.atomic(self.backup/'transaction.json', (json.dumps(record, sort_keys=True)+'\n').encode(), 0o600)
        self.last_phase = phase

    def create_pending(self):
        self.pending_bytes = ('version='+self.version+'\n').encode('ascii')
        self.atomic(self.pending,self.pending_bytes,0o644,exclusive=True)

    def remove_pending(self):
        if not self.pending_created:
            return
        raw, info = self.file(self.pending, mode=0o644, limit=2048)
        if raw != self.pending_bytes or (info.st_dev, info.st_ino) != (self.pending_identity.st_dev, self.pending_identity.st_ino):
            raise ValueError('upgrade marker identity changed; preserve it for inspection')
        self.remove_managed_file(self.pending)
        self.pending_created = False

    @contextlib.contextmanager
    def statistics_writer_stop_barrier(self):
        # Legacy executors did not drain their SQLite worker on SIGTERM. Hold
        # the SAME existing cross-process statistics/WAF lease until all fixed
        # program writers are proved stopped. This does not recover a database,
        # install an application, create/chmod a lock or change service budgets.
        module = self.path('/etc/panel/security-apps/modules/website-statistics-v2')
        for name, private in (('/etc', False), ('/etc/panel', False),
                              ('/etc/panel/security-apps', False),
                              ('/etc/panel/security-apps/modules', True),
                              ('/etc/panel/security-apps/modules/website-statistics-v2', True)):
            path = self.path(name)
            if not self.exists(path):
                yield
                return
            self.directory(path, private=private)
        lock = self.path('/etc/panel/security-apps/waf-configuration.lock')
        self.parents(lock)
        descriptor = os.open(lock, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
        try:
            info = os.fstat(descriptor)
            def identity(value):
                if (not stat.S_ISREG(value.st_mode) or value.st_uid != 0 or value.st_nlink != 1
                        or stat.S_IMODE(value.st_mode) != 0o600 or value.st_size != 0):
                    raise ValueError('unsafe existing statistics writer-stop lease')
                return (value.st_dev, value.st_ino, value.st_mode, value.st_uid, value.st_gid, value.st_nlink)
            original = identity(info)
            deadline = time.monotonic() + 8
            while True:
                try:
                    fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    break
                except BlockingIOError:
                    if time.monotonic() >= deadline:
                        raise ValueError('statistics writer-stop lease busy; no program stopped')
                    time.sleep(0.05)
            if identity(os.fstat(descriptor)) != original or identity(lock.lstat()) != original:
                raise ValueError('statistics writer-stop lease replaced during acquisition')
            # Parent substitution cannot make a detached old lock authoritative.
            self.parents(lock)
            self.parents(module)
            self.directory(module, private=True)
            yield
            if identity(os.fstat(descriptor)) != original or identity(lock.lstat()) != original:
                raise ValueError('statistics writer-stop lease changed during stop')
        finally:
            os.close(descriptor)

    def stop_writers(self):
        with self.statistics_writer_stop_barrier():
            self.stopping = True
            self._stop_writers_under_statistics_barrier()

    def _stop_writers_under_statistics_barrier(self):
        self.run_command('/usr/bin/systemctl', 'stop', *reversed(PROGRAMS))
        stopped = {unit:self.stopped_program(unit) for unit in PROGRAMS}
        self.no_program_jobs()
        failed = [unit for unit in PROGRAMS if stopped[unit]['ActiveState'] == 'failed']
        if failed:
            # systemctl stop can leave a failed unit even with no remaining
            # process or cgroup (for example a killed ExecStartPre). Never
            # confuse that with running writers or relax ordinary preflight.
            # Preserve failure evidence before clearing only our fixed units.
            if self.backup is None or self.failed_stop_snapshots >= 8:
                raise ValueError('failed stop lacks bounded private transaction evidence')
            self.parents(self.backup)
            self.directory(self.backup, private=True)
            self.failed_stop_snapshots += 1
            target = self.backup/('stopped-failed-programs-'+str(self.failed_stop_snapshots)+'.json')
            if self.exists(target):
                raise ValueError('retained failed stop evidence must not be replaced')
            self.atomic(target, (json.dumps({'format':1,'services':stopped},sort_keys=True)+'\n').encode(), 0o600)
            if any(self.stopped_program(unit) != stopped[unit] for unit in PROGRAMS):
                raise RuntimeError('stopped writer evidence changed before failed state normalization')
            self.no_program_jobs()
            self.run_command('/usr/bin/systemctl', 'reset-failed', *failed)
        for unit in PROGRAMS:
            if self.stopped_program(unit)['ActiveState'] != 'inactive':
                raise RuntimeError('program writer did not stop; database must not be replaced')
        self.no_program_jobs()

    def stopped_program(self, unit):
        if unit not in PROGRAMS:
            raise ValueError('stopped writer check outside fixed program scope')
        raw = self.run_command('/usr/bin/systemctl', 'show', unit, '--property=LoadState,ActiveState,SubState,UnitFileState,MainPID,ControlPID,ControlGroup,Result')
        names = {'LoadState','ActiveState','SubState','UnitFileState','MainPID','ControlPID','ControlGroup','Result'}
        if len(raw) > 16384:
            raise ValueError('stopped writer evidence exceeds budget')
        record = {}
        for line in raw.splitlines():
            fields = line.split('=', 1)
            if len(fields) != 2 or fields[0] not in names or fields[0] in record:
                raise ValueError('unknown or duplicate stopped writer property')
            record[fields[0]] = fields[1]
        if set(record) != names or record['LoadState'] != 'loaded' or record['UnitFileState'] not in ('enabled','disabled','static','indirect','enabled-runtime'):
            raise ValueError('unsafe stopped writer unit identity')
        if (record['ActiveState'],record['SubState']) not in (('inactive','dead'),('failed','failed')) or record['MainPID'] != '0' or record['ControlPID'] != '0' or record['ControlGroup'] != '':
            raise RuntimeError('program writer has processes, cgroup or a transitional state; database must not be replaced')
        if record['Result'] not in ('success','exit-code','signal','core-dump','timeout','watchdog','oom-kill','start-limit-hit','resources','protocol','exec-condition'):
            raise ValueError('unsupported stopped writer result')
        return record

    def no_program_jobs(self):
        raw = self.run_command('/usr/bin/systemctl', 'list-jobs', '--no-legend', '--no-pager')
        lines = raw.splitlines()
        if len(raw) > 1024*1024 or len(lines) > 4096:
            raise ValueError('systemd job inventory exceeds complete budget')
        for line in lines:
            fields = line.split()
            if len(fields) != 4 or not fields[0].isascii() or not fields[0].isdigit():
                raise ValueError('unverifiable systemd job inventory')
            if fields[1] in PROGRAMS+(TIMER,'panel-mysql-overwrite-recovery.service'):
                raise RuntimeError('program or database recovery job remains scheduled')

    def release_runtime(self):
        if len(self.locks) == 2:
            os.close(self.locks.pop())
        elif len(self.locks) != 1:
            raise ValueError('program start lacks exact release/runtime lease state')

    def start_previous_state(self):
        self.release_runtime()
        self.authorize_startup()
        self.run_command('/usr/bin/systemctl', 'start', *PROGRAMS)

    def timer_declaration(self):
        info=self.directory(self.backup,private=True)
        return {'format':1,'version':self.version,'backup_device':info.st_dev,
                'backup_inode':info.st_ino,'original_timer':self.states[TIMER]}

    def validate_timer_declaration(self,value):
        expected=self.timer_declaration()
        if (not isinstance(value,dict) or set(value)!=set(expected)
                or any(type(value[name])is not int for name in ('format','backup_device','backup_inode'))
                or not isinstance(value['version'],str) or not isinstance(value['original_timer'],dict)
                or value!=expected):
            raise ValueError('closed deferred timer receipt is not bound to this backup')

    def defer_timer(self):
        # The database recovery guard deliberately rejects EVERY maintenance
        # marker. Starting its timer earlier creates failed native jobs and
        # makes the strict queue check correctly refuse the transaction.
        # Declare the timer protocol durably before changing its activity.
        declaration=self.timer_declaration()
        path=self.backup/'timer-deferred.json'
        if self.exists(path):
            self.validate_timer_declaration(self.read_record(path))
        else:
            self.atomic(path,(json.dumps(declaration,sort_keys=True)+'\n').encode(),0o600)
        self.timer_deferred=True

    def stop_timer(self):
        self.run_command('/usr/bin/systemctl','stop',TIMER)
        if self.state(TIMER)['ActiveState']!='inactive':
            raise RuntimeError('database timer did not stop')

    def verify_original_activity(self):
        for unit in PROGRAMS+(TIMER,'nginx.service'):
            current=self.state(unit)
            expected=('inactive'if unit==TIMER and self.pending_created and self.timer_deferred
                      else self.states[unit]['ActiveState'])
            if current['ActiveState']!=expected or current['UnitFileState']!=self.states[unit]['UnitFileState']:
                raise RuntimeError('original service activity or enablement changed')

    def restore_timer(self):
        if self.pending_created or self.exists(self.pending) or not self.timer_deferred:
            raise ValueError('database timer cannot resume before owned maintenance cleanup')
        receipt=self.backup/'timer-restored.json'
        if self.exists(receipt):
            raise ValueError('completed timer restoration must never be replayed')
        current=self.state(TIMER)
        expected=self.states[TIMER]
        if current['UnitFileState']!=expected['UnitFileState']:
            raise ValueError('database timer enablement changed outside transaction')
        if current['ActiveState']=='inactive' and expected['ActiveState']=='active':
            self.run_command('/usr/bin/systemctl','start',TIMER)
        self.verify_original_activity()
        self.atomic(receipt,(json.dumps(self.timer_declaration(),sort_keys=True)+'\n').encode(),0o600)

    def wait_readiness(self):
        # systemctl start confirms the service job, not an HTTP listener.
        # Keep this owner's release lease/startup authorization while waiting;
        # never remove maintenance or replay a restored DB to hide a slow start.
        # Only transient command failures/timeouts retry, at most 30 attempts.
        for attempt in range(30):
            try:
                self.run_command('/usr/bin/curl', '-fsS', '--max-time', '2',
                                 'http://127.0.0.1:19100/api/ready', timeout=3)
                return
            except (RuntimeError, subprocess.TimeoutExpired):
                if attempt == 29:
                    raise
                time.sleep(1)

    def startup_program_directory(self):
        target = pathlib.Path(os.readlink(self.current))
        if target.parent != self.releases or not VERSION.fullmatch(target.name):
            raise ValueError('startup program reference outside retained releases')
        self.directory(target)
        return target/'bin'

    def authorize_startup(self):
        if not self.pending_created or not self.locks:
            raise ValueError('program start lacks owned transaction marker or release lease')
        raw, info = self.file(self.pending, mode=0o644, limit=2048)
        if raw != self.pending_bytes or (info.st_dev, info.st_ino) != (self.pending_identity.st_dev, self.pending_identity.st_ino):
            raise ValueError('startup marker changed outside this transaction')
        lease = os.fstat(self.locks[0])
        if lease.st_uid != 0 or stat.S_IMODE(lease.st_mode) != 0o600 or lease.st_nlink != 1 or not stat.S_ISREG(lease.st_mode):
            raise ValueError('startup release lease identity invalid')
        process = pathlib.Path('/proc/self/stat').read_text()
        suffix = process[process.rindex(') ')+2:].split()
        ticks = int(suffix[19])
        boot = pathlib.Path('/proc/sys/kernel/random/boot_id').read_text().strip()
        if ticks <= 0 or not re.fullmatch(r'[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}', boot):
            raise ValueError('startup owner boot identity unavailable')
        programs = self.startup_program_directory()
        digests = {name:hashlib.sha256(self.file(programs/name, mode=0o755, limit=256*1024*1024)[0]).hexdigest() for name in ('panel', 'panel-executor')}
        record = {'format':2, 'version':self.version, 'pid':os.getpid(), 'start_ticks':ticks, 'boot_id':boot, 'lock_device':lease.st_dev, 'lock_inode':lease.st_ino, 'phase':'program-start', 'panel_sha256':digests['panel'], 'executor_sha256':digests['panel-executor']}
        self.pending_bytes = (json.dumps(record, sort_keys=True)+'\n').encode('ascii')
        self.atomic(self.pending, self.pending_bytes, 0o644)
        self.pending_identity = self.pending.lstat()

    def switch(self, previous):
        target = pathlib.Path(previous)
        if target.parent != self.releases or not VERSION.fullmatch(target.name):
            raise ValueError('production switch outside retained releases')
        before = self.validate_pointer()
        # A killed process can leave its stage behind. Never remove or reuse
        # that path; each replacement binds a new exclusively created link.
        temporary = self.current.with_name('.program-upgrade-current-'+uuid.uuid4().hex)
        os.symlink(previous, temporary)
        self.sync_directory(self.current.parent)
        candidate = self.pointer_snapshot(temporary)
        intent = {'kind':'pointer-replace','target':str(self.current),'stage':str(temporary),'before':before,'candidate':candidate}
        self.mutation_evidence(intent)
        self.pointer_mutations.append(intent)
        if self.pointer_snapshot(self.current) != before or self.pointer_snapshot(temporary) != candidate:
            raise ValueError('production pointer changed after durable intent')
        os.replace(temporary, self.current)
        intent['applied'] = True
        self.sync_directory(self.current.parent)

    @staticmethod
    def stable_inventory(inventory):
        return {name:{**record,'identity':record['identity'][:-1]} for name,record in inventory.items()}

    def retain_production_stage(self, stage):
        inventory = self.code_inventory(stage)
        # copytree and checksum success alone do not establish persistence.
        for name,value in inventory.items():
            if value['kind']=='file':
                path = stage/name
                descriptor = os.open(path,os.O_RDONLY|os.O_NOFOLLOW)
                try:
                    if self.file_snapshot(b'',os.fstat(descriptor))['identity']!=value['identity']:
                        raise ValueError('production stage changed before durable publication')
                    os.fsync(descriptor)
                finally:
                    os.close(descriptor)
        for name,value in sorted(inventory.items(),key=lambda pair:len(pathlib.PurePath(pair[0]).parts),reverse=True):
            if value['kind']=='directory':
                self.sync_directory(stage if name=='.' else stage/name)
        self.sync_directory(stage.parent)
        if self.code_inventory(stage)!=inventory:
            raise ValueError('production stage changed during durable publication')
        target = self.backup/'production-stage.json'
        if self.exists(target):
            raise ValueError('retained production stage receipt must not be overwritten')
        self.atomic(target,(json.dumps({'format':1,'version':self.version,'inventory':inventory},sort_keys=True)+'\n').encode(),0o600)

    def backup_database_snapshot(self, name='panel.db'):
        if name not in ('panel.db','failed-panel.db'):
            raise ValueError('database evidence outside fixed private scope')
        path = self.backup/name
        self.parents(path)
        descriptor = os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
        try:
            before = os.fstat(descriptor)
            if (not stat.S_ISREG(before.st_mode) or before.st_nlink!=1 or before.st_uid!=0
                    or stat.S_IMODE(before.st_mode)!=0o600 or before.st_size>16*1024*1024*1024):
                raise ValueError('unsafe retained database backup identity')
            identity = self.file_snapshot(b'',before)['identity']
            digest, size, deadline = hashlib.sha256(), 0, time.monotonic()+60
            while True:
                if time.monotonic()>deadline:
                    raise ValueError('database backup verification exceeded deadline')
                block = os.read(descriptor,1024*1024)
                if not block:
                    break
                digest.update(block)
                size += len(block)
                if size > before.st_size:
                    raise ValueError('retained database backup grew during verification')
            if size!=before.st_size or self.file_snapshot(b'',os.fstat(descriptor))['identity']!=identity:
                raise ValueError('retained database backup changed during verification')
            return {'sha256':digest.hexdigest(),'identity':identity}
        finally:
            os.close(descriptor)

    def retain_database_receipt(self):
        target = self.backup/'database-backup.json'
        if self.exists(target):
            raise ValueError('retained database receipt must not be overwritten')
        record = {'format':1,'version':self.version,'database':self.backup_database_snapshot()}
        self.atomic(target,(json.dumps(record,sort_keys=True)+'\n').encode(),0o600)

    def validate_database_backup(self, *, failed=False):
        raw, _ = self.file(self.backup/('failed-database-backup.json'if failed else'database-backup.json'),mode=0o600,limit=4096)
        def closed_object(pairs):
            record = {}
            for name,value in pairs:
                if name in record:
                    raise ValueError('duplicate retained database receipt field')
                record[name] = value
            return record
        record = json.loads(raw,object_pairs_hook=closed_object)
        if (not isinstance(record,dict) or set(record)!= {'format','version','database'}
                or type(record['format']) is not int or record['format']!=1 or record['version']!=self.version):
            raise ValueError('invalid retained database receipt')
        expected = record['database']
        if (not isinstance(expected,dict) or set(expected)!= {'sha256','identity'}
                or not isinstance(expected['sha256'],str) or not re.fullmatch('[0-9a-f]{64}',expected['sha256'])
                or not isinstance(expected['identity'],list) or len(expected['identity'])!=9
                or any(type(value) is not int or value<0 for value in expected['identity'])):
            raise ValueError('invalid retained database snapshot')
        if self.backup_database_snapshot('failed-panel.db'if failed else'panel.db')!=expected:
            raise ValueError('retained database backup inode or content differs from durable receipt')
        return expected

    def retain_failed_database(self, *, check=False):
        """Publish a complete SQLite snapshot without overwriting evidence.

        A killed copy leaves only a random private stage. A fsynced immutable
        inode intent is retained before exclusive publication; a later process
        can finish that exact publication, never substitute another file.
        """
        target = self.backup/'failed-panel.db'
        proof = self.backup/'failed-database-publish.json'
        receipt = self.backup/'failed-database-backup.json'
        if self.exists(proof):
            record = self.read_record(proof,limit=16384)
            if (set(record)!={'format','version','stage','candidate'} or type(record['format'])is not int or record['format']!=1
                    or record['version']!=self.version or not isinstance(record['stage'],str)):
                raise ValueError('invalid failed database publication intent')
            stage = self.scoped_path(record['stage'])
            if stage.parent!=self.backup or not stage.name.startswith('.program-upgrade-failed-db-'):
                raise ValueError('failed database stage outside fixed private backup')
            expected = self.valid_snapshot(record['candidate'],mode=0o600)
            if self.exists(target):
                if self.exists(stage) or not self.same_owned_snapshot(self.backup_database_snapshot('failed-panel.db'),expected):
                    raise ValueError('retained failed database inode differs from publication intent')
            else:
                actual = self.private_database_stage_snapshot(stage)
                if actual!=expected:
                    raise ValueError('failed database publication stage changed')
                if check:
                    return
                rename_noreplace(stage,target)
                self.sync_directory(self.backup)
            if self.exists(receipt):
                self.validate_database_backup(failed=True)
            elif not check:
                value = {'format':1,'version':self.version,'database':self.backup_database_snapshot('failed-panel.db')}
                self.atomic(receipt,(json.dumps(value,sort_keys=True)+'\n').encode(),0o600)
            return
        if self.exists(target) or self.exists(receipt):
            raise ValueError('failed database evidence has no durable publication authority')
        if check:
            raise ValueError('failed database recovery evidence is absent')
        descriptor,name = tempfile.mkstemp(prefix='.program-upgrade-failed-db-',dir=self.backup)
        os.fchmod(descriptor,0o600)
        original_inode = os.fstat(descriptor)
        os.close(descriptor)
        stage = pathlib.Path(name)
        deadline = time.monotonic()+60
        def bounded(status,remaining,total):
            if time.monotonic()>deadline:
                raise ValueError('failed database snapshot exceeded deadline')
        with self.connect() as source,contextlib.closing(sqlite3.connect(stage)) as destination:
            source.backup(destination,pages=1024,progress=bounded,sleep=0.01)
            if destination.execute('PRAGMA quick_check').fetchone()!=('ok',):
                raise ValueError('failed database snapshot integrity check failed')
        descriptor = os.open(stage,os.O_RDONLY|os.O_NOFOLLOW)
        try:
            info = os.fstat(descriptor)
            if (info.st_dev,info.st_ino)!=(original_inode.st_dev,original_inode.st_ino):
                raise ValueError('failed database snapshot stage inode replaced during copy')
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        expected = self.private_database_stage_snapshot(stage)
        self.sync_directory(self.backup)
        record = {'format':1,'version':self.version,'stage':str(stage),'candidate':expected}
        self.atomic(proof,(json.dumps(record,sort_keys=True)+'\n').encode(),0o600)
        self.retain_failed_database()

    def private_database_stage_snapshot(self, stage):
        if stage.parent!=self.backup or not stage.name.startswith('.program-upgrade-failed-db-'):
            raise ValueError('private database stage outside fixed evidence scope')
        self.parents(stage)
        descriptor = os.open(stage,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
        try:
            before = os.fstat(descriptor)
            if (not stat.S_ISREG(before.st_mode) or before.st_nlink!=1 or before.st_uid!=0
                    or stat.S_IMODE(before.st_mode)!=0o600 or before.st_size>16*1024*1024*1024):
                raise ValueError('unsafe private failed database stage')
            digest,size,deadline = hashlib.sha256(),0,time.monotonic()+60
            identity = self.file_snapshot(b'',before)['identity']
            while True:
                if time.monotonic()>deadline:
                    raise ValueError('private database stage verification exceeded deadline')
                block = os.read(descriptor,1024*1024)
                if not block:
                    break
                digest.update(block);size+=len(block)
                if size>before.st_size:
                    raise ValueError('private database stage grew during verification')
            if size!=before.st_size or self.file_snapshot(b'',os.fstat(descriptor))['identity']!=identity:
                raise ValueError('private database stage changed during verification')
            return {'sha256':digest.hexdigest(),'identity':identity}
        finally:
            os.close(descriptor)

    def restore_database(self):
        expected = self.validate_database_backup()
        self.validate_database_lineage()
        before_database = self.current_database_snapshot(self.database)
        history = self.database_mutations.get(str(self.database),[])
        if (history and history[-1]['kind']=='database-replace'
                and history[-1]['candidate']['sha256']==expected['sha256']
                and self.same_owned_snapshot(before_database,history[-1]['candidate'])):
            # A kill after replace but before the phase journal must not
            # replace the already-owned restored inode a second time.
            descriptor = os.open(self.database,os.O_RDONLY|os.O_NOFOLLOW)
            try:
                if self.file_snapshot(b'',os.fstat(descriptor))['identity']!=before_database['identity']:
                    raise ValueError('restored database changed before durability confirmation')
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
            self.sync_directory(self.database.parent)
            return
        source = os.open(self.backup/'panel.db', os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        descriptor = None
        try:
            before = os.fstat(source)
            if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or before.st_uid != 0 or stat.S_IMODE(before.st_mode) != 0o600 or before.st_size > 16*1024*1024*1024:
                raise ValueError('unsafe or oversized private database backup')
            if self.file_snapshot(b'',before)['identity'] != expected['identity']:
                raise ValueError('retained database backup changed before restore')
            descriptor, name = tempfile.mkstemp(prefix='.program-upgrade-panel.db-', dir=self.database.parent)
            os.fchmod(descriptor, 0o600)
            os.fchown(descriptor, self.db_owner, self.db_group)
            digest, size, deadline = hashlib.sha256(), 0, time.monotonic()+60
            with os.fdopen(descriptor, 'wb', closefd=False) as destination:
                while True:
                    if time.monotonic()>deadline:
                        raise ValueError('database restore exceeded streaming deadline')
                    block = os.read(source, 1024*1024)
                    if not block:
                        break
                    size += len(block)
                    digest.update(block)
                    if size > before.st_size:
                        raise ValueError('database backup grew during restore')
                    destination.write(block)
                destination.flush()
                os.fsync(descriptor)
            after = os.fstat(source)
            if (self.file_snapshot(b'',after)['identity'] != expected['identity']
                    or size != before.st_size or digest.hexdigest()!=expected['sha256']):
                raise ValueError('backup changed during bounded streaming restore')
            candidate = {'sha256':digest.hexdigest(),'identity':self.file_snapshot(b'',os.fstat(descriptor))['identity']}
            intent = {'kind':'database-replace','target':str(self.database),'stage':str(name),'before':before_database,'candidate':candidate}
            self.mutation_evidence(intent)
            self.database_mutations.setdefault(str(self.database),[]).append(intent)
            if (self.current_database_snapshot(self.database)!=before_database
                    or self.file_snapshot(b'',pathlib.Path(name).lstat())['identity']!=candidate['identity']):
                raise ValueError('database changed after durable restore intent')
            os.replace(name, self.database)
            intent['applied'] = True
            self.sync_directory(self.database.parent)
        finally:
            os.close(source)
            if descriptor is not None:
                os.close(descriptor)

    @staticmethod
    def validate_inventory_record(value):
        if not isinstance(value,dict) or not value or len(value)>10000 or '.' not in value:
            raise ValueError('invalid complete recovery inventory')
        total = 0
        for name,record in value.items():
            relative = pathlib.PurePosixPath(name)
            if (not isinstance(name,str) or not name or relative.is_absolute() or '..' in relative.parts
                    or str(relative)!=name or '\x00' in name or not isinstance(record,dict)):
                raise ValueError('unsafe recovery inventory path')
            # Linux paths can contain literal backslashes; normal payloads
            # include escaped systemd mount names. They are not separators.
            # PurePosixPath still rejects absolute and dotdot components.
            kind = record.get('kind')
            fields = {'kind','mode','identity'} if kind=='directory' else {'kind','mode','size','sha256','identity'}
            if set(record)!=fields or kind not in ('file','directory'):
                raise ValueError('unknown recovery inventory kind or field')
            info = record['identity']
            if (not isinstance(info,list) or len(info)!=9 or any(type(item)is not int or item<0 for item in info)
                    or type(record['mode'])is not int or record['mode']!=stat.S_IMODE(info[2])
                    or info[3]!=0 or info[2]&0o022):
                raise ValueError('unsafe recovery inventory ownership or mode')
            if kind=='directory':
                if not stat.S_ISDIR(info[2]):
                    raise ValueError('recovery directory identity mismatch')
            else:
                if (not stat.S_ISREG(info[2]) or info[5]!=1 or type(record['size'])is not int
                        or record['size']!=info[6] or record['size']>256*1024*1024
                        or not isinstance(record['sha256'],str) or not re.fullmatch('[0-9a-f]{64}',record['sha256'])):
                    raise ValueError('recovery file identity mismatch')
                total += record['size']
            if name!='.' and (str(relative.parent) not in value or value[str(relative.parent)].get('kind')!='directory'):
                raise ValueError('incomplete recovery inventory parent')
        if value['.']['kind']!='directory' or total>1024*1024*1024:
            raise ValueError('recovery inventory exceeds complete byte budget')
        return value

    def recover_preflight(self, backup):
        """Reconstruct only a fixed layout transaction, without live writes.

        A Root-private plan is not authority to restore arbitrary paths. Both
        original fixed leases, dead owner, complete code trees and contiguous
        prewrite inode intents must independently agree before any service or
        database mutation. Old transactions without this protocol refuse.
        """
        if self.layout not in ('production','development') or self.locks or self.backup is not None:
            raise ValueError('recovery requires a fresh transaction object')
        backup = self.scoped_path(backup)
        parent = self.path('/var/backups/panel/system')
        prefix = self.layout+'-'
        if backup.parent!=parent or not backup.name.startswith(prefix):
            raise ValueError('recovery backup outside fixed layout namespace')
        version = backup.name[len(prefix):]
        if not VERSION.fullmatch(version):
            raise ValueError('invalid recovery backup version')
        self.parents(backup)
        self.directory(parent,private=True)
        info = self.directory(backup,private=True)
        plan = self.read_record(backup/'recovery-plan.json')
        fields = {'format','layout','version','backup_device','backup_inode','owner','services','nginx_pid',
                  'database_owner','database_group','database_inode','candidate','original_units','original_marker'}
        fields |= {'previous','original_pointer','previous_inventory'} if self.layout=='production' else {'original_trees'}
        if (set(plan)!=fields or type(plan['format'])is not int or plan['format']!=1
                or plan['layout']!=self.layout or plan['version']!=version
                or type(plan['backup_device'])is not int or type(plan['backup_inode'])is not int
                or (plan['backup_device'],plan['backup_inode'])!=(info.st_dev,info.st_ino)):
            raise ValueError('closed recovery plan does not bind this backup')
        owner = plan['owner']
        if (not isinstance(owner,dict) or set(owner)!={'pid','start_ticks','boot_id','leases'}
                or any(type(owner[k])is not int or owner[k]<=0 for k in ('pid','start_ticks'))
                or not isinstance(owner['boot_id'],str) or not re.fullmatch(r'[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}',owner['boot_id'])
                or not isinstance(owner['leases'],list) or len(owner['leases'])!=2
                or any(not isinstance(pair,list) or len(pair)!=2 or any(type(item)is not int or item<=0 for item in pair) for pair in owner['leases'])):
            raise ValueError('invalid retained transaction owner or leases')
        boot = pathlib.Path('/proc/sys/kernel/random/boot_id').read_text().strip()
        if owner['boot_id']==boot:
            try:
                raw = pathlib.Path('/proc')/str(owner['pid'])/'stat'
                process = raw.read_text()
                ticks = int(process[process.rindex(') ')+2:].split()[19])
            except FileNotFoundError:
                ticks = None
            if ticks==owner['start_ticks']:
                raise ValueError('original upgrade owner is still alive; recovery refused')
        self.version,self.backup,self.backup_path = version,backup,backup
        self.release = backup/'candidate'
        if self.layout=='production':
            self.current = self.path('/opt/panel/current')
            self.releases = self.path('/opt/panel/releases')
            self.marker = self.path('/etc/panel-release')
            self.pending = self.releases/'.program-upgrade.pending'
            self.release_lock = self.releases/'.release.lock'
        else:
            self.base = self.path('/opt/panel')
            self.releases = self.base
            self.marker = self.base/'DEVELOPMENT_RELEASE'
            self.pending = self.base/'.development-upgrade.pending'
            self.release_lock = self.base/'.development-update.lock'
        self.destination = self.releases/version
        self.database = self.path('/var/lib/panel/panel.db')
        self.db_owner,self.db_group = plan['database_owner'],plan['database_group']
        if (type(self.db_owner)is not int or self.db_owner<=0 or type(self.db_group)is not int or self.db_group<0
                or str(self.db_owner)!=self.run_command('/usr/bin/id','-u','panel')
                or str(self.db_group)!=self.run_command('/usr/bin/id','-g','panel')):
            raise ValueError('recovery database owner is not the fixed panel account')
        inode = plan['database_inode']
        if (not isinstance(inode,list) or len(inode)!=6 or any(type(item)is not int or item<0 for item in inode)
                or not stat.S_ISREG(inode[2]) or stat.S_IMODE(inode[2])!=0o600
                or inode[3:6]!=[self.db_owner,self.db_group,1]):
            raise ValueError('invalid original database inode identity')
        self.original_database_inode = inode
        for location in (self.release_lock,self.path('/var/lib/panel-executor/runtime-lifecycle.lock')):
            self.lock(location)  # Never create, chmod or replace a recovery lease.
        if [[os.fstat(fd).st_dev,os.fstat(fd).st_ino] for fd in self.locks]!=owner['leases']:
            raise ValueError('recovery lease inode differs from original transaction')
        for location,fd in zip((self.release_lock,self.path('/var/lib/panel-executor/runtime-lifecycle.lock')),self.locks):
            actual = location.lstat()
            held = os.fstat(fd)
            if (actual.st_dev,actual.st_ino)!=(held.st_dev,held.st_ino):
                raise ValueError('recovery lease pathname changed after locking')
        expected = self.validate_inventory_record(plan['candidate'])
        if self.code_inventory(self.release)!=expected:
            raise ValueError('complete retained candidate inode inventory changed')
        self.run_command(str(self.release/'verify-release.sh'),str(self.release))
        fields = dict(line.split('=',1) for line in self.file(self.release/'RELEASE',limit=256)[0].decode('ascii').splitlines())
        arch = self.run_command('/usr/bin/dpkg','--print-architecture')
        if fields!={'PANEL_FORMAT':'1','PANEL_VERSION':version,'PANEL_OS':'linux','PANEL_ARCH':arch} or arch not in ('amd64','arm64'):
            raise ValueError('recovery candidate version or architecture mismatch')
        prerequisites = backup/'native-prerequisites.json'
        if self.exists(prerequisites):
            # This is an immutable intent, not a completion claim or deletion
            # authority. A crash at any helper step leaves the dirs untouched.
            record = self.read_record(prerequisites,limit=4096)
            if (self.layout!='production' or type(record.get('format'))is not int
                    or record!=self.native_prerequisite_record(self.release)):
                raise ValueError('native prerequisite intent differs from retained candidate')
        self.recover_layout_plan(plan,arch)
        units = plan['original_units']
        self.units = sorted((self.release/'systemd').iterdir())
        if (not isinstance(units,dict) or not units or len(units)>64
                or set(units)!={path.name for path in self.units} or any(not UNIT.fullmatch(name) for name in units)):
            raise ValueError('recovery units are not the complete fixed candidate inventory')
        for name,value in units.items():
            if value is None:
                if self.exists(backup/'units'/name):
                    raise ValueError('unexpected private original unit')
                self.original_units[name] = None
            else:
                self.valid_snapshot(value)
                raw = self.file(backup/'units'/name,mode=0o600,limit=65536)[0]
                if hashlib.sha256(raw).hexdigest()!=value['sha256']:
                    raise ValueError('private original unit differs from recovery plan')
                self.original_units[name] = raw,self.snapshot_info(value)
        services = plan['services']
        if not isinstance(services,dict) or set(services)!=set(PROGRAMS+(TIMER,'panel-mysql-overwrite-recovery.service','nginx.service')):
            raise ValueError('recovery service inventory is outside fixed scope')
        for name,value in services.items():
            if (not isinstance(value,dict) or set(value)!={'LoadState','ActiveState','SubState','UnitFileState'}
                    or value['LoadState']!='loaded' or value['ActiveState']not in ('active','inactive')
                    or value['UnitFileState']not in ('enabled','disabled','static','indirect','enabled-runtime')
                    or not isinstance(value['SubState'],str) or len(value['SubState'])>128):
                raise ValueError('invalid original recovery service state')
        if any(services[name]['ActiveState']!='active' for name in PROGRAMS) or services['panel-mysql-overwrite-recovery.service']['ActiveState']!='inactive':
            raise ValueError('recovery plan does not describe an admissible original host')
        self.states = services
        timer_record=backup/'timer-deferred.json'
        if self.exists(timer_record):
            self.validate_timer_declaration(self.read_record(timer_record))
            self.timer_deferred=True
        if self.exists(backup/'timer-restored.json'):
            raise ValueError('completed timer restoration is finalized; recovery must not replay it')
        if not isinstance(plan['nginx_pid'],str) or not plan['nginx_pid'].isascii() or not plan['nginx_pid'].isdigit():
            raise ValueError('invalid retained gateway process identity')
        self.nginx_pid = self.run_command('/usr/bin/systemctl','show','nginx.service','--property=MainPID','--value')
        if owner['boot_id']==boot and self.nginx_pid!=plan['nginx_pid']:
            raise ValueError('gateway changed during interrupted upgrade')
        if not self.nginx_pid.isascii() or not self.nginx_pid.isdigit():
            raise ValueError('unverifiable recovery gateway identity')
        self.load_recovery_mutations()
        self.validate_restore_lineage()
        journal = self.read_record(backup/'transaction.json',limit=16384)
        journal_fields = {'format','version','phase','services'}
        journal_fields |= {'previous'} if self.layout=='production' else {'layout','tree_intents','unit_intents','marker_intent'}
        valid_layout = (journal.get('previous')==self.previous if self.layout=='production'
                        else journal.get('layout')=='development' and journal.get('tree_intents')==self.tree_intents
                        and isinstance(journal.get('unit_intents'),list)
                        and journal['unit_intents']==sorted(set(journal['unit_intents']))
                        and set(journal['unit_intents'])<=set(self.original_units)
                        and type(journal.get('marker_intent'))is bool)
        if (set(journal)!=journal_fields or type(journal['format'])is not int
                or journal['format']!=(1 if self.layout=='production' else 2)
                or journal['version']!=version or journal['services']!=services or not valid_layout
                or journal['phase']not in ('prepared','writers-stopped','database-backed-up','program-swapped','committed','rolled-back',
                                          'switching-bin','switching-web','switching-marker','switching-units',
                                          'rollback-evidence-retained','restoring-web','restoring-bin','rollback-data-restored',
                                          'refused-before-program-change')):
            raise ValueError('unsupported or finalized recovery journal')
        self.recovery_phase = journal['phase']
        self.last_phase = self.recovery_phase
        self.changed = self.recovery_code_changed()
        if self.changed or self.exists(backup/'database-backup.json'):
            self.validate_database_backup()
        if self.changed and self.layout=='production':
            stage = self.read_record(backup/'production-stage.json')
            if set(stage)!={'format','version','inventory'} or type(stage['format'])is not int or stage['format']!=1 or stage['version']!=version:
                raise ValueError('invalid production stage recovery receipt')
            self.validate_inventory_record(stage['inventory'])
            if self.stable_inventory(self.code_inventory(self.destination))!=self.stable_inventory(stage['inventory']):
                raise ValueError('installed candidate code differs from owned durable stage')
        if self.exists(backup/'failed-database-publish.json') or self.exists(backup/'failed-panel.db') or self.database_mutations:
            self.retain_failed_database(check=True)
        self.validate_database_lineage(preserve_restored=self.recovery_phase in ('rollback-data-restored','rolled-back'))
        for unit in PROGRAMS+(TIMER,'nginx.service'):
            if self.state(unit)['UnitFileState']!=services[unit]['UnitFileState']:
                raise ValueError('service enablement changed outside interrupted transaction')
        if self.state('panel-mysql-overwrite-recovery.service')['ActiveState']!='inactive':
            raise ValueError('database replacement recovery is active')
        self.no_program_jobs()
        self.run_command('/usr/sbin/nginx','-t')
        self.queue_check()
        pending = self.validate_managed_file(self.pending)
        self.pending_created = pending is not None
        if self.pending_created:
            self.pending_bytes,self.pending_identity = self.file(self.pending,mode=0o644,limit=2048)
            location = pathlib.Path(__file__).with_name('start-guard-install.py')
            spec = importlib.util.spec_from_file_location('panel_recovery_start_guard',location)
            guard = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(guard)
            for target,data,mode in guard.inventory(self):
                if not self.exists(target) or self.file(target,mode=mode,limit=16*1024*1024)[0]!=data:
                    raise ValueError('interrupted upgrade lacks complete independent startup interlock')
        elif self.changed or self.timer_deferred and self.recovery_phase!='prepared':
            history=self.file_mutations.get(str(self.pending),[])
            if (not self.timer_deferred or self.recovery_phase not in ('committed','rolled-back','refused-before-program-change')
                    or not history or history[-1]['kind']!='file-remove' or history[-1]['candidate']is not None):
                raise ValueError('changed interrupted transaction has no owned maintenance cleanup authority')
        self.replaced_units = {name:b'' for name in self.original_units if str(self.path('/etc/systemd/system')/name) in self.file_mutations}
        if self.layout=='development':
            self.runtime_locked = True
        return {'layout':self.layout,'version':version,'phase':self.recovery_phase,'mutations':self.mutation_sequence,'database_restore':self.changed}

    def recover_layout_plan(self, plan, arch):
        self.previous = plan['previous']
        if not isinstance(self.previous,str):
            raise ValueError('invalid previous production release')
        previous = self.scoped_path(self.previous)
        if previous.parent!=self.releases or not VERSION.fullmatch(previous.name) or previous==self.destination:
            raise ValueError('previous recovery release outside fixed retained namespace')
        if self.code_inventory(previous)!=self.validate_inventory_record(plan['previous_inventory']):
            raise ValueError('original retained release inode inventory changed')
        self.previous_inventory = plan['previous_inventory']
        self.original_pointer = self.valid_snapshot(plan['original_pointer'],link=True)
        if self.original_pointer['sha256']!=hashlib.sha256(self.previous.encode()).hexdigest():
            raise ValueError('original pointer does not select retained previous code')
        marker = self.valid_snapshot(plan['original_marker'])
        self.marker_bytes = self.file(self.backup/'panel-release',mode=0o600,limit=256)[0]
        self.marker_info = self.snapshot_info(marker)
        if (hashlib.sha256(self.marker_bytes).hexdigest()!=marker['sha256']
                or self.marker_bytes!=('version='+previous.name+'\narch='+arch+'\n').encode()):
            raise ValueError('private original marker differs from recovery plan')

    def recovery_code_changed(self):
        return bool(self.pointer_mutations)

    def load_recovery_mutations(self):
        paths = sorted(self.backup.glob('mutation-*.json'))
        if len(paths)>160 or [path.name for path in paths]!=['mutation-'+str(index).zfill(3)+'.json' for index in range(1,len(paths)+1)]:
            raise ValueError('noncontiguous or oversized recovery mutation ledger')
        files = {str(self.path('/etc/systemd/system')/name) for name in self.original_units}|{str(self.marker),str(self.pending)}
        database = {str(self.database),str(self.database.with_name(self.database.name+'-wal')),str(self.database.with_name(self.database.name+'-shm'))}
        for path in paths:
            value = self.read_record(path,limit=16384)
            if (set(value)!={'format','version','kind','target','stage','before','candidate'}
                    or type(value['format'])is not int or value['format']!=1 or value['version']!=self.version
                    or not isinstance(value['target'],str)):
                raise ValueError('invalid closed recovery mutation')
            target = self.scoped_path(value['target'])
            kind = value['kind']
            pointer = kind=='pointer-replace' and target==getattr(self,'current',None)
            db = kind in ('database-replace','database-remove') and str(target) in database
            regular = kind in ('file-replace','file-remove') and str(target) in files
            if not (pointer or db or regular) or (db and kind=='database-replace' and target!=self.database):
                raise ValueError('recovery mutation is outside fixed code/config/database scope')
            for snapshot in (value['before'],value['candidate']):
                if snapshot is not None:
                    self.valid_snapshot(snapshot,mode=0o600 if db else 0o644,owner=self.db_owner if db else 0,link=pointer)
            removing = kind.endswith('-remove')
            if removing:
                if value['stage']is not None or value['candidate']is not None or value['before']is None:
                    raise ValueError('invalid durable remove intent')
            else:
                if value['candidate']is None or not isinstance(value['stage'],str):
                    raise ValueError('missing bound recovery replacement stage')
                stage = self.scoped_path(value['stage'])
                prefix = '.program-upgrade-current-' if pointer else '.program-upgrade-'+target.name+'-'
                if stage.parent!=target.parent or not stage.name.startswith(prefix) or len(stage.name)<=len(prefix):
                    raise ValueError('replacement stage outside fixed target parent')
                if self.exists(stage):
                    actual = self.pointer_snapshot(stage) if pointer else (self.current_database_stage(stage) if db else self.current_file_snapshot(stage))
                    if actual!=value['candidate']:
                        raise ValueError('abandoned recovery replacement stage inode changed')
            if pointer:
                allowed = {hashlib.sha256(item.encode()).hexdigest() for item in (self.previous,str(self.destination))}
                if value['candidate']['sha256']not in allowed or value['before']is None:
                    raise ValueError('pointer recovery selects unowned code')
                history,original = self.pointer_mutations,self.original_pointer
            elif regular:
                history = self.file_mutations.setdefault(str(target),[])
                original = self.managed_file_original(target)
            else:
                history = self.database_mutations.setdefault(str(target),[])
                original = value['before']
                if target==self.database and not history and (original is None or original['identity'][:6]!=self.original_database_inode):
                    raise ValueError('database restore intent lacks original inode lineage')
            expected = history[-1]['candidate'] if history else original
            if not self.same_owned_snapshot(value['before'],expected):
                raise ValueError('disconnected recovery mutation inode chain')
            history.append(value)
        self.mutation_sequence = len(paths)

    def current_database_stage(self, stage):
        if stage.parent!=self.database.parent or not stage.name.startswith('.program-upgrade-panel.db-'):
            raise ValueError('database recovery stage outside fixed namespace')
        return self.stream_database_snapshot(stage)

    def recover(self, backup, *, check=False):
        summary = self.recover_preflight(backup)
        if check:
            return summary
        if not self.pending_created:
            if self.recovery_phase in ('committed','rolled-back','refused-before-program-change'):
                # Only a durable owned marker-removal intent and timer protocol
                # can admit this cleanup gap. Do not restart programs, replay
                # data, or reinterpret a later user-requested timer stop.
                if self.recovery_phase=='committed':
                    self.verify_recovery_candidate_units()
                else:
                    self.verify_recovery_original_code()
                    for name,value in self.original_units.items():
                        path=self.path('/etc/systemd/system')/name
                        actual=self.file(path,mode=0o644,limit=65536)[0]if self.exists(path)else None
                        if actual!=(value[0]if value is not None else None):
                            raise ValueError('markerless timer cleanup has changed original units')
                for unit in PROGRAMS+('nginx.service',):
                    if self.state(unit)['ActiveState']!=self.states[unit]['ActiveState']:
                        raise ValueError('markerless timer cleanup cannot restart changed programs')
                self.wait_readiness()
                self.restore_timer()
                self.journal('recovered-committed'if self.recovery_phase=='committed'else'recovered-rolled-back')
                return summary
            checked=PROGRAMS+('nginx.service',)if self.timer_deferred else PROGRAMS+(TIMER,'nginx.service')
            if any(self.state(unit)['ActiveState']!=self.states[unit]['ActiveState'] for unit in checked):
                raise ValueError('markerless prepared recovery does not preserve original service state')
            if self.timer_deferred:
                self.wait_readiness()
                self.restore_timer()
            self.journal('recovered-before-maintenance')
            return summary
        if self.recovery_phase=='committed':
            self.recover_committed()
            return summary
        if self.recovery_phase in ('rollback-data-restored','rolled-back'):
            self.finish_restored_recovery()
            return summary
        # Every code/config/data input was validated before the first stop.
        # rollback repeats those checks after it has stopped all fixed writers.
        self.stopping = True
        self.rollback()
        self.journal('recovered-rolled-back')
        return summary

    def recover_committed(self):
        if os.readlink(self.current)!=str(self.destination) or self.file(self.marker,mode=0o644,limit=256)[0]!=('version='+self.version+'\narch='+self.run_command('/usr/bin/dpkg','--print-architecture')+'\n').encode():
            raise ValueError('committed recovery no longer selects candidate code')
        self.verify_recovery_candidate_units()
        self.defer_timer()
        self.stop_timer()
        self.verify_original_activity()
        self.wait_readiness()
        self.remove_pending()
        self.restore_timer()
        self.journal('recovered-committed')

    def verify_recovery_candidate_units(self):
        for source in self.units:
            expected = self.file(source,mode=0o644,limit=65536)[0]
            if self.layout=='production':
                expected = expected.replace(b'/opt/panel/bin/',b'/opt/panel/current/bin/').replace(b'/opt/panel/web',b'/opt/panel/current/web').replace(b'development ',b'')
            if self.file(self.path('/etc/systemd/system')/source.name,mode=0o644,limit=65536)[0]!=expected:
                raise ValueError('committed recovery does not select exact candidate units')

    def verify_recovery_original_code(self):
        if os.readlink(self.current)!=self.previous or self.file(self.marker,mode=0o644,limit=256)[0]!=self.marker_bytes:
            raise ValueError('restored recovery no longer selects original code')

    def finish_restored_recovery(self):
        self.verify_recovery_original_code()
        for name,original in self.original_units.items():
            target = self.path('/etc/systemd/system')/name
            actual = self.file(target,mode=0o644,limit=65536)[0]if self.exists(target)else None
            if actual!=(original[0]if original is not None else None):
                raise ValueError('restored recovery unit differs from original')
        # Preserve the current database, including any initialization writes.
        # Only its owned restored inode is admitted; no data is replayed here.
        self.validate_database_lineage(preserve_restored=True)
        self.defer_timer()
        self.stop_timer()
        self.run_command('/usr/bin/systemctl','daemon-reload')
        self.start_previous_state()
        self.wait_readiness()
        self.queue_check()
        self.verify_original_activity()
        if self.run_command('/usr/bin/systemctl','show','nginx.service','--property=MainPID','--value')!=self.nginx_pid:
            raise ValueError('gateway process changed during restored recovery')
        self.journal('rolled-back')
        self.remove_pending()
        self.restore_timer()
        self.journal('recovered-rolled-back')

    def run(self):
        self.preflight()
        self.lock(self.releases/'.release.lock', create=True)
        # Full verification may outlast the recovery timer interval on an
        # emulated/slow host. Do it under release serialization BEFORE holding
        # the runtime lease: a timer worker needs that lease to finish. This
        # read is not permission to mutate programs; the unchanged complete
        # queue guard runs again under both leases after timer suspension.
        self.preflight()
        self.lock(self.path('/var/lib/panel-executor/runtime-lifecycle.lock'))
        self.backup = self.backup_path
        self.backup.mkdir(mode=0o700)
        self.sync_directory(self.backup.parent)
        (self.backup/'units').mkdir(mode=0o700)
        self.sync_directory(self.backup)
        for name, value in self.original_units.items():
            if value is not None:
                self.atomic(self.backup/'units'/name, value[0], 0o600)
        self.atomic(self.backup/'panel-release', self.marker_bytes, 0o600)
        self.retain_candidate_plan()
        self.defer_timer()
        self.journal('prepared')
        # Independent immutable interlock remains installed on rollback. It
        # protects the original retained binaries before the pending marker
        # or the first code/unit mutation exists, including cold boot.
        self.start_guard(install=True)
        # Keep the independent startup interlock before EVERY service action.
        # The owned recovery plan and timer declaration are already durable.
        # Prevent new periodic recovery from waiting on our runtime lease
        # during native preparation and stage verification. Never stop the
        # recovery SERVICE, reset failures or retry/bypass a refused queue.
        self.stop_timer()
        self.queue_check()
        self.native_prerequisites(create=True)
        stage = self.destination.with_name(self.version+'.tmp')
        shutil.copytree(self.release, stage)
        self.run_command(str(stage/'verify-release.sh'), str(stage))
        self.retain_production_stage(stage)
        # Independent writers could have accepted work during preparation.
        # Repeat the full original guard, never use the earlier read as lease.
        self.queue_check()
        self.create_pending()
        self.stop_writers()
        self.queue_check()
        self.journal('writers-stopped')
        with self.connect() as source, contextlib.closing(sqlite3.connect(self.backup/'panel.db')) as destination:
            source.backup(destination)
        os.chmod(self.backup/'panel.db', 0o600)
        descriptor = os.open(self.backup/'panel.db', os.O_RDONLY | os.O_NOFOLLOW)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        self.sync_directory(self.backup)
        self.retain_database_receipt()
        self.journal('database-backed-up')
        os.rename(stage, self.destination)
        self.sync_directory(self.releases)
        # Set before the first pointer/unit mutation, including partial errors.
        self.changed = True
        self.switch(str(self.destination))
        self.atomic(self.marker, ('version='+self.version+'\narch='+self.run_command('/usr/bin/dpkg', '--print-architecture')+'\n').encode(), 0o644)
        for source in self.units:
            data = self.file(source, mode=0o644, limit=65536)[0]
            data = data.replace(b'/opt/panel/bin/', b'/opt/panel/current/bin/').replace(b'/opt/panel/web', b'/opt/panel/current/web').replace(b'development ', b'')
            target = self.path('/etc/systemd/system')/source.name
            original = self.original_units[source.name]
            current = self.file(target, mode=0o644, limit=65536) if self.exists(target) else None
            identity = lambda value: None if value is None else (value[0], value[1].st_dev, value[1].st_ino, value[1].st_mtime_ns, value[1].st_ctime_ns)
            if identity(current) != identity(original):
                raise ValueError('original unit changed during upgrade; refuse to overwrite it')
            self.replaced_units[source.name] = data
            self.atomic(target, data, 0o644)
        self.journal('program-swapped')
        self.run_command('/usr/bin/systemctl', 'daemon-reload')
        # Release the runtime lock before executor readiness requests, which
        # take shared runtime leases. Release serialization remains held.
        self.release_runtime()
        self.start_previous_state()
        self.wait_readiness()
        self.queue_check()
        self.verify_original_activity()
        self.run_command('/usr/sbin/nginx', '-t')
        if self.run_command('/usr/bin/systemctl', 'show', 'nginx.service', '--property=MainPID', '--value') != self.nginx_pid:
            raise RuntimeError('website gateway master changed during the program upgrade')
        self.journal('committed')
        self.committed = True
        self.remove_pending()
        self.restore_timer()
        print('panel '+self.version+' upgraded; private rollback evidence: '+str(self.backup))

    def rollback(self):
        if self.committed:
            return
        if not self.stopping:
            if self.pending_created:
                self.validate_restore_lineage()
                self.journal('refused-before-program-change')
                self.remove_pending()
            if self.timer_deferred:
                for unit in PROGRAMS+('nginx.service',):
                    if self.state(unit)['ActiveState']!=self.states[unit]['ActiveState']:
                        raise ValueError('pre-maintenance failure cannot restart changed programs')
                self.restore_timer()
            return
        if not self.changed:
            self.validate_restore_lineage()
            self.start_previous_state()
            self.wait_readiness()
            self.journal('refused-before-program-change')
            self.remove_pending()
            self.restore_timer()
            return
        if self.states[TIMER]['ActiveState'] == 'active':
            self.run_command('/usr/bin/systemctl', 'stop', TIMER)
        self.stop_writers()
        if len(self.locks) == 1:
            self.lock(self.path('/var/lib/panel-executor/runtime-lifecycle.lock'))
        elif len(self.locks) != 2:
            raise ValueError('rollback lacks exact release/runtime lease state')
        if self.state('panel-mysql-overwrite-recovery.service')['ActiveState'] != 'inactive':
            raise RuntimeError('database replacement recovery is active; rollback refused')
        # Never erase a newly accepted job during the candidate health window.
        # Such a transaction needs deliberate recovery, with evidence retained.
        self.queue_check()
        self.validate_restore_lineage()
        self.validate_database_backup()
        self.validate_database_lineage()
        self.retain_failed_database()
        with contextlib.closing(sqlite3.connect(self.backup/'panel.db')) as old, self.connect() as current:
            for table in QUEUES:
                if old.execute(f'SELECT * FROM {table} ORDER BY id').fetchall() != current.execute(f'SELECT * FROM {table} ORDER BY id').fetchall():
                    raise RuntimeError('candidate accepted job changes; automatic database rollback refused')
        self.journal('rollback-evidence-retained')
        for name, candidate_bytes in self.replaced_units.items():
            value = self.original_units[name]
            target = self.path('/etc/systemd/system')/name
            self.validate_managed_file(target)
            if value is None:
                self.remove_managed_file(target)
            elif self.file(target,mode=0o644,limit=65536)[0]!=value[0]:
                self.atomic(target, value[0], stat.S_IMODE(value[1].st_mode), value[1].st_uid, value[1].st_gid)
        if os.readlink(self.current)!=self.previous:
            self.switch(self.previous)
        if self.file(self.marker,mode=0o644,limit=256)[0]!=self.marker_bytes:
            self.atomic(self.marker, self.marker_bytes, stat.S_IMODE(self.marker_info.st_mode), self.marker_info.st_uid, self.marker_info.st_gid)
        self.remove_database_sidecars()
        self.restore_database()
        self.journal('rollback-data-restored')
        self.run_command('/usr/bin/systemctl', 'daemon-reload')
        self.start_previous_state()
        self.wait_readiness()
        self.journal('rolled-back')
        self.verify_original_activity()
        self.remove_pending()
        self.restore_timer()

    def close(self):
        for descriptor in self.locks:
            os.close(descriptor)
        self.locks.clear()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=('check', 'run', 'recover-check', 'recover'))
    parser.add_argument('release', type=pathlib.Path)
    args = parser.parse_args()
    if os.geteuid() != 0:
        parser.exit(1, 'production upgrade must run as root\n')
    transaction = Upgrade(args.release)
    def interrupted(signum, frame):
        raise RuntimeError('production upgrade interrupted')
    signal.signal(signal.SIGTERM, interrupted)
    signal.signal(signal.SIGINT, interrupted)
    try:
        if args.action in ('recover-check','recover'):
            result = transaction.recover(args.release,check=args.action=='recover-check')
            print(json.dumps({'recovery':args.action,**result},sort_keys=True))
        elif args.action == 'check':
            transaction.preflight()
            print('production upgrade preflight passed without changes')
        else:
            transaction.run()
    except BaseException as error:
        for diagnostic in (public_queue_refusal_diagnostic(error), public_service_refusal_diagnostic(error)):
            if diagnostic is not None:
                print(json.dumps(diagnostic, sort_keys=True), file=sys.stderr)
        if args.action not in ('recover-check','recover'):
            try:
                transaction.rollback()
            except BaseException:
                print('automatic rollback incomplete; service and data recovery cannot be confirmed; private transaction evidence and maintenance marker are retained for inspection', file=sys.stderr)
        parser.exit(1, 'production upgrade failed: '+str(error)+'\n')
    finally:
        transaction.close()


if __name__ == '__main__':
    main()
