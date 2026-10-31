#!/usr/bin/env python3
"""Normalize/check public program payload modes, independently of host umask.

Only packager-generated program files belong here. Runtime state, keys, logs,
QA evidence and source staging are NOT inputs and must remain private.
"""
import argparse
import hashlib
import os
import pathlib
import re
import stat

EXECUTABLES={"bin/panel","bin/panel-executor","bin/panel-start-guard","install.sh","verify-release.sh","prune-releases.sh"}

def _identity(info):
    return (info.st_dev,info.st_ino,info.st_mode,info.st_uid,info.st_gid,
            info.st_nlink,info.st_size,info.st_mtime_ns,info.st_ctime_ns)

def _release_tree(descriptor):
    records={"":_identity(os.fstat(descriptor))}
    def walk(parent,prefix):
        with os.scandir(parent) as entries:
            for entry in entries:
                relative=prefix+entry.name
                info=entry.stat(follow_symlinks=False)
                if len(records)>=10000:
                    raise ValueError("release checksum tree exceeds entry budget")
                if stat.S_ISDIR(info.st_mode):
                    child=os.open(entry.name,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=parent)
                    try:
                        if _identity(os.fstat(child))!=_identity(info):
                            raise ValueError("release directory changed during checksum inventory")
                        records[relative]=_identity(info)
                        walk(child,relative+"/")
                    finally:
                        os.close(child)
                elif stat.S_ISREG(info.st_mode) and info.st_nlink==1:
                    records[relative]=_identity(info)
                else:
                    raise ValueError("release checksum tree contains a linked or special entry")
    walk(descriptor,"")
    if sum(v[6] for v in records.values() if stat.S_ISREG(v[2]))>2<<30:
        raise ValueError("release checksum tree exceeds byte budget")
    return records

def _open_release_file(descriptor,name,records):
    current=os.dup(descriptor)
    try:
        prefix=""
        for part in name.split("/")[:-1]:
            prefix+=part
            child=os.open(part,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=current)
            os.close(current);current=child
            if _identity(os.fstat(current))!=records[prefix]:
                raise ValueError("release checksum parent identity changed")
            prefix+="/"
        file=os.open(name.split("/")[-1],os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=current)
        try:
            info=os.fstat(file)
            if not stat.S_ISREG(info.st_mode) or info.st_nlink!=1 or _identity(info)!=records[name]:
                raise ValueError("release checksum file identity changed")
        except BaseException:
            os.close(file)
            raise
        return file
    finally:
        os.close(current)

def _checksum_entries(data):
    # GNU's leading backslash marks filename escaping. Decode only its three
    # documented escapes; literal backslashes without that marker stay literal.
    # Never use splitlines(), which would split a real carriage-return name.
    if not data or len(data)>2<<20 or b"\0" in data or b"\r" in data:
        raise ValueError("release checksum manifest is empty, oversized or malformed")
    lines=data.split(b"\n")
    if lines[-1]==b"":lines.pop()
    if not 1<=len(lines)<=9999:
        raise ValueError("release checksum manifest exceeds entry budget")
    result={}
    for line in lines:
        escaped=line.startswith(b"\\")
        if escaped:line=line[1:]
        match=re.fullmatch(rb"([0-9a-fA-F]{64}) ([ *])(.+)",line)
        if not match:
            raise ValueError("release checksum manifest contains a malformed line")
        raw=match[3]
        if escaped:
            decoded=bytearray();index=0
            while index<len(raw):
                byte=raw[index];index+=1
                if byte==92:
                    if index==len(raw) or raw[index] not in (92,110,114):
                        raise ValueError("release checksum filename has an invalid escape")
                    byte={92:92,110:10,114:13}[raw[index]];index+=1
                decoded.append(byte)
            raw=bytes(decoded)
        name=os.fsdecode(raw)
        if len(raw)>4096 or name.startswith("/") or any(p in ("",".","..") for p in name.split("/")) or name=="SHA256SUMS" or name in result:
            raise ValueError("release checksum filename is unsafe, duplicate or self-referential")
        result[name]=match[1].decode("ascii").lower()
    return result

def payload_checksums(root):
    root=pathlib.Path(root)
    descriptor=os.open(root,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    try:
        before=_release_tree(descriptor)
        if "SHA256SUMS" not in before:
            raise ValueError("release checksum manifest is missing")
        file=_open_release_file(descriptor,"SHA256SUMS",before)
        with os.fdopen(file,"rb") as stream:
            data=stream.read((2<<20)+1)
            if _identity(os.fstat(stream.fileno()))!=before["SHA256SUMS"]:
                raise ValueError("release checksum manifest changed during read")
        entries=_checksum_entries(data)
        actual={name for name,value in before.items() if stat.S_ISREG(value[2]) and name!="SHA256SUMS"}
        if set(entries)!=actual:
            raise ValueError("release checksum manifest does not cover the entire payload")
        for name,expected in entries.items():
            digest=hashlib.sha256()
            file=_open_release_file(descriptor,name,before)
            with os.fdopen(file,"rb") as stream:
                received=0
                while True:
                    block=stream.read(min(1<<20,before[name][6]-received+1))
                    if not block:break
                    received+=len(block)
                    if received>before[name][6]:
                        raise ValueError("release checksum file grew beyond its recorded size")
                    digest.update(block)
                if _identity(os.fstat(stream.fileno()))!=before[name]:
                    raise ValueError("release checksum file changed during read")
            if digest.hexdigest()!=expected:
                raise ValueError("release checksum mismatch")
        if _release_tree(descriptor)!=before or _identity(root.lstat())!=before[""]:
            raise ValueError("release checksum tree changed during verification")
        return len(entries)
    finally:
        os.close(descriptor)

def payload_modes(root,normalize=False):
    root=pathlib.Path(root)
    info=root.lstat()
    if not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode):
        raise ValueError("release root must be an ordinary directory")
    paths=[root]+sorted(root.rglob("*"))
    if len(paths)>10000:
        raise ValueError("release payload exceeds permission-check budget")
    expected=[]
    # Validate the entire tree BEFORE changing the first permission. No
    # symlink, hardlink or special file may redirect this packaging operation.
    for path in paths:
        info=path.lstat()
        relative=path.relative_to(root).as_posix()
        if stat.S_ISDIR(info.st_mode):
            mode=0o755
        elif stat.S_ISREG(info.st_mode) and info.st_nlink==1:
            mode=0o755 if relative in EXECUTABLES else 0o644
        else:
            raise ValueError("release contains a linked or special payload")
        expected.append((path,mode,info))
    for path,mode,expected_info in expected:
        if normalize:
            flags=os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK
            if stat.S_ISDIR(expected_info.st_mode):
                flags|=os.O_DIRECTORY
            descriptor=os.open(path,flags)
            try:
                opened=os.fstat(descriptor)
                if (opened.st_dev,opened.st_ino)!=(expected_info.st_dev,expected_info.st_ino):
                    raise ValueError("release payload identity changed during normalization")
                os.fchmod(descriptor,mode)
            finally:
                os.close(descriptor)
        if stat.S_IMODE(path.lstat().st_mode)!=mode:
            raise ValueError("release payload has inaccessible or unsafe modes")
    return len(expected)

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action",choices=["normalize","check","verify"])
    parser.add_argument("root",type=pathlib.Path)
    args=parser.parse_args()
    try:
        count=payload_modes(args.root,args.action=="normalize")
        if args.action=="verify":
            files=payload_checksums(args.root)
            print("release strict checksums verified: "+str(files)+" files")
        print("release public program modes verified: "+str(count)+" entries")
    except (OSError,ValueError) as error:
        parser.exit(1,"release mode policy failed: "+str(error)+"\n")

if __name__=="__main__":
    main()
