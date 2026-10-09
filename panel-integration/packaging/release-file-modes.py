#!/usr/bin/env python3
"""Normalize/check public program payload modes, independently of host umask.

Only packager-generated program files belong here. Runtime state, keys, logs,
QA evidence and source staging are NOT inputs and must remain private.
"""
import argparse
import os
import pathlib
import stat

EXECUTABLES={"bin/panel","bin/panel-executor","install.sh","verify-release.sh","prune-releases.sh"}

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
    parser.add_argument("action",choices=["normalize","check"])
    parser.add_argument("root",type=pathlib.Path)
    args=parser.parse_args()
    try:
        count=payload_modes(args.root,args.action=="normalize")
        print("release public program modes verified: "+str(count)+" entries")
    except (OSError,ValueError) as error:
        parser.exit(1,"release mode policy failed: "+str(error)+"\n")

if __name__=="__main__":
    main()
