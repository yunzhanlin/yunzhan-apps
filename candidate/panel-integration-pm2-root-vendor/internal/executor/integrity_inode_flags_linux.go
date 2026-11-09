//go:build linux

package executor

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

	"golang.org/x/sys/unix"
)

const integrityImmutableFlag = 0x10

// Device, inode and original numeric owners are witnesses. They must never be
// inferred from the current process's effective group or a replacement path.
type integrityInodeIdentity struct {
	Device    uint64 `json:"device"`
	Inode     uint64 `json:"inode"`
	UID       uint32 `json:"uid"`
	GID       uint32 `json:"gid"`
	Mode      uint32 `json:"mode"`
	Links     uint64 `json:"links"`
	Bytes     int64  `json:"bytes"`
	MTimeSec  int64  `json:"mtime_sec"`
	MTimeNano int64  `json:"mtime_nsec"`
}

type integrityInodeFlagState struct {
	Identity integrityInodeIdentity `json:"identity"`
	Flags    int                    `json:"flags"`
}

func integrityInodeIdentityOf(st unix.Stat_t) integrityInodeIdentity {
	return integrityInodeIdentity{Device: uint64(st.Dev), Inode: st.Ino, UID: st.Uid, GID: st.Gid, Mode: st.Mode, Links: uint64(st.Nlink), Bytes: st.Size, MTimeSec: st.Mtim.Sec, MTimeNano: st.Mtim.Nsec}
}

func validateIntegrityFlagInode(st unix.Stat_t, directory bool) error {
	if directory {
		if st.Mode&unix.S_IFMT != unix.S_IFDIR || st.Nlink < 1 {
			return errors.New("kernel protection target is not the original directory")
		}
	} else if st.Mode&unix.S_IFMT != unix.S_IFREG || st.Nlink != 1 {
		return errors.New("kernel protection requires a regular file with one link")
	}
	return nil
}

// Opening a FIFO or device can itself have effects. First obtain an O_PATH
// descriptor beneath the already-pinned public root, reject every other inode
// type, then reopen only that verified descriptor through the kernel procfs.
// There is deliberately no openat fallback when openat2 fences are unavailable.
func openIntegrityFlagTarget(public *os.File, relative string, directory bool) (*os.File, error) {
	if public == nil || !utf8.ValidString(relative) || len(relative) == 0 || len(relative) > 4096 || !fs.ValidPath(relative) || strings.Contains(relative, "\\") || strings.IndexFunc(relative, unicode.IsControl) >= 0 || relative == "." && !directory {
		return nil, errors.New("invalid relative kernel protection target")
	}
	pathFD, err := unix.Openat2(int(public.Fd()), relative, &unix.OpenHow{Flags: unix.O_PATH | unix.O_CLOEXEC | unix.O_NOFOLLOW, Resolve: unix.RESOLVE_BENEATH | unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_MAGICLINKS | unix.RESOLVE_NO_XDEV})
	if err != nil {
		return nil, fmt.Errorf("cannot pin kernel protection target: %w", err)
	}
	defer unix.Close(pathFD)
	var before unix.Stat_t
	if err = unix.Fstat(pathFD, &before); err != nil {
		return nil, err
	}
	if err = validateIntegrityFlagInode(before, directory); err != nil {
		return nil, err
	}
	flags := unix.O_RDONLY | unix.O_NONBLOCK | unix.O_CLOEXEC
	if directory {
		flags |= unix.O_DIRECTORY
	}
	fd, err := unix.Open("/proc/self/fd/"+strconv.Itoa(pathFD), flags, 0)
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(fd), relative)
	var after unix.Stat_t
	if err = unix.Fstat(fd, &after); err != nil || integrityInodeIdentityOf(before) != integrityInodeIdentityOf(after) {
		f.Close()
		return nil, errors.New("kernel protection inode changed while opening")
	}
	return f, nil
}

func readIntegrityInodeFlags(f *os.File, directory bool) (integrityInodeFlagState, error) {
	var state integrityInodeFlagState
	if f == nil {
		return state, errors.New("missing kernel protection descriptor")
	}
	var before, after unix.Stat_t
	if err := unix.Fstat(int(f.Fd()), &before); err != nil {
		return state, err
	}
	if err := validateIntegrityFlagInode(before, directory); err != nil {
		return state, err
	}
	flags, err := unix.IoctlGetInt(int(f.Fd()), unix.FS_IOC_GETFLAGS)
	if err != nil {
		return state, fmt.Errorf("inode flags are unavailable: %w", err)
	}
	if flags < 0 {
		return state, errors.New("inode flag value is not supported")
	}
	if err = unix.Fstat(int(f.Fd()), &after); err != nil || integrityInodeIdentityOf(before) != integrityInodeIdentityOf(after) {
		return state, errors.New("kernel protection inode changed during inspection")
	}
	confirmed, err := unix.IoctlGetInt(int(f.Fd()), unix.FS_IOC_GETFLAGS)
	if err != nil || confirmed != flags {
		return state, errors.New("kernel protection flags changed during inspection")
	}
	return integrityInodeFlagState{Identity: integrityInodeIdentityOf(after), Flags: flags}, nil
}

// This descriptor primitive is not an application operation. Its caller must
// first durably record the original state and whether this application owns
// the added immutable bit. Pre-existing protection must never be released.
func setIntegrityInodeImmutable(f *os.File, directory bool, expected integrityInodeFlagState, enabled bool) (integrityInodeFlagState, error) {
	current, err := readIntegrityInodeFlags(f, directory)
	if err != nil {
		return current, err
	}
	if current != expected {
		return current, errors.New("kernel protection inode or flags no longer match the original observation")
	}
	next := current.Flags | integrityImmutableFlag
	if !enabled {
		next = current.Flags &^ integrityImmutableFlag
	}
	if next == current.Flags {
		return current, nil
	}
	// FS_IOC_SETFLAGS takes an int pointer, not an immediate integer value.
	if err = unix.IoctlSetPointerInt(int(f.Fd()), unix.FS_IOC_SETFLAGS, next); err != nil {
		return current, fmt.Errorf("inode protection was not applied: %w", err)
	}
	observed, err := readIntegrityInodeFlags(f, directory)
	if err != nil || observed.Identity != expected.Identity || observed.Flags != next {
		return observed, errors.New("inode protection result needs independent verification; do not replay")
	}
	return observed, nil
}
