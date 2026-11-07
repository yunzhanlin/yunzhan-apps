//go:build linux

package executor

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

// The only real-host fallback is an existing site's already verified numeric
// identity. Fixed tools emit socket inodes or executable dev:ino only. They
// cannot read application file contents, command lines, environment or secrets.
// No ptrace capability, shell, arbitrary program or configurable path is used.
func pm2SameUIDProcRead(ctx context.Context, root string, identity taskProcessIdentity, gid uint32, operation string) ([]byte, error) {
	if root != "/proc" || os.Geteuid() != 0 || identity.PID < 2 || identity.UID == 0 || gid == 0 || !identity.SafeUser ||
		(operation != "exe" && operation != "sockets" && operation != "descriptor-count") {
		return nil, errPM2ListenerOwnership
	}
	nnp, err := unix.PrctlRetInt(unix.PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0)
	if err != nil || nnp != 1 {
		return nil, errPM2ListenerOwnership
	}
	fd, err := unix.PidfdOpen(identity.PID, 0)
	if err != nil {
		return nil, errPM2ListenerOwnership
	}
	defer unix.Close(fd)
	check := func() error {
		pid, e := compilerPIDFDTask(fd)
		if e != nil || pid != identity.PID {
			return errPM2ListenerOwnership
		}
		current, e := readTaskProcessIdentity(root, identity.PID)
		if e != nil || current != identity {
			return errPM2ListenerOwnership
		}
		raw, e := readModuleProcFile(filepath.Join(root, strconv.Itoa(identity.PID), "status"), 16384)
		if e != nil {
			return errPM2ListenerOwnership
		}
		return pm2ListenerProcessStatus(raw, identity, pm2ListenerAccount{identity.UID, gid})
	}
	if check() != nil {
		return nil, errPM2ListenerOwnership
	}
	for _, program := range []string{"/usr/bin/setpriv", "/usr/bin/stat", "/usr/bin/find"} {
		if wafSameUIDTrustedProgram(program) != nil {
			return nil, errPM2ListenerOwnership
		}
	}
	base := filepath.Join(root, strconv.Itoa(identity.PID))
	limit := 128
	args := []string{"--no-new-privs", "--inh-caps=-all", "--ambient-caps=-all", "--"}
	switch operation {
	case "exe":
		args = append(args, "/usr/bin/stat", "-L", "--format=%d:%i", "--", filepath.Join(base, "exe"))
	case "descriptor-count":
		args = append(args, "/usr/bin/find", filepath.Join(base, "fd"), "-mindepth", "1", "-maxdepth", "1", "-printf", "%f\n")
		limit = 1 << 20
	case "sockets":
		args = append(args, "/usr/bin/find", filepath.Join(base, "fd"), "-mindepth", "1", "-maxdepth", "1", "-type", "l", "-lname", "socket:*", "-printf", "%l\n")
		limit = 4 << 20
	}
	bounded, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	command := exec.CommandContext(bounded, "/usr/bin/setpriv", args...)
	command.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: identity.UID, Gid: gid, Groups: []uint32{}}}
	command.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LANG=C", "LC_ALL=C"}
	stdout, stderr := &boundedBuffer{max: limit}, &boundedBuffer{max: 4096}
	command.Stdout, command.Stderr = stdout, stderr
	if command.Run() != nil || stdout.truncated || stderr.truncated || len(stderr.Bytes()) != 0 || check() != nil {
		return nil, errPM2ListenerOwnership
	}
	switch operation {
	case "exe":
		if _, _, err = wafSameUIDExecutableInode(stdout.Bytes()); err != nil {
			return nil, errPM2ListenerOwnership
		}
	case "descriptor-count":
		if wafSameUIDDescriptorNames(stdout.Bytes()) != nil {
			return nil, errPM2ListenerOwnership
		}
	case "sockets":
		if _, err = wafSameUIDSocketInodes(stdout.Bytes()); err != nil {
			return nil, errPM2ListenerOwnership
		}
	}
	return stdout.Bytes(), nil
}

func verifyPM2ListenerExecutable(ctx context.Context, root, binary string, identity taskProcessIdentity, gid uint32) error {
	selected, err := os.Stat(binary)
	if err != nil || !selected.Mode().IsRegular() || selected.Mode().Perm()&0022 != 0 || selected.Mode().Perm()&0111 == 0 {
		return errPM2ListenerOwnership
	}
	meta, ok := selected.Sys().(*syscall.Stat_t)
	if !ok || meta.Uid != 0 || meta.Nlink != 1 {
		return errPM2ListenerOwnership
	}
	if root == "/proc" && wafSameUIDTrustedProgram(binary) != nil {
		return errPM2ListenerOwnership
	}
	actual, err := os.Stat(filepath.Join(root, strconv.Itoa(identity.PID), "exe"))
	if err == nil {
		if !os.SameFile(selected, actual) {
			return errPM2ListenerOwnership
		}
	} else if errors.Is(err, os.ErrPermission) || errors.Is(err, unix.EPERM) {
		raw, e := pm2SameUIDProcRead(ctx, root, identity, gid, "exe")
		if e != nil {
			return e
		}
		dev, ino, e := wafSameUIDExecutableInode(raw)
		if e != nil || dev != uint64(meta.Dev) || ino != meta.Ino {
			return errPM2ListenerOwnership
		}
	} else {
		return errPM2ListenerOwnership
	}
	after, err := os.Stat(binary)
	if err != nil || !geoStoreStableInfo(selected, after) {
		return errPM2ListenerOwnership
	}
	return nil
}

func pm2ListenerSocketsDirect(ctx context.Context, root string, identity taskProcessIdentity) (map[string]bool, int, error) {
	directory, err := os.OpenFile(filepath.Join(root, strconv.Itoa(identity.PID), "fd"), os.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, 0, err
	}
	defer directory.Close()
	entries, err := directory.ReadDir(pm2ListenerMaxDescriptors + 1)
	if err != nil && !errors.Is(err, io.EOF) {
		return nil, 0, err
	}
	if len(entries) > pm2ListenerMaxDescriptors {
		return nil, 0, errPM2ListenerOwnership
	}
	var sockets strings.Builder
	for _, entry := range entries {
		if ctx.Err() != nil {
			return nil, 0, ctx.Err()
		}
		n, e := strconv.ParseUint(entry.Name(), 10, 32)
		if e != nil || strconv.FormatUint(n, 10) != entry.Name() {
			return nil, 0, errPM2ListenerOwnership
		}
		target, e := os.Readlink(filepath.Join(root, strconv.Itoa(identity.PID), "fd", entry.Name()))
		if errors.Is(e, os.ErrNotExist) {
			continue
		} // No negative ownership claim is inferred.
		if e != nil {
			return nil, 0, e
		}
		if strings.HasPrefix(target, "socket:") {
			sockets.WriteString(target)
			sockets.WriteByte('\n')
		}
	}
	result, err := wafSameUIDSocketInodes([]byte(sockets.String()))
	if err != nil {
		return nil, 0, errPM2ListenerOwnership
	}
	return result, len(entries), nil
}

func pm2ListenerProcessSockets(ctx context.Context, root string, identity taskProcessIdentity, gid uint32) (map[string]bool, int, error) {
	result, count, err := pm2ListenerSocketsDirect(ctx, root, identity)
	if err == nil {
		return result, count, nil
	}
	if !errors.Is(err, os.ErrPermission) && !errors.Is(err, unix.EPERM) {
		return nil, 0, errPM2ListenerOwnership
	}
	names, e := pm2SameUIDProcRead(ctx, root, identity, gid, "descriptor-count")
	if e != nil {
		return nil, 0, e
	}
	raw, e := pm2SameUIDProcRead(ctx, root, identity, gid, "sockets")
	if e != nil {
		return nil, 0, e
	}
	result, e = wafSameUIDSocketInodes(raw)
	if e != nil {
		return nil, 0, errPM2ListenerOwnership
	}
	count = bytes.Count(names, []byte{'\n'})
	if len(result) > count {
		count = len(result)
	}
	return result, count, nil
}
