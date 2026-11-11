//go:build linux

package executor

import (
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"os"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

var (
	taskSSHSocketInode = regexp.MustCompile("\\bino:([1-9][0-9]*)\\b")
	taskSSHSocketOwner = regexp.MustCompile("\\(\"(sshd|sshd-session)\",pid=([1-9][0-9]*),fd=([0-9]+)\\)")
	taskSSHProcessName = regexp.MustCompile("^(?:sshd|sshd-session): ([a-zA-Z0-9_][a-zA-Z0-9_.-]{0,63})@(pts/[0-9]+|notty)$")
)

func readTaskSSHProcFile(directory *os.File, name string, limit int64) ([]byte, error) {
	fd, err := unix.Openat(int(directory.Fd()), name, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(fd), name)
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() {
		return nil, errors.New("无法核对 SSH 进程身份文件")
	}
	raw, err := io.ReadAll(io.LimitReader(file, limit+1))
	if int64(len(raw)) > limit {
		return nil, errors.New("SSH 进程身份字段过长")
	}
	return raw, err
}

func taskSSHProcessUser(directory *os.File, names map[string]string) (string, string, bool) {
	command, err := readTaskSSHProcFile(directory, "cmdline", 4096)
	if err != nil {
		return "", "", false
	}
	title, _, _ := strings.Cut(string(command), "\x00")
	fields := taskSSHProcessName.FindStringSubmatch(strings.TrimSpace(title))
	if len(fields) != 3 {
		return "", "", false
	}
	uid, known := names[fields[1]]
	if !known {
		return "", "", false
	}
	status, err := readTaskSSHProcFile(directory, "status", 16<<10)
	if err != nil {
		return "", "", false
	}
	for _, line := range strings.Split(string(status), "\n") {
		value, ok := strings.CutPrefix(line, "Uid:")
		if !ok {
			continue
		}
		uids := strings.Fields(value)
		if len(uids) == 4 && uids[0] == uid && uids[1] == uid {
			terminal := fields[2]
			if terminal == "notty" {
				terminal = ""
			}
			return fields[1], terminal, true
		}
		return "", "", false
	}
	return "", "", false
}

func taskSSHProcessOwnsSocket(directory *os.File, fd, inode string) bool {
	var target [128]byte
	n, err := unix.Readlinkat(int(directory.Fd()), "fd/"+fd, target[:])
	return err == nil && n < len(target) && string(target[:n]) == "socket:["+inode+"]"
}

func (s *Service) taskSSHProcessRow(pid, fd, inode string, names map[string]string, executables map[[2]uint64]bool) (string, string, bool) {
	directory, err := os.OpenFile(s.systemPath("/proc/"+pid), os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_DIRECTORY|syscall.O_CLOEXEC, 0)
	if err != nil {
		return "", "", false
	}
	defer directory.Close()
	var exe unix.Stat_t
	if unix.Fstatat(int(directory.Fd()), "exe", &exe, 0) != nil ||
		!executables[[2]uint64{uint64(exe.Dev), exe.Ino}] || !taskSSHProcessOwnsSocket(directory, fd, inode) {
		return "", "", false
	}
	name, terminal, ok := taskSSHProcessUser(directory, names)
	var current unix.Stat_t
	return name, terminal, ok && taskSSHProcessOwnsSocket(directory, fd, inode) &&
		unix.Fstatat(int(directory.Fd()), "exe", &current, 0) == nil && current.Dev == exe.Dev && current.Ino == exe.Ino
}

// OpenSSH processes distinguish authenticated sessions from listeners and
// pre-authentication children. Require the kernel's socket and executable
// identities before interpreting the process title.
func (s *Service) taskOpenSSHInventory(ctx context.Context, out *taskInventory) error {
	executables := map[[2]uint64]bool{}
	for _, path := range []string{"/usr/sbin/sshd", "/usr/lib/openssh/sshd-session", "/usr/libexec/openssh/sshd-session"} {
		var file unix.Stat_t
		if unix.Stat(s.systemPath(path), &file) == nil && file.Uid == 0 &&
			file.Mode&unix.S_IFMT == unix.S_IFREG && file.Mode&0o022 == 0 {
			executables[[2]uint64{uint64(file.Dev), file.Ino}] = true
		}
	}
	if len(executables) == 0 {
		return nil
	}
	passwd, err := taskInventoryFile(s.systemPath("/etc/passwd"))
	if err != nil {
		return errors.New("无法核对 OpenSSH 会话所属的本地账户")
	}
	names := map[string]string{}
	for _, line := range strings.Split(string(passwd), "\n") {
		fields := strings.Split(line, ":")
		if len(fields) == 7 {
			names[fields[0]] = fields[2]
		}
	}
	raw, err := s.Config.RunWait(ctx, 5*time.Second, "/usr/bin/ss", "-H", "-n", "-t", "-p", "-e", "state", "established")
	if err != nil {
		return errors.New("无法读取 OpenSSH 已建立的连接")
	}
	seen := map[string]bool{}
	for _, line := range out.commandLines(raw) {
		fields := strings.Fields(line)
		inode := taskSSHSocketInode.FindStringSubmatch(line)
		if len(fields) < 5 || len(inode) != 2 || seen[inode[1]] {
			continue
		}
		host, port, err := net.SplitHostPort(fields[3])
		address, addressErr := netip.ParseAddr(host)
		number, portErr := strconv.ParseUint(port, 10, 16)
		if err != nil || addressErr != nil || portErr != nil || number == 0 {
			continue
		}
		for _, owner := range taskSSHSocketOwner.FindAllStringSubmatch(line, 16) {
			name, terminal, known := s.taskSSHProcessRow(owner[2], owner[3], inode[1], names, executables)
			if !known {
				continue
			}
			out.add(map[string]string{"name": name, "session": "ssh:" + inode[1], "terminal": terminal,
				"remote_host": address.Unmap().String(), "state": "active", "started_at": "",
				"source": "OpenSSH"})
			seen[inode[1]] = true
			break
		}
	}
	return nil
}
