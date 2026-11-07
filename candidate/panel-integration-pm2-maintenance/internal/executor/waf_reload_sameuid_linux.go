//go:build linux

package executor

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

// No ptrace capability is needed to read a www-data worker's executable or
// socket links. The fixed same-UID reader has no active/inherited/ambient
// capabilities, NNP, no shell, no configurable program/user/path, bounded
// numeric output, and an independently held stable pidfd. Failure is never
// interpreted as a closed listener. Non-canonical fixture proc roots do not
// use this real-host fallback.
var errWAFWorkerTitleUnverifiable = errors.New("Nginx 工作进程标题不可核对")

// Only fixed stage/reason labels are public. Never forward child stderr,
// environment, command arguments or a private file path in a failure receipt.
func wafSameUIDReadFailure(operation, step string, runErr, contextErr error, truncated, stderrPresent bool) error {
	if (operation != "exe" && operation != "sockets") || (step != "executable" && step != "descriptor-count" && step != "socket-inodes") {
		return errors.New("Nginx 同身份只读核对失败（固定步骤无法核对）")
	}
	reason := "子进程未成功退出"
	if truncated {
		reason = "有界输出超限"
	} else if contextErr != nil {
		if errors.Is(contextErr, context.DeadlineExceeded) {
			reason = "原有读取期限已到"
		} else {
			reason = "原读取上下文已取消"
		}
	} else if stderrPresent {
		reason = "子进程报告读取异常"
	} else if runErr == nil {
		reason = "读取结果无法核对"
	}
	return fmt.Errorf("Nginx 同身份只读核对失败（%s/%s：%s）；未据此认定监听已关闭", operation, step, reason)
}

func wafSameUIDWorkerRead(ctx context.Context, root, binary string, worker wafReloadProcess, operation string) ([]byte, error) {
	if root != "/proc" || os.Geteuid() != 0 || worker.PID <= 1 || worker.Parent <= 1 || worker.Start == 0 || (operation != "exe" && operation != "sockets") {
		return nil, errors.New("Nginx 同身份只读核对参数异常")
	}
	account, err := user.Lookup("www-data")
	if err != nil {
		return nil, err
	}
	uid, err := strconv.ParseUint(account.Uid, 10, 32)
	if err != nil || uid == 0 {
		return nil, errors.New("Nginx 工作进程账户异常")
	}
	gid, err := strconv.ParseUint(account.Gid, 10, 32)
	nnp, nnpErr := unix.PrctlRetInt(unix.PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0)
	if err != nil || gid == 0 || nnpErr != nil || nnp != 1 {
		return nil, errors.New("同身份只读核对缺少固定账户或禁止提权约束")
	}
	fd, err := unix.PidfdOpen(worker.PID, 0)
	if errors.Is(err, unix.ESRCH) {
		return nil, os.ErrNotExist
	}
	if err != nil {
		return nil, err
	}
	defer unix.Close(fd)
	check := func() error {
		pid, err := compilerPIDFDTask(fd)
		if err == nil && pid == -1 {
			return os.ErrNotExist
		}
		if err != nil || pid != worker.PID {
			return errors.New("Nginx 稳定工作进程已退出或不可核对")
		}
		current, err := readWAFReloadProcess(root, worker.PID)
		if errors.Is(err, os.ErrNotExist) || err == nil && (current.Start != worker.Start || current.State == "Z" || current.State == "X") {
			return os.ErrNotExist
		}
		if err != nil || current.Parent != worker.Parent {
			return errors.New("Nginx 工作进程启动身份发生变化")
		}
		status, err := readModuleProcFile(filepath.Join(root, strconv.Itoa(worker.PID), "status"), 32<<10)
		if err != nil {
			return err
		}
		if err := wafSameUIDWorkerIdentity(status, uid, worker.Parent); err != nil {
			return err
		}
		title, err := readModuleProcFile(filepath.Join(root, strconv.Itoa(worker.PID), "cmdline"), 8192)
		if err != nil || !strings.HasPrefix(string(title), "nginx: worker process") {
			return errWAFWorkerTitleUnverifiable
		}
		return nil
	}
	if err := check(); err != nil {
		return nil, err
	}
	for _, path := range []string{"/usr/bin/setpriv", "/usr/bin/stat", "/usr/bin/find"} {
		if err := wafSameUIDTrustedProgram(path); err != nil {
			return nil, err
		}
	}
	args := []string{"--no-new-privs", "--inh-caps=-all", "--ambient-caps=-all", "--"}
	maxBytes := 4 << 20
	if operation == "exe" {
		args = append(args, "/usr/bin/stat", "-L", "--format=%d:%i", "--", filepath.Join(root, strconv.Itoa(worker.PID), "exe"))
		maxBytes = 128
	} else {
		// find emits ONLY socket links, never request files, command arguments,
		// environment or the names of other descriptors. Parsing below accepts
		// only canonical positive integer inodes, including a real empty set.
		args = append(args, "/usr/bin/find", filepath.Join(root, strconv.Itoa(worker.PID), "fd"), "-maxdepth", "1", "-type", "l", "-lname", "socket:*", "-printf", "%l\n")
	}
	bounded, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	run := func(step string, arguments []string, limit int) ([]byte, error) {
		// Switch in the fork child, clear supplementary groups, then exec the
		// fixed setpriv/tool chain. No PAM supervisor, shell, extra session or
		// forked reader survives cancellation of this owned process.
		cmd := exec.CommandContext(bounded, "/usr/bin/setpriv", arguments...)
		cmd.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: uint32(uid), Gid: uint32(gid), Groups: []uint32{}}}
		cmd.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LANG=C", "LC_ALL=C"}
		stdout, stderr := &boundedBuffer{max: limit}, &boundedBuffer{max: 4096}
		cmd.Stdout, cmd.Stderr = stdout, stderr
		if err := cmd.Run(); err != nil || stdout.truncated || stderr.truncated || len(stderr.Bytes()) != 0 {
			if changed := check(); changed != nil {
				return nil, changed
			}
			return nil, wafSameUIDReadFailure(operation, step, err, bounded.Err(), stdout.truncated || stderr.truncated, len(stderr.Bytes()) != 0)
		}
		return stdout.Bytes(), nil
	}
	verifyExecutable := func(data []byte) error {
		dev, ino, err := wafSameUIDExecutableInode(data)
		selected, statErr := os.Stat(binary)
		if err != nil || statErr != nil || !selected.Mode().IsRegular() || selected.Mode().Perm()&0022 != 0 {
			return errors.New("Nginx 选定程序身份不可核对")
		}
		meta, ok := selected.Sys().(*syscall.Stat_t)
		if !ok || meta.Uid != 0 || meta.Nlink != 1 || dev != uint64(meta.Dev) || ino != meta.Ino {
			return errors.New("Nginx 工作进程不是选定程序 inode")
		}
		return nil
	}
	if operation == "sockets" {
		exeArgs := []string{"--no-new-privs", "--inh-caps=-all", "--ambient-caps=-all", "--", "/usr/bin/stat", "-L", "--format=%d:%i", "--", filepath.Join(root, strconv.Itoa(worker.PID), "exe")}
		identity, err := run("executable", exeArgs, 128)
		if err != nil {
			return nil, err
		}
		if err := verifyExecutable(identity); err != nil {
			return nil, err
		}
		countArgs := []string{"--no-new-privs", "--inh-caps=-all", "--ambient-caps=-all", "--", "/usr/bin/find", filepath.Join(root, strconv.Itoa(worker.PID), "fd"), "-mindepth", "1", "-maxdepth", "1", "-printf", "%f\n"}
		data, err := run("descriptor-count", countArgs, 1<<20)
		if err != nil {
			return nil, err
		}
		if err := wafSameUIDDescriptorNames(data); err != nil {
			return nil, err
		}
	}
	step := "executable"
	if operation == "sockets" {
		step = "socket-inodes"
	}
	data, err := run(step, args, maxBytes)
	if err != nil {
		return nil, err
	}
	if err := check(); err != nil {
		return nil, err
	}
	if operation == "exe" {
		if err := verifyExecutable(data); err != nil {
			return nil, err
		}
	} else if _, err := wafSameUIDSocketInodes(data); err != nil {
		return nil, err
	}
	return data, nil
}

func wafSameUIDWorkerIdentity(data []byte, uid uint64, parent int) error {
	if len(data) == 0 || len(data) > 32<<10 || uid == 0 || parent <= 1 {
		return errors.New("Nginx 工作进程账户记录异常")
	}
	fields := map[string]string{}
	for _, line := range strings.Split(string(data), "\n") {
		key, value, ok := strings.Cut(line, ":")
		if !ok || (key != "Uid" && key != "PPid") {
			continue
		}
		if _, exists := fields[key]; exists {
			return errors.New("Nginx 工作进程账户记录重复")
		}
		fields[key] = strings.TrimSpace(value)
	}
	ids := strings.Fields(fields["Uid"])
	if len(ids) != 4 || fields["PPid"] != strconv.Itoa(parent) {
		return errors.New("Nginx 工作进程父身份异常")
	}
	for _, value := range ids {
		if value != strconv.FormatUint(uid, 10) {
			return errors.New("拒绝切换到任意或尚未转换的进程账户")
		}
	}
	return nil
}

func wafSameUIDTrustedProgram(path string) error {
	real, err := filepath.EvalSymlinks(path)
	if err != nil || !filepath.IsAbs(real) {
		return errors.New("同身份只读系统程序不可核对")
	}
	info, err := os.Lstat(real)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0111 == 0 || info.Mode()&os.ModeSetuid != 0 || info.Mode()&os.ModeSetgid != 0 {
		return errors.New("同身份只读系统程序类型或模式异常")
	}
	for current := real; ; current = filepath.Dir(current) {
		info, err := os.Lstat(current)
		if err != nil || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0022 != 0 {
			return errors.New("同身份只读系统程序父目录不可信")
		}
		meta, ok := info.Sys().(*syscall.Stat_t)
		if !ok || meta.Uid != 0 {
			return errors.New("同身份只读系统程序不是 root 所有")
		}
		if current == "/" {
			break
		}
	}
	return nil
}

func wafSameUIDExecutableInode(data []byte) (uint64, uint64, error) {
	if len(data) < 4 || len(data) > 128 || !bytes.HasSuffix(data, []byte{'\n'}) || bytes.ContainsAny(data[:len(data)-1], "\n\r\x00") {
		return 0, 0, errors.New("同身份程序 inode 输出异常")
	}
	parts := strings.Split(string(data[:len(data)-1]), ":")
	if len(parts) != 2 {
		return 0, 0, errors.New("同身份程序 inode 字段异常")
	}
	values := [2]uint64{}
	for index, part := range parts {
		n, err := strconv.ParseUint(part, 10, 64)
		if err != nil || n == 0 || strconv.FormatUint(n, 10) != part {
			return 0, 0, errors.New("同身份程序 inode 非规范整数")
		}
		values[index] = n
	}
	return values[0], values[1], nil
}

func wafSameUIDSocketInodes(data []byte) (map[string]bool, error) {
	if len(data) > 4<<20 || bytes.ContainsAny(data, "\r\x00") || len(data) > 0 && !bytes.HasSuffix(data, []byte{'\n'}) {
		return nil, errors.New("同身份监听 inode 输出异常或超限")
	}
	result := map[string]bool{}
	if len(data) == 0 {
		return result, nil
	}
	lines := strings.Split(string(data[:len(data)-1]), "\n")
	if len(lines) > 65536 {
		return nil, errors.New("同身份监听 inode 超过描述符预算")
	}
	for _, line := range lines {
		if !strings.HasPrefix(line, "socket:[") || !strings.HasSuffix(line, "]") {
			return nil, errors.New("同身份监听输出不是纯 inode")
		}
		value := line[len("socket:[") : len(line)-1]
		n, err := strconv.ParseUint(value, 10, 64)
		if err != nil || n == 0 || strconv.FormatUint(n, 10) != value {
			return nil, errors.New("同身份监听 inode 非规范整数")
		}
		result[value] = true // duplicated descriptors may own the same socket.
	}
	return result, nil
}

func wafSameUIDDescriptorNames(data []byte) error {
	if len(data) > 1<<20 || bytes.ContainsAny(data, "\r\x00") || len(data) > 0 && !bytes.HasSuffix(data, []byte{'\n'}) {
		return errors.New("同身份描述符记录格式异常")
	}
	if len(data) == 0 {
		return nil
	}
	lines := strings.Split(string(data[:len(data)-1]), "\n")
	if len(lines) > 65536 {
		return errors.New("同身份描述符超过可核对预算")
	}
	seen := map[string]bool{}
	for _, line := range lines {
		n, err := strconv.ParseUint(line, 10, 32)
		if err != nil || strconv.FormatUint(n, 10) != line || seen[line] {
			return errors.New("同身份描述符不是唯一规范整数")
		}
		seen[line] = true
	}
	return nil
}

func wafReloadWorkerExecutable(ctx context.Context, root, binary string, worker wafReloadProcess) error {
	actual, err := os.Readlink(filepath.Join(root, strconv.Itoa(worker.PID), "exe"))
	if errors.Is(err, os.ErrPermission) && root == "/proc" {
		_, err = wafSameUIDWorkerRead(ctx, root, binary, worker, "exe")
		return err
	}
	if err != nil {
		return err
	}
	if actual != binary {
		return errors.New("Nginx 工作进程程序无法验证")
	}
	return nil
}

func wafReloadWorkerSockets(ctx context.Context, root, binary string, worker wafReloadProcess) (map[string]bool, error) {
	sockets, err := wafProcessSockets(ctx, root, worker.PID)
	if errors.Is(err, os.ErrPermission) && root == "/proc" {
		data, readErr := wafSameUIDWorkerRead(ctx, root, binary, worker, "sockets")
		if readErr != nil {
			return nil, readErr
		}
		return wafSameUIDSocketInodes(data)
	}
	return sockets, err
}
