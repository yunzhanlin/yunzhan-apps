//go:build linux

package executor

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

var redisPeerKernelChild = flag.String("redis-peer-kernel-child", "", "private kernel-peer fixture only")

// Real Linux Unix sockets, SO_PEERCRED, pidfds and changed process identity.
// The observe closure below is a fixture, NOT actual PID1/Redis instance
// acceptance. The normal API/default systemd path must be accepted separately.
func redisPeerKernelFixture(t *testing.T) (string, string) {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("actual Root CHOWN/SETUID kernel fixture")
	}
	base := os.Getenv("PANEL_QA_REDIS_PEER_MODEL_ROOT")
	if base == "" {
		base = "/var/lib/panel-executor"
	} else if !regexp.MustCompile(`^/var/lib/panel-executor/redis-peer-models24bktr-(arm64|amd64)\.[a-f0-9]{32}$`).MatchString(base) {
		t.Fatal("explicit private model root required")
	}
	if threatIDSTrustedParents(base, false) != nil {
		t.Fatal("unsafe model parent")
	}
	root, err := os.MkdirTemp(base, "redis-peer-fixture-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if filepath.Dir(root) != base || !strings.HasPrefix(filepath.Base(root), "redis-peer-fixture-") {
			t.Error("refuse broad cleanup")
			return
		}
		if err := os.RemoveAll(root); err != nil {
			t.Error(err)
		}
	})
	dir := filepath.Join(root, "run")
	if os.Mkdir(dir, 0700) != nil || os.Chown(dir, 0, 65534) != nil || os.Chmod(dir, 0770) != nil {
		t.Fatal("NEW private directory initialization")
	}
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	input, err := os.Open(self)
	if err != nil {
		t.Fatal(err)
	}
	defer input.Close()
	info, err := input.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > 128<<20 {
		t.Fatal("test executable capacity")
	}
	var space unix.Statfs_t
	if unix.Statfs(root, &space) != nil || space.Bavail*uint64(space.Bsize) <= uint64(info.Size())+(32<<20) {
		t.Fatal("private fixture free-space gate")
	}
	binary := filepath.Join(root, "child.test")
	output, err := os.OpenFile(binary, os.O_CREATE|os.O_EXCL|os.O_WRONLY|syscall.O_NOFOLLOW, 0500)
	if err != nil {
		t.Fatal(err)
	}
	n, copyErr := io.Copy(output, io.LimitReader(input, (128<<20)+1))
	if copyErr != nil || n != info.Size() || output.Chown(0, 0) != nil || output.Chmod(0555) != nil || output.Sync() != nil {
		output.Close()
		t.Fatal("sealed NEW fixture executable")
	}
	if err := output.Close(); err != nil {
		t.Fatal(err)
	}
	return dir, binary
}

type redisPeerChildHandle struct {
	command *exec.Cmd
	reader  *bufio.Reader
	pipe    *os.File
	stop    *os.File
	cancel  context.CancelFunc
	done    chan error
}

func redisPeerSpawnChild(t *testing.T, dir, binary, role string) *redisPeerChildHandle {
	t.Helper()
	directory, err := os.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer directory.Close()
	executable, err := os.Open(binary)
	if err != nil {
		t.Fatal(err)
	}
	defer executable.Close()
	read, write, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	stopRead, stopWrite, err := os.Pipe()
	if err != nil {
		read.Close()
		write.Close()
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 6*time.Second)
	cmd := exec.CommandContext(ctx, "/proc/self/fd/4", "-test.run=^TestRedisPeerKernelChild$", "-test.count=1", "-redis-peer-kernel-child="+role)
	cmd.ExtraFiles = []*os.File{directory, executable, write, stopRead}
	cmd.Env = []string{"PATH=/usr/bin:/bin", "LANG=C", "HOME=/nonexistent"}
	cmd.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: 65534, Gid: 65534, Groups: []uint32{65534}}}
	// Never inherit a secret or publish fixture protocol frames through logs.
	cmd.Stdout = io.Discard
	cmd.Stderr = io.Discard
	if err = cmd.Start(); err != nil {
		read.Close()
		write.Close()
		stopRead.Close()
		stopWrite.Close()
		cancel()
		t.Fatal("owned child start", err)
	}
	write.Close()
	stopRead.Close()
	h := &redisPeerChildHandle{cmd, bufio.NewReader(read), read, stopWrite, cancel, make(chan error, 1)}
	go func() { h.done <- cmd.Wait() }()
	t.Cleanup(func() {
		// Closing this private pipe asks ONLY our own child to exit. Root in
		// the narrowly capped fixture need not gain CAP_KILL for another UID.
		h.stop.Close()
		h.pipe.Close()
		defer h.cancel()
		select {
		case <-h.done:
		case <-time.After(2 * time.Second):
			t.Error("owned child not reaped")
		}
	})
	ready, err := h.reader.ReadString('\n')
	if err != nil || ready != "ready\n" {
		t.Fatal("owned peer not ready", err)
	}
	return h
}
func (h *redisPeerChildHandle) count(t *testing.T) int {
	t.Helper()
	line, err := h.reader.ReadString('\n')
	if err != nil {
		t.Fatal("owned peer observation missing", err)
	}
	var result struct {
		Bytes int `json:"bytes"`
	}
	if json.Unmarshal([]byte(line), &result) != nil || result.Bytes < 0 {
		t.Fatal("bad owned peer observation")
	}
	return result.Bytes
}

func TestRedisPeerKernelChild(t *testing.T) {
	role := *redisPeerKernelChild
	if role == "" {
		return
	} // Parent cases below run the real kernel interactions.
	if os.Geteuid() != 65534 || os.Getegid() != 65534 || unix.Prctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != nil {
		t.Fatal("private nonroot child policy")
	}
	report := os.NewFile(5, "private-parent-pipe")
	defer report.Close()
	if role == "idle" {
		io.WriteString(report, "ready\n")
		stop := os.NewFile(6, "private-parent-stop")
		defer stop.Close()
		var one [1]byte
		if n, err := stop.Read(one[:]); n != 0 || !errors.Is(err, io.EOF) {
			t.Fatal("private parent stop channel")
		}
		return
	}
	if role != "capture" && role != "control" {
		t.Fatal("unbound private role")
	}
	name := "/proc/self/fd/3/admin.sock"
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: name, Net: "unix"})
	if err != nil {
		t.Fatal("private child bind")
	}
	defer listener.Close()
	if os.Chmod(name, 0666) != nil {
		t.Fatal("NEW protected-parent socket mode")
	}
	listener.SetDeadline(time.Now().Add(1500 * time.Millisecond))
	io.WriteString(report, "ready\n")
	conn, err := listener.AcceptUnix()
	if err != nil {
		if timeout, ok := err.(net.Error); role == "capture" && ok && timeout.Timeout() {
			io.WriteString(report, "{\"bytes\":0}\n")
			return
		}
		t.Fatal("private child accept")
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(3 * time.Second))
	count := 0
	if role == "control" {
		reader := newRedisRESPReader(conn)
		auth, err := reader.value(0)
		values, ok := auth.([]any)
		if err != nil || !ok || len(values) != 3 || values[0] != "AUTH" || values[1] != "panel-admin" || values[2] != strings.Repeat("ab", 32) {
			t.Fatal("private control protocol")
		}
		frame, _ := redisRESPCommand([]string{"AUTH", "panel-admin", strings.Repeat("ab", 32)})
		count += len(frame)
		clear(frame)
		if _, err = io.WriteString(conn, "+OK\r\n"); err != nil {
			t.Fatal("private control response")
		}
		ping, err := reader.value(0)
		items, ok := ping.([]any)
		if err != nil || !ok || len(items) != 1 || items[0] != "PING" {
			t.Fatal("private control request")
		}
		count += 14
		if _, err = io.WriteString(conn, "+PONG\r\n"); err != nil {
			t.Fatal("private control reply")
		}
	} else {
		buf := make([]byte, 256)
		for {
			n, err := conn.Read(buf)
			count += n
			clear(buf)
			if err != nil {
				if !errors.Is(err, io.EOF) {
					if timeout, ok := err.(net.Error); !ok || !timeout.Timeout() {
						t.Fatal("private byte-count read")
					}
				}
				break
			}
			if count > 4096 {
				t.Fatal("unexpected fixture protocol capacity")
			}
		}
	}
	fmt.Fprintf(report, "{\"bytes\":%d}\n", count)
}

func redisPeerObservedChild(t *testing.T, child *redisPeerChildHandle) redisPeerIdentity {
	t.Helper()
	start, err := moduleProcessStart("/proc", child.command.Process.Pid)
	if err != nil {
		t.Fatal("owned actual process lifetime", err)
	}
	return redisPeerIdentity{Unit: redisPeerUnit{PID: child.command.Process.Pid, Invocation: strings.Repeat("a", 32), Cgroup: "private-fixture-NOT-PID1", Started: "1"}, Start: start, UID: 65534, GID: 65534, ProcessDevice: 1, ProcessInode: 1, ExecutableDevice: 1, ExecutableInode: 1}
}

func TestRedisPeerKernelMatchingIdentityUsesTheSameConnectionForAUTH(t *testing.T) {
	dir, binary := redisPeerKernelFixture(t)
	server := redisPeerSpawnChild(t, dir, binary, "control")
	identity := redisPeerObservedChild(t, server)
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()
	conn, directory, pidfd, err := dialRedisVerifiedAt(ctx, dir, redisServiceAccount{65534, 65534}, func(context.Context) (redisPeerIdentity, error) { return identity, nil })
	if err != nil {
		t.Fatal("genuine kernel peer refused", err)
	}
	defer directory.Close()
	defer unix.Close(pidfd)
	defer conn.Close()
	value, err := redisAuthenticatedCommand(ctx, conn, "panel-admin", strings.Repeat("ab", 32), 0, "PING")
	if err != nil || value != "PONG" {
		t.Fatal("verified private control failed", err)
	}
	conn.Close()
	if server.count(t) <= 64 {
		t.Fatal("legitimate AUTH/PING control not observed")
	}
}

func TestRedisPeerKernelSameUIDForeignPIDReceivesNoAUTHBytes(t *testing.T) {
	dir, binary := redisPeerKernelFixture(t)
	expected := redisPeerSpawnChild(t, dir, binary, "idle")
	server := redisPeerSpawnChild(t, dir, binary, "capture")
	identity := redisPeerObservedChild(t, expected)
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()
	conn, directory, pidfd, err := dialRedisVerifiedAt(ctx, dir, redisServiceAccount{65534, 65534}, func(context.Context) (redisPeerIdentity, error) { return identity, nil })
	if err == nil {
		conn.Close()
		directory.Close()
		unix.Close(pidfd)
		t.Fatal("same-UID foreign PID authorized")
	}
	if server.count(t) != 0 {
		t.Fatal("unverified peer received protocol bytes")
	}
}

func TestRedisPeerKernelGenerationChangeAndCancellationSendNoAUTH(t *testing.T) {
	for _, scenario := range []string{"generation", "cancel"} {
		t.Run(scenario, func(t *testing.T) {
			dir, binary := redisPeerKernelFixture(t)
			server := redisPeerSpawnChild(t, dir, binary, "capture")
			identity := redisPeerObservedChild(t, server)
			ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
			defer cancel()
			calls := 0
			conn, directory, pidfd, err := dialRedisVerifiedAt(ctx, dir, redisServiceAccount{65534, 65534}, func(context.Context) (redisPeerIdentity, error) {
				calls++
				value := identity
				if calls == 2 {
					if scenario == "generation" {
						value.Unit.Invocation = strings.Repeat("b", 32)
					} else {
						cancel()
					}
				}
				return value, nil
			})
			if err == nil {
				conn.Close()
				directory.Close()
				unix.Close(pidfd)
				t.Fatal("stale/canceled peer authorized")
			}
			if calls != 2 || server.count(t) != 0 {
				t.Fatal("changed authority reached a protocol write", calls)
			}
		})
	}
}

func TestRedisPeerKernelWrongOwnerAndUnknownDirectoryNeverRepairOrConnect(t *testing.T) {
	for _, scenario := range []string{"wrong-uid", "unknown-file", "public-mode"} {
		t.Run(scenario, func(t *testing.T) {
			dir, binary := redisPeerKernelFixture(t)
			server := redisPeerSpawnChild(t, dir, binary, "capture")
			identity := redisPeerObservedChild(t, server)
			account := redisServiceAccount{65534, 65534}
			if scenario == "wrong-uid" {
				account.UID = 65533
				identity.UID = 65533
			}
			if scenario == "unknown-file" {
				if os.WriteFile(filepath.Join(dir, "unknown"), []byte("preserve"), 0600) != nil {
					t.Fatal("new fixture")
				}
			}
			if scenario == "public-mode" {
				if os.Chmod(dir, 0777) != nil {
					t.Fatal("new fixture mode")
				}
			}
			before, _ := os.Lstat(dir)
			ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
			defer cancel()
			conn, directory, pidfd, err := dialRedisVerifiedAt(ctx, dir, account, func(context.Context) (redisPeerIdentity, error) { return identity, nil })
			if err == nil {
				conn.Close()
				directory.Close()
				unix.Close(pidfd)
				t.Fatal("unsafe peer authorized")
			}
			after, _ := os.Lstat(dir)
			if !geoStoreStableInfo(before, after) || server.count(t) != 0 {
				t.Fatal("unsafe state repaired or contacted")
			}
			if scenario == "unknown-file" {
				raw, err := os.ReadFile(filepath.Join(dir, "unknown"))
				if err != nil || string(raw) != "preserve" {
					t.Fatal("unknown data changed")
				}
			}
		})
	}
}
