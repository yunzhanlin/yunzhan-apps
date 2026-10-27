//go:build linux

package executor

import (
	"context"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"

	"local/panel/internal/loadbalancestream"
)

// Actual CURRENT panel.service listener ports, not hard-coded19100, configured
// text/argv, a supplied PID or every database/backend port on the server. This
// is READ-ONLY admission metadata, not native mutation/ownership authority.
// The existing Root dispatcher can inspect the unprivileged Core; a missing
// permission refuses rather than widening the account child capabilities.
func observeLoadBalanceStreamControlPorts(ctx context.Context) ([]int, error) {
	if ctx == nil || ctx.Err() != nil {
		return nil, loadbalancestream.ErrService
	}
	raw, err := programQueueCommand(ctx, "/usr/bin/systemctl", "show", "panel.service", "--property=Id,LoadState,ActiveState,SubState,MainPID,ControlPID")
	if err != nil {
		return nil, loadbalancestream.ErrService
	}
	pid, err := decodeStreamCoreListenerOwner([]byte(raw))
	if err != nil {
		return nil, err
	}
	pidfd, err := unix.PidfdOpen(pid, 0)
	if err != nil {
		return nil, loadbalancestream.ErrService
	}
	defer unix.Close(pidfd)
	before, err := readWAFReloadProcess("/proc", pid)
	if err != nil || before.State == "Z" || before.State == "X" {
		return nil, loadbalancestream.ErrService
	}
	exe, err := os.Stat(filepath.Join("/proc", strconv.Itoa(pid), "exe"))
	if err != nil || !exe.Mode().IsRegular() || exe.Mode().Perm()&0022 != 0 {
		return nil, loadbalancestream.ErrService
	}
	census, err := observeLoadBalanceStreamHostSockets(ctx)
	if err != nil {
		return nil, loadbalancestream.ErrService
	}
	defer census.close()
	namespace, err := os.Stat(filepath.Join("/proc", strconv.Itoa(pid), "ns/net"))
	if err != nil || !os.SameFile(namespace, census.before) {
		return nil, loadbalancestream.ErrService
	}
	fds, err := wafProcessSockets(ctx, "/proc", pid)
	if err != nil {
		return nil, loadbalancestream.ErrService
	}
	ports := map[int]bool{19100: true, 19102: true, 19080: true}
	actual := 0
	for _, socket := range census.sockets {
		if (socket.Protocol == "tcp" || socket.Protocol == "tcp6") && socket.State == 10 && socket.Inode != 0 && fds[strconv.FormatUint(socket.Inode, 10)] {
			ports[int(socket.Local.Port())] = true
			actual++
		}
	}
	if actual == 0 || len(ports) > 1024 {
		return nil, loadbalancestream.ErrService
	}
	after, err := readWAFReloadProcess("/proc", pid)
	poll := []unix.PollFd{{Fd: int32(pidfd), Events: unix.POLLIN}}
	n, pollErr := unix.Poll(poll, 0)
	exeAfter, exeErr := os.Stat(filepath.Join("/proc", strconv.Itoa(pid), "exe"))
	if err != nil || after.Start != before.Start || after.State == "Z" || after.State == "X" || pollErr != nil || n != 0 || poll[0].Revents != 0 || exeErr != nil || !geoStoreStableInfo(exe, exeAfter) || !census.current() || ctx.Err() != nil {
		return nil, loadbalancestream.ErrService
	}
	current, err := programQueueCommand(ctx, "/usr/bin/systemctl", "show", "panel.service", "--property=Id,LoadState,ActiveState,SubState,MainPID,ControlPID")
	currentPID, e2 := decodeStreamCoreListenerOwner([]byte(current))
	if err != nil || e2 != nil || currentPID != pid {
		return nil, loadbalancestream.ErrService
	}
	out := make([]int, 0, len(ports))
	for port := range ports {
		out = append(out, port)
	}
	slices.Sort(out)
	return out, nil
}

func decodeStreamCoreListenerOwner(raw []byte) (int, error) {
	if len(raw) == 0 || len(raw) > 4096 || !strings.HasSuffix(string(raw), "\n") || strings.ContainsAny(string(raw), "\x00\r") {
		return 0, loadbalancestream.ErrService
	}
	want := map[string]string{"Id": "panel.service", "LoadState": "loaded", "ActiveState": "active", "SubState": "running", "ControlPID": "0"}
	seen := map[string]bool{}
	pid := 0
	for _, line := range strings.Split(strings.TrimSuffix(string(raw), "\n"), "\n") {
		key, value, ok := strings.Cut(line, "=")
		if !ok || seen[key] {
			return 0, loadbalancestream.ErrService
		}
		seen[key] = true
		if key == "MainPID" {
			var err error
			pid, err = strconv.Atoi(value)
			if err != nil || pid < 2 || pid > 1<<30 || strconv.Itoa(pid) != value {
				return 0, loadbalancestream.ErrService
			}
		} else if expected, ok := want[key]; !ok || value != expected {
			return 0, loadbalancestream.ErrService
		}
	}
	if len(seen) != 6 || pid < 2 {
		return 0, loadbalancestream.ErrService
	}
	return pid, nil
}
