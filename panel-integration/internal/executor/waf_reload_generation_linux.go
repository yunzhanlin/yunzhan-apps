//go:build linux

package executor

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// A successful fingerprint from ONE new worker is not a reload barrier: an
// old worker can still accept the next connection before it processes QUIT.
// Capture actual pre-reload worker identities and listener socket inodes. Wait
// until those workers have closed their listeners, not until their existing
// clients finish. Never kill workers, change shutdown timeouts or retry a
// customer's request. Long-running pre-existing clients retain their old config.
// https://nginx.org/en/docs/control.html#reconfiguration
type wafReloadGeneration struct {
	ProcRoot  string
	Binary    string
	Master    wafReloadProcess
	Workers   []wafReloadProcess
	Listeners map[string]bool
}

type wafReloadProcess struct {
	PID, Parent int
	Start       uint64
	State       string
}

func readWAFReloadProcess(root string, pid int) (wafReloadProcess, error) {
	result := wafReloadProcess{PID: pid}
	if pid <= 1 {
		return result, errors.New("Nginx 进程标识无效")
	}
	data, err := readModuleProcFile(filepath.Join(root, strconv.Itoa(pid), "stat"), 8192)
	if err != nil {
		return result, err
	}
	if !strings.HasPrefix(string(data), strconv.Itoa(pid)+" (") {
		return result, errors.New("Nginx 进程身份不可验证")
	}
	stat, err := parseProcStat(pid, string(data), uint64(os.Getpagesize()))
	fields := strings.Fields(string(data)[strings.LastIndexByte(string(data), ')')+1:])
	if err != nil || len(fields) < 20 || stat.StartTime == 0 {
		return result, errors.New("Nginx 进程启动身份不可验证")
	}
	result.Parent, err = strconv.Atoi(fields[1])
	if err != nil || result.Parent < 0 {
		return result, errors.New("Nginx 父进程身份不可验证")
	}
	result.Start, result.State = stat.StartTime, stat.State
	return result, nil
}

// Parse only listening TCP, bound unconnected UDP and listening Unix sockets.
// Established clients, connected syslog sockets and worker control socketpairs
// must not make a graceful reload wait for all old clients to disconnect.
func wafListenerTable(data []byte, protocol string) (map[string]bool, error) {
	if protocol != "tcp" && protocol != "tcp6" && protocol != "udp" && protocol != "udp6" && protocol != "unix" {
		return nil, errors.New("未支持的监听套接字表")
	}
	result := map[string]bool{}
	lines := strings.Split(string(data), "\n")
	if len(lines) < 2 || len(lines) > 131073 {
		return nil, errors.New("Nginx 监听套接字表缺失或超限")
	}
	for _, line := range lines[1:] {
		if strings.TrimSpace(line) == "" {
			continue
		}
		fields := strings.Fields(line)
		inode, listening := "", false
		switch protocol {
		case "tcp", "tcp6":
			if len(fields) < 10 {
				return nil, errors.New("TCP 监听套接字表无效")
			}
			inode, listening = fields[9], fields[3] == "0A"
		case "udp", "udp6":
			if len(fields) < 10 {
				return nil, errors.New("UDP 监听套接字表无效")
			}
			inode, listening = fields[9], fields[3] == "07" && !strings.HasSuffix(fields[1], ":0000") && strings.HasSuffix(fields[2], ":0000")
		case "unix":
			if len(fields) < 7 {
				return nil, errors.New("Unix 监听套接字表无效")
			}
			inode, listening = fields[6], fields[3] == "00010000" && fields[4] == "0001" && fields[5] == "01"
		default:
			return nil, errors.New("未支持的监听套接字表")
		}
		if listening {
			n, err := strconv.ParseUint(inode, 10, 64)
			if err != nil || n == 0 {
				return nil, errors.New("监听套接字 inode 无效")
			}
			result[strconv.FormatUint(n, 10)] = true
		}
	}
	return result, nil
}

func wafProcessSockets(ctx context.Context, root string, pid int) (map[string]bool, error) {
	dir := filepath.Join(root, strconv.Itoa(pid), "fd")
	f, err := os.Open(dir)
	if err != nil {
		return nil, err
	}
	entries, err := f.ReadDir(65537)
	f.Close()
	if err != nil && !errors.Is(err, io.EOF) {
		return nil, err
	}
	if len(entries) > 65536 {
		return nil, errors.New("Nginx 文件描述符超过可验证预算")
	}
	result := map[string]bool{}
	for _, entry := range entries {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if _, err := strconv.ParseUint(entry.Name(), 10, 32); err != nil {
			return nil, errors.New("Nginx 文件描述符标识无效")
		}
		value, err := os.Readlink(filepath.Join(dir, entry.Name()))
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return nil, err
		}
		if strings.HasPrefix(value, "socket:[") && strings.HasSuffix(value, "]") {
			inode := strings.TrimSuffix(strings.TrimPrefix(value, "socket:["), "]")
			n, err := strconv.ParseUint(inode, 10, 64)
			if err != nil || n == 0 {
				return nil, errors.New("Nginx 套接字身份无效")
			}
			result[strconv.FormatUint(n, 10)] = true
		}
	}
	return result, nil
}

func captureWAFReloadGeneration(ctx context.Context, root, binary string, pid int) (*wafReloadGeneration, error) {
	master, err := readWAFReloadProcess(root, pid)
	if err != nil || master.State == "Z" || master.State == "X" {
		return nil, errors.New("Nginx 主进程启动身份不可验证")
	}
	g := &wafReloadGeneration{ProcRoot: root, Binary: binary, Master: master, Listeners: map[string]bool{}}
	actual, err := os.Readlink(filepath.Join(root, strconv.Itoa(pid), "exe"))
	if err != nil || actual != binary {
		return nil, errors.New("Nginx 监听主进程程序不匹配")
	}
	listeners := map[string]bool{}
	for _, protocol := range []string{"tcp", "tcp6", "udp", "udp6", "unix"} {
		data, err := readModuleProcFile(filepath.Join(root, strconv.Itoa(pid), "net", protocol), 16<<20)
		// Disabled IPv6 kernels do not expose these two optional tables.
		if errors.Is(err, os.ErrNotExist) && (protocol == "tcp6" || protocol == "udp6") {
			continue
		}
		if err != nil {
			return nil, err
		}
		parsed, err := wafListenerTable(data, protocol)
		if err != nil {
			return nil, err
		}
		for inode := range parsed {
			listeners[inode] = true
		}
	}
	sockets, err := wafProcessSockets(ctx, root, pid)
	if err != nil {
		return nil, err
	}
	for inode := range sockets {
		if listeners[inode] {
			g.Listeners[inode] = true
		}
	}
	if len(g.Listeners) == 0 {
		return nil, errors.New("Nginx 主进程未确认持有监听套接字")
	}
	data, err := readModuleProcFile(filepath.Join(root, strconv.Itoa(pid), "task", strconv.Itoa(pid), "children"), 16384)
	if err != nil {
		return nil, err
	}
	children := strings.Fields(string(data))
	if len(children) == 0 || len(children) > 1024 {
		return nil, errors.New("Nginx 工作进程列表缺失或超限")
	}
	seen := map[int]bool{}
	for _, child := range children {
		id, err := strconv.Atoi(child)
		if err != nil || id <= 1 || seen[id] {
			return nil, errors.New("Nginx 子进程标识无效或重复")
		}
		seen[id] = true
		p, err := readWAFReloadProcess(root, id)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return nil, err
		}
		if p.State == "Z" || p.State == "X" {
			continue
		}
		if p.Parent != pid {
			return nil, errors.New("Nginx 工作进程父身份变化")
		}
		title, err := readModuleProcFile(filepath.Join(root, child, "cmdline"), 8192)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return nil, err
		}
		if !strings.HasPrefix(string(title), "nginx: worker process") {
			continue
		}
		actual, err := os.Readlink(filepath.Join(root, child, "exe"))
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil || actual != binary {
			return nil, errors.New("Nginx 工作进程程序无法验证")
		}
		g.Workers = append(g.Workers, p)
	}
	if len(g.Workers) == 0 {
		return nil, errors.New("Nginx 未确认具有正在工作的进程")
	}
	current, err := readWAFReloadProcess(root, pid)
	if err != nil || current.Start != master.Start {
		return nil, errors.New("Nginx 主进程在重载准备中变化")
	}
	return g, nil
}

func (s *Service) captureWAFReloadGeneration(ctx context.Context, nginx string) (*wafReloadGeneration, error) {
	if s.Config.SystemRoot != "/" || s.Config.SitesDir != "/srv/panel/sites" {
		return nil, nil
	}
	pid, err := s.wafNginxPID(ctx, nginx)
	if err != nil {
		return nil, err
	}
	return captureWAFReloadGeneration(ctx, s.systemPath("/proc"), nginx, pid)
}

func (g *wafReloadGeneration) drained(ctx context.Context) (bool, error) {
	master, err := readWAFReloadProcess(g.ProcRoot, g.Master.PID)
	if err != nil || master.Start != g.Master.Start || master.State == "Z" || master.State == "X" {
		return false, errors.New("Nginx 主进程在重载交接中变化")
	}
	actual, err := os.Readlink(filepath.Join(g.ProcRoot, strconv.Itoa(g.Master.PID), "exe"))
	if err != nil || actual != g.Binary {
		return false, errors.New("Nginx 主进程程序在重载中变化")
	}
	for _, previous := range g.Workers {
		current, err := readWAFReloadProcess(g.ProcRoot, previous.PID)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return false, err
		}
		if current.Start != previous.Start || current.State == "Z" || current.State == "X" {
			continue
		}
		if current.Parent != g.Master.PID {
			return false, errors.New("Nginx 旧工作进程父身份变化")
		}
		sockets, err := wafProcessSockets(ctx, g.ProcRoot, previous.PID)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return false, err
		}
		for inode := range sockets {
			if g.Listeners[inode] {
				return false, nil
			}
		}
		// Recheck PID/start after the fd snapshot. A dead/reused PID is not an
		// old worker; an unreadable live worker must never be counted as drained.
		again, err := readWAFReloadProcess(g.ProcRoot, previous.PID)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return false, err
		}
		if again.Start == previous.Start && again.Parent != g.Master.PID {
			return false, errors.New("Nginx 工作进程身份无法核对")
		}
	}
	return true, ctx.Err()
}

func waitWAFReloadGeneration(ctx context.Context, g *wafReloadGeneration) error {
	if g == nil {
		return nil
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	for {
		done, err := g.drained(ctx)
		if err != nil {
			return err
		}
		if done {
			return nil
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("旧 Nginx 工作进程仍持有监听套接字: %w", ctx.Err())
		case <-time.After(100 * time.Millisecond):
		}
	}
}
