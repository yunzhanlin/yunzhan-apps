//go:build linux

package executor

import (
	"context"
	"errors"
	"io"
	"local/panel/internal/core"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unicode"
	"unicode/utf8"

	"golang.org/x/sys/unix"
)

const taskInventoryLimit = 256
const taskInventoryFileLimit = 64 << 10
const taskInventoryCommandLimit = 32 << 10

type taskInventory struct {
	View      string              `json:"view"`
	CheckedAt string              `json:"checked_at"`
	Rows      []map[string]string `json:"rows"`
	Partial   bool                `json:"partial"`
	Available bool                `json:"available"`
	Detail    string              `json:"detail,omitempty"`
}

func taskInventoryText(value string, limit int) bool {
	return value != "" && len(value) <= limit && utf8.ValidString(value) &&
		strings.IndexFunc(value, unicode.IsControl) < 0
}

func (out *taskInventory) add(row map[string]string) {
	if len(out.Rows) >= taskInventoryLimit {
		out.Partial = true
		return
	}
	for _, field := range row {
		if field != "" && !taskInventoryText(field, 240) {
			out.Partial = true
			return
		}
	}
	out.Rows = append(out.Rows, row)
}

func (out *taskInventory) commandLines(raw string) []string {
	if len(raw) >= taskInventoryCommandLimit {
		out.Partial = true
		raw = raw[:taskInventoryCommandLimit]
		if last := strings.LastIndexByte(raw, '\n'); last >= 0 {
			raw = raw[:last]
		} else {
			return nil
		}
	}
	return strings.Split(strings.TrimSpace(raw), "\n")
}

func (s *Service) taskSystemdInventory(ctx context.Context, out *taskInventory) error {
	args := []string{"list-units", "--all", "--type=service", "--no-legend", "--no-pager", "--plain"}
	if out.View == "startup" {
		args = []string{"list-unit-files", "--type=service", "--no-legend", "--no-pager"}
	}
	raw, err := s.Config.RunWait(ctx, 5*time.Second, "/usr/bin/systemctl", args...)
	if err != nil {
		return errors.New("无法读取 systemd 服务清单")
	}
	for _, line := range out.commandLines(raw) {
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		if len(fields) < 2 || !strings.HasSuffix(fields[0], ".service") {
			out.Partial = true
			continue
		}
		if out.View == "startup" {
			preset := ""
			if len(fields) > 2 {
				preset = fields[2]
			}
			out.add(map[string]string{"name": fields[0], "startup_state": fields[1], "preset": preset})
		} else if len(fields) >= 4 {
			out.add(map[string]string{"name": fields[0], "load_state": fields[1], "active_state": fields[2],
				"sub_state": fields[3], "description": strings.Join(fields[4:], " ")})
		} else {
			out.Partial = true
		}
	}
	return nil
}

func taskInventoryFile(path string) ([]byte, error) {
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return readTaskInventoryFile(f)
}

func readTaskInventoryFile(f *os.File) ([]byte, error) {
	info, err := f.Stat()
	if err != nil {
		return nil, err
	}
	stat, valid := info.Sys().(*syscall.Stat_t)
	if !valid || stat.Uid != 0 || !info.Mode().IsRegular() || info.Mode().Perm()&0o022 != 0 {
		return nil, errors.New("系统清单文件身份无法核对")
	}
	raw, err := io.ReadAll(io.LimitReader(f, taskInventoryFileLimit+1))
	if len(raw) > taskInventoryFileLimit {
		return nil, errors.New("系统清单文件超出读取上限")
	}
	return raw, err
}

func (s *Service) taskLocalAccounts(out *taskInventory) error {
	raw, err := taskInventoryFile(s.systemPath("/etc/passwd"))
	if err != nil {
		return errors.New("无法读取本地账户清单")
	}
	for _, line := range strings.Split(strings.TrimSpace(string(raw)), "\n") {
		fields := strings.Split(line, ":")
		if len(fields) != 7 {
			out.Partial = true
			continue
		}
		_, uidErr := strconv.ParseUint(fields[2], 10, 32)
		_, gidErr := strconv.ParseUint(fields[3], 10, 32)
		if uidErr != nil || gidErr != nil {
			out.Partial = true
			continue
		}
		out.add(map[string]string{"name": fields[0], "uid": fields[2], "gid": fields[3],
			"home": fields[5], "shell": fields[6]})
	}
	return nil
}

func (out *taskInventory) cronFile(name string, raw []byte) {
	for _, line := range strings.Split(string(raw), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		if first, _, found := strings.Cut(line, "="); found && len(strings.Fields(strings.TrimSpace(first))) == 1 {
			continue
		}
		timingFields := 5
		if strings.HasPrefix(fields[0], "@") {
			timingFields = 1
		}
		if len(fields) <= timingFields+1 {
			out.Partial = true
			continue
		}
		out.add(map[string]string{"source": name, "timing": strings.Join(fields[:timingFields], " "),
			"account": fields[timingFields]})
	}
}

func (s *Service) taskCronInventory(out *taskInventory) error {
	const directory = "/etc/cron.d"
	raw, err := taskInventoryFile(s.systemPath("/etc/crontab"))
	if err == nil {
		out.cronFile("/etc/crontab", raw)
	} else if !errors.Is(err, os.ErrNotExist) {
		out.Partial = true
	}
	f, err := os.OpenFile(s.systemPath(directory), os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_DIRECTORY, 0)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return errors.New("无法读取系统 Cron 目录")
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return errors.New("无法核对系统 Cron 目录")
	}
	stat, valid := info.Sys().(*syscall.Stat_t)
	if !valid || stat.Uid != 0 || info.Mode().Perm()&0o022 != 0 {
		return errors.New("系统 Cron 目录权限无法核对")
	}
	names, err := f.Readdirnames(taskInventoryLimit + 1)
	if err != nil && !errors.Is(err, io.EOF) {
		return errors.New("无法读取系统 Cron 目录")
	}
	out.Partial = out.Partial || len(names) > taskInventoryLimit
	for _, name := range names[:min(len(names), taskInventoryLimit)] {
		if len(out.Rows) >= taskInventoryLimit {
			out.Partial = true
			break
		}
		if filepath.Base(name) != name || strings.Trim(name, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-") != "" {
			continue
		}
		label := directory + "/" + name
		fd, err := unix.Openat(int(f.Fd()), name, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
		if err != nil {
			out.Partial = true
			continue
		}
		child := os.NewFile(uintptr(fd), name)
		raw, err := readTaskInventoryFile(child)
		child.Close()
		if err != nil {
			out.Partial = true
			continue
		}
		out.cronFile(label, raw)
	}
	return nil
}

func (s *Service) taskSSHInventory(ctx context.Context, out *taskInventory) error {
	ctx, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()
	raw, err := s.Config.RunWait(ctx, 4*time.Second, "/usr/bin/loginctl", "list-sessions", "--no-legend", "--no-pager")
	if err != nil {
		return errors.New("无法读取系统会话清单")
	}
	ids := []string{}
	for _, line := range out.commandLines(raw) {
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		id := fields[0]
		if len(ids) >= 64 || len(id) > 40 || strings.HasPrefix(id, "-") ||
			strings.Trim(id, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-") != "" {
			out.Partial = true
			continue
		}
		ids = append(ids, id)
	}
	if len(ids) == 0 {
		return nil
	}
	args := []string{"show-session", "--no-pager", "--property=Id,Name,Service,Remote,RemoteHost,TTY,State,Timestamp", "--"}
	raw, err = s.Config.RunWait(ctx, 4*time.Second, "/usr/bin/loginctl", append(args, ids...)...)
	if err != nil {
		return errors.New("无法核对系统会话来源")
	}
	lines := strings.Join(out.commandLines(raw), "\n")
	for _, block := range strings.Split(lines, "\n\n") {
		fields := map[string]string{}
		for _, line := range strings.Split(block, "\n") {
			if key, value, found := strings.Cut(line, "="); found {
				fields[key] = value
			}
		}
		if fields["Remote"] == "yes" && fields["Service"] == "sshd" && fields["Id"] != "" && fields["Name"] != "" {
			out.add(map[string]string{"name": fields["Name"], "session": fields["Id"], "remote_host": fields["RemoteHost"],
				"terminal": fields["TTY"], "state": fields["State"], "started_at": fields["Timestamp"]})
		}
	}
	return nil
}

func (s *Service) taskNetworkInventory(ctx context.Context, out *taskInventory) error {
	raw, err := s.Config.RunWait(ctx, 5*time.Second, "/usr/bin/ss", "-H", "-n", "-t", "-u", "-a")
	if err != nil {
		return errors.New("无法读取当前 TCP 和 UDP 连接")
	}
	for _, line := range out.commandLines(raw) {
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		if len(fields) < 6 || fields[0] != "tcp" && fields[0] != "udp" {
			out.Partial = true
			continue
		}
		out.add(map[string]string{"protocol": fields[0], "state": fields[1], "receive_queue": fields[2],
			"send_queue": fields[3], "local": fields[4], "peer": fields[5]})
	}
	return nil
}

func (s *Service) taskInventoryRoutes(m *http.ServeMux) {
	m.HandleFunc("GET /v1/app-modules/task-manager/inventory/{view}", func(w http.ResponseWriter, r *http.Request) {
		view := r.PathValue("view")
		if !core.ValidTaskInventoryView(view) {
			respond(w, http.StatusNotFound, map[string]string{"error": "未知的任务管理清单"})
			return
		}
		status := s.appModuleStatus(r.Context(), "task-manager")
		if status.StateUnknown || !status.Installed || !core.TaskInventoryVersionSupported(status.Version) {
			respond(w, http.StatusConflict, map[string]string{"error": "请先通过签名应用商店安装或更新任务管理器"})
			return
		}
		if view == "sysv-startup" && status.Version != core.TaskSysVStartupAppVersion {
			respond(w, http.StatusConflict, map[string]string{"error": "SysV 启动清单需要任务管理器 1.3.1"})
			return
		}
		out := taskInventory{View: view, CheckedAt: core.Now(), Rows: []map[string]string{}}
		var err error
		switch view {
		case "services", "startup":
			err = s.taskSystemdInventory(r.Context(), &out)
		case "sysv-startup":
			err = s.taskSysVStartup(&out)
		case "accounts":
			err = s.taskLocalAccounts(&out)
		case "cron":
			err = s.taskCronInventory(&out)
		case "ssh":
			err = s.taskSSHInventory(r.Context(), &out)
		case "network":
			err = s.taskNetworkInventory(r.Context(), &out)
		}
		out.Available = err == nil
		if err != nil {
			out.Detail = err.Error()
		}
		respond(w, http.StatusOK, out)
	})
}
