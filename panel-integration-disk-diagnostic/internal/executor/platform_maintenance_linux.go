//go:build linux

package executor

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
	"local/panel/internal/core"
	"local/panel/internal/upgradeguard"
)

// Fixed Root-only original receipts. The unexported function seam is used only
// by synthetic filesystem tests; no path/runner is supplied by a request.
type platformMaintenanceStore struct {
	base  string
	plan  func(context.Context) (core.PlatformMaintenancePlan, error)
	run   func(context.Context, string) error
	fault func(string) error
}

func (s platformMaintenanceStore) open(create bool) (*statisticsGeoDirectory, error) {
	return geoJobDirectory(s.base, create)
}
func platformMaintenanceRead(root *os.Root, name string) (core.PlatformMaintenanceRecord, error) {
	var out core.PlatformMaintenanceRecord
	raw, e := geoStoreRead(root, name, 4096)
	if e != nil {
		return out, e
	}
	var shape struct{ Request json.RawMessage }
	if json.Unmarshal(raw, &out) != nil || json.Unmarshal(raw, &shape) != nil {
		return out, errors.New("原维护记录不可解析")
	}
	in, e := core.DecodePlatformMaintenanceNativeRequest(shape.Request)
	if e != nil {
		return out, e
	}
	return core.DecodePlatformMaintenanceRecord(raw, in)
}
func (s platformMaintenanceStore) read(id string) (core.PlatformMaintenanceRecord, error) {
	var out core.PlatformMaintenanceRecord
	if !core.ValidID(id) {
		return out, errors.New("原维护ID无效")
	}
	d, e := s.open(false)
	if e != nil {
		return out, e
	}
	defer d.Close()
	started, e := platformMaintenanceRead(d.Root, id+".request.json")
	if errors.Is(e, os.ErrNotExist) {
		return out, e
	}
	if e != nil || started.State != "started" || started.Request.Input.RequestID != id {
		return out, errors.New("原开始记录绑定无效")
	}
	lock, e := d.OpenFile(id+".lock", os.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if e != nil {
		return out, errors.New("原维护锁缺失或不能核对，不将其当作新任务")
	}
	defer lock.Close()
	opened, e := lock.Stat()
	visible, ve := d.Lstat(id + ".lock")
	if e != nil || ve != nil || !moduleRecordInfo(opened, false, false) || opened.Size() != 0 || !geoStoreStableInfo(opened, visible) {
		return out, errors.New("原维护锁身份无效")
	}
	out, e = platformMaintenanceRead(d.Root, id+".result.json")
	if errors.Is(e, os.ErrNotExist) {
		if !d.current() {
			return out, errors.New("原维护目录变化")
		}
		return started, nil
	}
	if e != nil || out.Request != started.Request || out.RequestSHA != started.RequestSHA || out.State == "started" || !d.current() {
		return out, errors.New("原终态与开始记录不同")
	}
	return out, nil
}
func (s platformMaintenanceStore) inventory() (int, bool, error) {
	d, e := s.open(false)
	if errors.Is(e, os.ErrNotExist) {
		return 0, false, nil
	}
	if e != nil {
		return 0, false, e
	}
	defer d.Close()
	f, e := d.Open(".")
	if e != nil {
		return 0, false, e
	}
	entries, e := f.ReadDir(3*core.PlatformMaintenanceOperationLimit + 1)
	f.Close()
	if e != nil && !errors.Is(e, io.EOF) || len(entries) > 3*core.PlatformMaintenanceOperationLimit {
		return 0, false, errors.New("完整维护库存超过预算")
	}
	ids := map[string]bool{}
	for _, entry := range entries {
		name := entry.Name()
		parts := strings.Split(name, ".")
		if len(parts) != 2 && len(parts) != 3 || !core.ValidID(parts[0]) || len(parts) == 2 && parts[1] != "lock" || len(parts) == 3 && (parts[1] != "request" && parts[1] != "result" || parts[2] != "json") {
			return 0, false, errors.New("维护库存含未知成员")
		}
		info, e := d.Lstat(name)
		if e != nil || !moduleRecordInfo(info, false, false) || strings.HasSuffix(name, ".lock") && info.Size() != 0 {
			return 0, false, errors.New("维护库存身份无效")
		}
		ids[parts[0]] = true
	}
	if len(ids) > core.PlatformMaintenanceOperationLimit {
		return 0, false, errors.New("完整维护原操作库存超过上限")
	}
	pending := false
	for id := range ids {
		row, e := s.read(id)
		if e != nil {
			return 0, false, e
		}
		if row.State == "started" && row.Request.Input.Command == "nginx-reload" {
			pending = true
		}
	}
	if !d.current() {
		return 0, false, errors.New("维护库存目录变化")
	}
	return len(ids), pending, nil
}
func (s platformMaintenanceStore) execute(ctx context.Context, in core.PlatformMaintenanceNativeRequest) (core.PlatformMaintenanceRecord, error) {
	var out core.PlatformMaintenanceRecord
	if core.ValidatePlatformMaintenanceNativeRequest(in) != nil || s.plan == nil || s.run == nil {
		return out, errors.New("维护原请求或后端无效")
	}
	if e := ctx.Err(); e != nil {
		return out, e
	}
	old, e := s.read(in.Input.RequestID)
	if e == nil {
		if old.Request != in {
			return out, errors.New("原维护ID已绑定其他请求，未覆盖或重发")
		}
		return old, nil
	}
	if !errors.Is(e, os.ErrNotExist) {
		return out, e
	}
	count, pending, e := s.inventory()
	if e != nil {
		return out, e
	}
	if count >= core.PlatformMaintenanceOperationLimit || pending && in.Input.Command == "nginx-reload" {
		return out, errors.New("维护库存已满或有未核对重载；不换ID重发")
	}
	d, e := s.open(true)
	if e != nil {
		return out, e
	}
	defer d.Close()
	lock, e := d.OpenFile(in.Input.RequestID+".lock", os.O_CREATE|os.O_EXCL|os.O_RDWR|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0600)
	if e != nil {
		return out, e
	}
	defer lock.Close()
	if unix.Flock(int(lock.Fd()), unix.LOCK_EX|unix.LOCK_NB) != nil {
		return out, errors.New("原维护锁被占用")
	}
	out = core.PlatformMaintenanceRecord{Format: 1, Request: in, RequestSHA: core.PlatformMaintenanceRequestSHA(in), State: "started", Outcome: "unknown"}
	raw, _ := json.Marshal(out)
	if e = ruleFeedStoreWrite(d.Root, in.Input.RequestID+".request.json", raw, 0600); e != nil {
		return core.PlatformMaintenanceRecord{}, e
	}
	if e = lock.Sync(); e != nil {
		return core.PlatformMaintenanceRecord{}, e
	}
	if e = ruleFeedStoreSync(d.Root); e != nil {
		return core.PlatformMaintenanceRecord{}, e
	}
	if s.fault != nil {
		if e = s.fault("after-durable-start"); e != nil {
			return core.PlatformMaintenanceRecord{}, e
		}
	}
	plan, e := s.plan(ctx)
	if e != nil || plan.SHA != in.Input.ExpectedPlanSHA {
		out.State = "failed"
		out.Outcome = "plan_changed_before_command"
	} else {
		if !d.current() || ctx.Err() != nil {
			return core.PlatformMaintenanceRecord{}, errors.New("派发前原目录或上下文变化，原开始记录保留")
		}
		if e = s.run(ctx, in.Input.Command); e != nil {
			out.State = "failed"
			out.Outcome = "command_failed"
		} else {
			out.State = "completed"
			out.Outcome = "config_valid"
			if in.Input.Command == "nginx-reload" {
				out.Outcome = "reload_signal_submitted"
			}
		}
	}
	if s.fault != nil {
		if e = s.fault("after-command-before-result"); e != nil {
			return core.PlatformMaintenanceRecord{}, e
		}
	}
	raw, _ = json.Marshal(out)
	if e = ruleFeedStoreWrite(d.Root, in.Input.RequestID+".result.json", raw, 0600); e != nil {
		return core.PlatformMaintenanceRecord{}, e
	}
	if e = ruleFeedStoreSync(d.Root); e != nil {
		return core.PlatformMaintenanceRecord{}, e
	}
	if !d.current() {
		return core.PlatformMaintenanceRecord{}, errors.New("原终态交接目录变化")
	}
	return out, nil
}
func (s *Service) platformMaintenanceStore() platformMaintenanceStore {
	return platformMaintenanceStore{base: s.systemPath("/var/lib/panel-executor/platform-maintenance-jobs"), plan: s.platformMaintenancePlan, run: func(ctx context.Context, command string) error {
		nginx, e := s.nginxBinary()
		if e != nil {
			return errors.New("Nginx 程序未核对")
		}
		if command == "nginx-check" {
			_, e = s.Config.RunWait(ctx, 10*time.Second, nginx, "-t", "-c", s.Config.NginxConf)
			return e
		}
		if command != "nginx-reload" {
			return errors.New("命令未授权")
		}
		if _, e = s.Config.RunWait(ctx, 10*time.Second, nginx, "-t", "-c", s.Config.NginxConf); e != nil {
			return errors.New("Nginx 配置校验未通过，未发出重载")
		}
		_, e = s.Config.RunWait(ctx, 10*time.Second, nginx, "-s", "reload", "-c", s.Config.NginxConf)
		return e
	}}
}
func (s *Service) platformMaintenanceInstallation() (string, error) {
	record, e := s.moduleInstalledRecord("platform-ops")
	instance, ok := record["installation_id"].(string)
	if e != nil || record["version"] != core.PlatformMaintenanceAppVersion || !ok || !core.ValidID(instance) {
		return "", errors.New("维护1.3.0安装实例未核对")
	}
	return instance, nil
}
func (s *Service) platformMaintenancePlan(ctx context.Context) (core.PlatformMaintenancePlan, error) {
	var out core.PlatformMaintenancePlan
	instance, e := s.platformMaintenanceInstallation()
	if e != nil {
		return out, e
	}
	nginx, e := s.nginxBinary()
	if e != nil {
		return out, errors.New("Nginx 程序身份不可核对")
	}
	for _, p := range []string{nginx, s.Config.NginxConf} {
		info, e := os.Lstat(p)
		if e != nil {
			return out, errors.New("Nginx 程序或配置不可读取")
		}
		owner, ok := info.Sys().(*syscall.Stat_t)
		if !ok || owner.Uid != 0 || owner.Nlink != 1 || !info.Mode().IsRegular() || info.Mode()&(os.ModeSetuid|os.ModeSetgid|os.ModeSticky) != 0 || info.Mode().Perm()&0022 != 0 || info.Size() < 1 || info.Size() > 64<<20 {
			return out, errors.New("Nginx 程序或主配置不是受信普通文件")
		}
	}
	if validateNFSELF(nginx, runtime.GOARCH) != nil {
		return out, errors.New("Nginx 原生 ELF 架构不能核对")
	}
	before, e := os.Stat(nginx)
	if e != nil {
		return out, e
	}
	binary, e := os.ReadFile(nginx)
	if e != nil {
		return out, e
	}
	// -T's stdout is the complete config dump, stderr has nondeterministic
	// timestamps and possible secrets. Never hash a truncated dump or return it.
	bounded, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(bounded, nginx, "-T", "-c", s.Config.NginxConf)
	cmd.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LANG=C", "LC_ALL=C"}
	stdout := &boundedBuffer{max: 4 << 20}
	stderr := &boundedBuffer{max: 32 << 10}
	cmd.Stdout = stdout
	cmd.Stderr = stderr
	cmd.WaitDelay = time.Second
	if cmd.Run() != nil || stdout.truncated || stderr.truncated || stdout.Len() == 0 {
		return out, errors.New("完整 Nginx 配置核对失败、超时或超限，未使用部分配置")
	}
	after, e := os.Stat(nginx)
	if e != nil || !geoStoreStableInfo(before, after) {
		return out, errors.New("Nginx 程序在计划读取期间变化")
	}
	finalInstance, e := s.platformMaintenanceInstallation()
	if e != nil || finalInstance != instance {
		return out, errors.New("读取计划期间维护安装实例变化")
	}
	out = core.PlatformMaintenancePlan{Format: 1, SHA: core.Hash(instance + "\x00" + core.Hash(string(binary)) + "\x00" + s.Config.NginxConf + "\x00" + stdout.String()), Commands: core.PlatformMaintenanceCommands()}
	return out, nil
}
func (s *Service) platformMaintenanceRoutes(m *http.ServeMux) {
	m.HandleFunc("GET /v1/platform-maintenance/plan", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.RawQuery != "" || r.URL.ForceQuery {
			respond(w, 400, map[string]string{"error": "计划不接受查询字段"})
			return
		}
		s.mu.Lock()
		defer s.mu.Unlock()
		unlock, e := s.lockRuntimeUse()
		if e != nil {
			respond(w, 409, map[string]string{"error": "运行时正在变更"})
			return
		}
		defer unlock()
		out, e := s.platformMaintenancePlan(r.Context())
		if e != nil {
			respond(w, 409, map[string]string{"error": e.Error()})
			return
		}
		respond(w, 200, out)
	})
	m.HandleFunc("POST /v1/platform-maintenance/commands", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.RawQuery != "" || r.URL.ForceQuery {
			respond(w, 400, map[string]string{"error": "命令不接受查询字段"})
			return
		}
		raw, e := io.ReadAll(http.MaxBytesReader(w, r.Body, 2048))
		in, de := core.DecodePlatformMaintenanceNativeRequest(raw)
		if e != nil || de != nil {
			respond(w, 400, map[string]string{"error": "原命令绑定无效"})
			return
		}
		s.mu.Lock()
		defer s.mu.Unlock()
		if upgradeguard.CheckStartup() != nil {
			respond(w, 409, map[string]string{"error": "程序维护门禁未通过"})
			return
		}
		if _, ie := s.platformMaintenanceInstallation(); ie != nil {
			respond(w, 409, map[string]string{"error": "需明确更新并核对维护1.3.0，未执行命令"})
			return
		}
		unlock, e := s.lockRuntimeUse()
		if e != nil {
			respond(w, 409, map[string]string{"error": "运行时正在变更"})
			return
		}
		defer unlock()
		lock, e := s.lockWAFConfiguration()
		if e != nil {
			respond(w, 409, map[string]string{"error": "配置维护锁不可用"})
			return
		}
		defer lock.Close()
		out, e := s.platformMaintenanceStore().execute(r.Context(), in)
		if e != nil {
			respond(w, 409, map[string]string{"error": e.Error()})
			return
		}
		respond(w, 200, out)
	})
	m.HandleFunc("GET /v1/platform-maintenance/commands/{id}", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.RawQuery != "" || r.URL.ForceQuery {
			respond(w, 400, map[string]string{"error": "核对不接受查询字段"})
			return
		}
		s.mu.Lock()
		defer s.mu.Unlock()
		out, e := s.platformMaintenanceStore().read(r.PathValue("id"))
		if e != nil {
			respond(w, 409, map[string]string{"error": "原维护回执不可核对"})
			return
		}
		respond(w, 200, out)
	})
}
