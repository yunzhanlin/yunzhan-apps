//go:build linux

package executor

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"local/panel/internal/core"
	"local/panel/internal/runtimecatalog"
	"net/http"
	"os"
	"os/user"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"time"
)

const phpWorkerRoot = "/etc/panel/php-workers"

func phpWorkerDirectory(id string) string { return filepath.Join(phpWorkerRoot, id) }
func phpWorkerUnit(id string) string      { return "panel-php-worker-" + id + ".service" }
func phpWorkerUnitPath(id string) string {
	return filepath.Join(phpWorkerDirectory(id), phpWorkerUnit(id))
}

func readPHPWorker(id string) (core.PHPWorker, error) {
	var v core.PHPWorker
	if !core.ValidID(id) {
		return v, errors.New("PHP 进程标识无效")
	}
	for _, p := range []string{phpWorkerRoot, phpWorkerDirectory(id)} {
		if e := ordinary(p, true); e != nil {
			return v, e
		}
	}
	p := filepath.Join(phpWorkerDirectory(id), "instance.json")
	if e := ordinary(p, false); e != nil {
		return v, e
	}
	b, e := os.ReadFile(p)
	if e == nil {
		e = json.Unmarshal(b, &v)
	}
	release, found := runtimecatalog.Find(v.ObservedReleaseID)
	if e == nil && (v.ID != id || core.ValidatePHPWorkerSpec(v.PHPWorkerSpec) != nil || !found || release.Family != "php") {
		e = errors.New("PHP 进程清单损坏，拒绝继续操作")
	}
	return v, e
}

func savePHPWorker(v core.PHPWorker) error {
	v.PID, v.InvocationID, v.Status, v.LastError = 0, "", "", ""
	v.UpdatedAt = core.Now()
	b, e := json.Marshal(v)
	if e != nil {
		return e
	}
	return atomicWrite(filepath.Join(phpWorkerDirectory(v.ID), "instance.json"), b, 0600)
}

func phpWorkerRecords() ([]core.PHPWorker, error) {
	entries, e := os.ReadDir(phpWorkerRoot)
	if errors.Is(e, os.ErrNotExist) {
		return []core.PHPWorker{}, nil
	}
	if e != nil {
		return nil, e
	}
	if e = ordinary(phpWorkerRoot, true); e != nil {
		return nil, e
	}
	if len(entries) > 128 {
		return nil, errors.New("PHP 进程清单数量超限")
	}
	items := []core.PHPWorker{}
	for _, entry := range entries {
		if !core.ValidID(entry.Name()) {
			return nil, errors.New("PHP 进程目录包含未识别记录")
		}
		v, e := readPHPWorker(entry.Name())
		if e != nil {
			return nil, e
		}
		items = append(items, v)
	}
	return items, nil
}

func phpWorkerScriptPath(root, entry string) (string, error) {
	if !core.ValidPHPWorkerEntry(entry) {
		return "", errors.New("PHP 进程入口无效")
	}
	if e := ordinary(root, true); e != nil {
		return "", e
	}
	current := root
	parts := strings.Split(entry, "/")
	for index, part := range parts {
		current = filepath.Join(current, part)
		if e := ordinary(current, index < len(parts)-1); e != nil {
			return "", e
		}
	}
	return current, nil
}

// Quotes for systemd's native argv parser, not a shell. Dollar signs and unit
// specifiers must be escaped separately even inside a double-quoted argument.
func phpWorkerUnitArgument(v string) string {
	v = strings.NewReplacer(`\`, `\\`, `"`, `\"`, `%`, `%%`, `$`, `$$`).Replace(v)
	return `"` + v + `"`
}

func phpWorkerUnitContent(v core.PHPWorker, site core.Site, binary, script string, ini []string) string {
	base := "/srv/panel/sites/" + site.ID
	args := append([]string{binary}, ini...)
	args = append(args, core.PHPWorkerScriptArguments(script, v.Arguments)...)
	for i := range args {
		args[i] = phpWorkerUnitArgument(args[i])
	}
	return fmt.Sprintf(`[Unit]
Description=Panel managed PHP worker %s
After=network.target panel-site-user@%s.service
Requires=panel-site-user@%s.service
StartLimitIntervalSec=60
StartLimitBurst=5

[Service]
Type=exec
User=%s
Group=%s
WorkingDirectory=%s/public
Environment=%s
Environment=%s
ExecStart=%s
Restart=%s
RestartSec=5
TimeoutStopSec=%d
KillMode=control-group
MemoryMax=%dM
TasksMax=%d
OOMPolicy=stop
UMask=0077
NoNewPrivileges=yes
PrivateTmp=yes
PrivateDevices=yes
ProtectSystem=strict
ProtectHome=yes
ReadWritePaths=%s
CapabilityBoundingSet=
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6
RestrictSUIDSGID=yes
RestrictNamespaces=yes
LockPersonality=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
LogRateLimitIntervalSec=30s
LogRateLimitBurst=200
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
`, strings.ReplaceAll(v.Name, "%", "%%"), site.ID, site.ID, siteUser(site.ID), siteUser(site.ID), base,
		phpWorkerUnitArgument("PATH="+filepath.Dir(binary)+":/usr/bin:/bin"), phpWorkerUnitArgument("HOME="+base+"/private"),
		strings.Join(args, " "), v.RestartPolicy, v.StopSeconds, v.MemoryMB, v.TasksMax, base)
}

func (s *Service) phpWorkerBinding(id, expectedRelease string) (core.Site, error) {
	var site core.Site
	if s.Config.SitesDir != "/srv/panel/sites" || !core.ValidID(id) {
		return site, errors.New("PHP 进程需要受管 Linux 网站")
	}
	p := filepath.Join(phpConfigRoot, "bindings", id+".json")
	if e := ordinary(p, false); e != nil {
		return site, e
	}
	b, e := os.ReadFile(p)
	if e != nil {
		return site, e
	}
	if e = json.Unmarshal(b, &site); e != nil || site.ID != id || site.PHPVersionID == "" || site.PHPVersionID != expectedRelease {
		return site, errors.New("网站 PHP 绑定已改变，请刷新后重试")
	}
	configuration, e := os.ReadFile(filepath.Join(s.Config.ConfDir, id+".conf"))
	if e != nil || strings.Contains(string(configuration), "; disabled") {
		return site, errors.New("网站未启用，不能启动 PHP 进程")
	}
	if e = core.ValidatePHPSettings(site.Settings.PHP); e != nil {
		return site, e
	}
	return site, nil
}

func (s *Service) inspectPHPWorker(ctx context.Context, v core.PHPWorker) core.PHPWorker {
	v.Status, v.PID, v.InvocationID, v.LastError = "stopped", 0, "", ""
	out, e := s.Config.Run(ctx, "/usr/bin/systemctl", "show", phpWorkerUnit(v.ID), "--property=ActiveState,SubState,MainPID,InvocationID,Result")
	if e != nil {
		v.Status, v.LastError = "unknown", e.Error()
		return v
	}
	properties := map[string]string{}
	for _, line := range strings.Split(out, "\n") {
		key, value, ok := strings.Cut(line, "=")
		if ok {
			properties[key] = value
		}
	}
	pid, parseErr := strconv.Atoi(properties["MainPID"])
	if parseErr != nil || pid < 0 {
		v.Status, v.LastError = "unknown", "无法核对 PHP 进程的主进程标识"
		return v
	}
	v.PID = pid
	v.InvocationID = properties["InvocationID"]
	switch properties["ActiveState"] {
	case "active":
		v.Status = "running"
	case "activating", "deactivating":
		v.Status = properties["ActiveState"]
	case "failed":
		v.Status = "failed"
	case "inactive":
		v.Status = "stopped"
	default:
		v.Status, v.LastError = "unknown", "无法核对 PHP 进程的运行状态"
		return v
	}
	if result := properties["Result"]; result != "" && result != "success" {
		v.LastError = result
	}
	return v
}

func (s *Service) phpWorkerReady(ctx context.Context, v core.PHPWorker) error {
	// This confirms a stable live process, not the application's queue health.
	initial := s.inspectPHPWorker(ctx, v)
	if initial.Status != "running" || initial.PID == 0 {
		return errors.New("PHP 进程未运行，请查看进程日志")
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-time.After(2 * time.Second):
	}
	current := s.inspectPHPWorker(ctx, v)
	if current.Status != "running" || current.PID != initial.PID || current.InvocationID != initial.InvocationID {
		return errors.New("PHP 进程启动后退出或反复重启，请查看日志")
	}
	return nil
}

func (s *Service) stopPHPWorker(ctx context.Context, v core.PHPWorker) error {
	// Keep the external registry link until the stop has finished. disable --now
	// reloads after unlinking and systemd can then lose TimeoutStopSec, reverting
	// to its default while the running process is still exiting.
	_, e := s.Config.RunWait(ctx, time.Duration(v.StopSeconds+10)*time.Second, "/usr/bin/systemctl", "stop", phpWorkerUnit(v.ID))
	if e != nil {
		current := s.inspectPHPWorker(ctx, v)
		if current.PID != 0 || (current.Status != "stopped" && current.Status != "failed") {
			return e
		}
	}
	_, e = s.Config.Run(ctx, "/usr/bin/systemctl", "disable", phpWorkerUnit(v.ID))
	if e == nil {
		return nil
	}
	// Disabling a linked external unit removes both its registry link and its
	// boot link. A second stop/delete is safe only with two independent proofs:
	// no live process and no installed/enabled unit. Bus/query errors fail closed.
	current := s.inspectPHPWorker(ctx, v)
	state, stateErr := s.Config.Run(ctx, "/usr/bin/systemctl", "is-enabled", phpWorkerUnit(v.ID))
	state = strings.TrimSpace(state)
	if current.PID == 0 && (current.Status == "stopped" || current.Status == "failed") &&
		(state == "disabled" || stateErr != nil && strings.HasPrefix(state, "Failed to get unit file state") && strings.Contains(state, "No such file or directory")) {
		return nil
	}
	return e
}

func (s *Service) createPHPWorker(ctx context.Context, v core.PHPWorker) (ret error) {
	if !core.ValidID(v.ID) {
		return errors.New("PHP 进程标识无效")
	}
	if e := core.ValidatePHPWorkerSpec(v.PHPWorkerSpec); e != nil {
		return e
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	unlock, e := s.lockRuntimeUse()
	if e != nil {
		return e
	}
	defer unlock()
	lock := fileMutex(v.SiteID)
	lock.Lock()
	defer lock.Unlock()
	site, e := s.phpWorkerBinding(v.SiteID, v.ObservedReleaseID)
	if e != nil {
		return e
	}
	release, found := runtimecatalog.Find(site.PHPVersionID)
	if !found || release.Family != "php" {
		return errors.New("网站 PHP 版本无效")
	}
	if _, e = LoadRuntime(release.ID); e != nil {
		return e
	}
	account, e := user.Lookup(siteUser(site.ID))
	if e != nil || account.Uid == "0" || account.Gid == "0" {
		return errors.New("独立网站用户未就绪")
	}
	script, e := phpWorkerScriptPath(filepath.Join(s.Config.SitesDir, site.ID, "public"), v.Entry)
	if e != nil {
		return e
	}
	ini, e := phpExtensionArgs(ctx, release, site.Settings.PHP)
	if e != nil {
		return e
	}
	for _, pair := range core.PHPIniValues(site.Settings.PHP) {
		ini = append(ini, "-d", pair[0]+"="+pair[1])
	}
	items, e := phpWorkerRecords()
	if e != nil {
		return e
	}
	if len(items) >= 128 {
		return errors.New("最多允许 128 个 PHP 进程")
	}
	count := 0
	for _, item := range items {
		if item.SiteID == v.SiteID {
			count++
			if item.Name == v.Name {
				return errors.New("网站中已有同名 PHP 进程")
			}
		}
	}
	if count >= 16 {
		return errors.New("每个网站最多允许 16 个 PHP 进程")
	}
	if e = os.MkdirAll(phpWorkerRoot, 0700); e != nil {
		return e
	}
	if e = ordinary(phpWorkerRoot, true); e != nil {
		return e
	}
	if e = os.Mkdir(phpWorkerDirectory(v.ID), 0700); e != nil {
		return e
	}
	v.Enabled, v.ObservedReleaseID = true, site.PHPVersionID
	committed, startAttempted := false, false
	defer func() {
		if committed {
			return
		}
		if !startAttempted {
			_ = os.RemoveAll(phpWorkerDirectory(v.ID))
			return
		}
		// Keep the manifest if stopping failed: references must not disappear
		// while a process may still use this runtime.
		if stopErr := s.stopPHPWorker(context.Background(), v); stopErr != nil {
			v.Enabled = false
			_ = savePHPWorker(v)
			ret = errors.Join(ret, fmt.Errorf("失败进程清理未完成: %w", stopErr))
			return
		}
		_ = os.RemoveAll(phpWorkerDirectory(v.ID))
	}()
	if e = savePHPWorker(v); e != nil {
		return e
	}
	if e = atomicWrite(phpWorkerUnitPath(v.ID), []byte(phpWorkerUnitContent(v, site, release.CLI(), script, ini)), 0600); e != nil {
		return e
	}
	startAttempted = true
	if _, e = s.Config.Run(ctx, "/usr/bin/systemctl", "enable", "--now", phpWorkerUnitPath(v.ID)); e != nil {
		return e
	}
	if e = s.phpWorkerReady(ctx, v); e != nil {
		return e
	}
	committed = true
	return nil
}

func (s *Service) changePHPWorker(ctx context.Context, siteID, id, action, confirm string) (core.PHPWorker, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	unlock, e := s.lockRuntimeUse()
	if e != nil {
		return core.PHPWorker{}, e
	}
	defer unlock()
	v, e := readPHPWorker(id)
	if e != nil || v.SiteID != siteID {
		return v, errors.New("网站中不存在该 PHP 进程")
	}
	lock := fileMutex(siteID)
	lock.Lock()
	defer lock.Unlock()
	switch action {
	case "stop", "delete":
		if action == "delete" && confirm != v.Name {
			return v, errors.New("请输入进程名称确认删除")
		}
		v.Enabled = false
		if e = savePHPWorker(v); e != nil {
			return v, e
		}
		if e = s.stopPHPWorker(ctx, v); e != nil {
			return s.inspectPHPWorker(ctx, v), e
		}
		current := s.inspectPHPWorker(ctx, v)
		if current.PID != 0 || current.Status != "stopped" && current.Status != "failed" {
			return current, errors.New("PHP 进程尚未完全停止，保留配置与版本引用")
		}
		if action == "delete" {
			if e = os.RemoveAll(phpWorkerDirectory(id)); e != nil {
				return current, e
			}
			_, e = s.Config.Run(ctx, "/usr/bin/systemctl", "daemon-reload")
			return current, e
		}
		return current, nil
	case "start", "restart":
		if _, e = s.phpWorkerBinding(siteID, v.ObservedReleaseID); e != nil {
			return v, e
		}
		if _, e = phpWorkerScriptPath(filepath.Join(s.Config.SitesDir, siteID, "public"), v.Entry); e != nil {
			return v, e
		}
		if _, e = LoadRuntime(v.ObservedReleaseID); e != nil {
			return v, e
		}
		v.Enabled = true
		if e = savePHPWorker(v); e != nil {
			return v, e
		}
		_, _ = s.Config.Run(ctx, "/usr/bin/systemctl", "reset-failed", phpWorkerUnit(id))
		if action == "restart" {
			if _, e = s.Config.RunWait(ctx, time.Duration(v.StopSeconds+10)*time.Second, "/usr/bin/systemctl", "stop", phpWorkerUnit(id)); e != nil {
				return v, e
			}
		}
		if _, e = s.Config.Run(ctx, "/usr/bin/systemctl", "enable", "--now", phpWorkerUnitPath(id)); e != nil {
			return v, e
		}
		if e = s.phpWorkerReady(ctx, v); e != nil {
			return s.inspectPHPWorker(ctx, v), e
		}
		return s.inspectPHPWorker(ctx, v), nil
	default:
		return v, errors.New("PHP 进程操作无效")
	}
}

// Until the durable rebind/rollback transaction is implemented, reject a site
// transition that could leave a worker using stale PHP or a suspended website.
// Never silently keep the old worker running and call the switch successful.
func (s *Service) checkPHPWorkerSiteChange(in core.ApplyRequest) error {
	if s.Config.SitesDir != "/srv/panel/sites" {
		return nil
	}
	operations, e := s.phpWorkerPublicOperations(in.Site.ID)
	if e != nil {
		return e
	}
	for _, operation := range operations {
		if phpWorkerOperationPending(operation.State) {
			return errors.New("该网站 PHP 进程操作尚未完成，请等待后再变更网站")
		}
	}
	items, e := phpWorkerRecords()
	if e != nil {
		return e
	}
	for _, item := range items {
		if item.SiteID != in.Site.ID {
			continue
		}
		old, e := s.phpWorkerBinding(item.SiteID, item.ObservedReleaseID)
		if e != nil {
			return e
		}
		if !in.Enabled || in.Site.PHPVersionID != old.PHPVersionID || !reflect.DeepEqual(in.Site.Settings.PHP, old.Settings.PHP) {
			return errors.New("该网站仍有 PHP 常驻进程；自动重绑恢复尚未开放，请先删除进程配置再变更 PHP、PHP 参数或停用网站")
		}
	}
	return nil
}

func (s *Service) phpWorkerRoutes(m *http.ServeMux) {
	base := "/v1/sites/{id}/php-workers"
	m.HandleFunc("GET "+base, func(w http.ResponseWriter, r *http.Request) {
		if !core.ValidID(r.PathValue("id")) {
			respond(w, 400, map[string]string{"error": "网站标识无效"})
			return
		}
		items, e := phpWorkerRecords()
		if e != nil {
			respond(w, 409, map[string]string{"error": e.Error()})
			return
		}
		out := []core.PHPWorker{}
		for _, item := range items {
			if item.SiteID == r.PathValue("id") {
				out = append(out, s.inspectPHPWorker(r.Context(), item))
			}
		}
		operations, e := s.phpWorkerPublicOperations(r.PathValue("id"))
		if e != nil {
			respond(w, 409, map[string]string{"error": e.Error()})
			return
		}
		respond(w, 200, map[string]any{"workers": out, "operations": operations, "automatic_rebind": false})
	})
	m.HandleFunc("GET "+base+"/operations/{operation}/status", func(w http.ResponseWriter, r *http.Request) {
		v, e := s.phpWorkerOperation(r.PathValue("id"), r.PathValue("operation"))
		if e != nil {
			respond(w, 404, map[string]string{"error": e.Error()})
			return
		}
		respond(w, 200, v)
	})
	m.HandleFunc("POST "+base, func(w http.ResponseWriter, r *http.Request) {
		var in core.PHPWorker
		if !readJSON(w, r, &in) {
			return
		}
		if in.SiteID != r.PathValue("id") {
			respond(w, 400, map[string]string{"error": "网站身份不匹配"})
			return
		}
		v, e := s.enqueuePHPWorkerOperation(in, "create", "")
		if e != nil {
			respond(w, 409, map[string]string{"error": e.Error()})
			return
		}
		respond(w, 202, v)
	})
	m.HandleFunc("POST "+base+"/{worker}/{action}", func(w http.ResponseWriter, r *http.Request) {
		worker, e := readPHPWorker(r.PathValue("worker"))
		if e != nil || worker.SiteID != r.PathValue("id") {
			respond(w, 404, map[string]string{"error": "网站中不存在该 PHP 进程"})
			return
		}
		v, e := s.enqueuePHPWorkerOperation(worker, r.PathValue("action"), "")
		if e != nil {
			respond(w, 409, map[string]string{"error": e.Error()})
			return
		}
		respond(w, 202, v)
	})
	m.HandleFunc("DELETE "+base+"/{worker}", func(w http.ResponseWriter, r *http.Request) {
		var in struct {
			ConfirmName string `json:"confirm_name"`
		}
		if !readJSON(w, r, &in) {
			return
		}
		worker, e := readPHPWorker(r.PathValue("worker"))
		if e != nil || worker.SiteID != r.PathValue("id") {
			respond(w, 404, map[string]string{"error": "网站中不存在该 PHP 进程"})
			return
		}
		v, e := s.enqueuePHPWorkerOperation(worker, "delete", in.ConfirmName)
		if e != nil {
			respond(w, 409, map[string]string{"error": e.Error()})
			return
		}
		respond(w, 202, v)
	})
	m.HandleFunc("GET "+base+"/{worker}/logs", func(w http.ResponseWriter, r *http.Request) {
		v, e := readPHPWorker(r.PathValue("worker"))
		if e != nil || v.SiteID != r.PathValue("id") {
			respond(w, 404, map[string]string{"error": "网站中不存在该 PHP 进程"})
			return
		}
		out, e := s.Config.Run(r.Context(), "/usr/bin/journalctl", "-u", phpWorkerUnit(v.ID), "-n", "200", "--no-pager", "--output=short-iso")
		if e != nil {
			respond(w, 409, map[string]string{"error": e.Error()})
			return
		}
		respond(w, 200, map[string]string{"content": out, "sampled_at": core.Now()})
	})
}
