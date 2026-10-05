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
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

const nginxActiveFile = "/etc/panel/nginx/active.json"
const nginxSwitchDir = "/var/lib/panel-executor/nginx-switches"

type nginxSelection struct {
	ID string `json:"id"`
}
type nginxGuard struct {
	JobID string `json:"job_id"`
	OldID string `json:"old_id"`
	NewID string `json:"new_id"`
	State string `json:"state"`
}

func nginxReleaseBinary(id string) (string, error) {
	if id == "nginx-system" {
		return "/usr/sbin/nginx", nil
	}
	r, ok := runtimecatalog.Find(id)
	if !ok || r.Family != "nginx" {
		return "", errors.New("不支持的 Nginx 版本")
	}
	if _, e := LoadRuntime(id); e != nil {
		return "", errors.New("Nginx 目标版本未完整安装")
	}
	return r.CLI(), nil
}
func activeNginx() (string, error) {
	b, e := os.ReadFile(nginxActiveFile)
	if errors.Is(e, os.ErrNotExist) {
		return "nginx-system", nil
	}
	if e != nil {
		return "", e
	}
	var st nginxSelection
	if e = json.Unmarshal(b, &st); e != nil {
		return "", e
	}
	if _, e = nginxReleaseBinary(st.ID); e != nil {
		return "", e
	}
	return st.ID, nil
}
func writeNginx(id string) error {
	if _, e := nginxReleaseBinary(id); e != nil {
		return e
	}
	if e := os.MkdirAll(filepath.Dir(nginxActiveFile), 0755); e != nil {
		return e
	}
	b, _ := json.Marshal(nginxSelection{ID: id})
	return atomicWrite(nginxActiveFile, b, 0600)
}
func (s *Service) nginxBinary() (string, error) {
	if s.Config.SitesDir != "/srv/panel/sites" {
		return s.Config.NginxBin, nil
	}
	id, e := activeNginx()
	if e != nil {
		return "", e
	}
	return nginxReleaseBinary(id)
}
func nginxLock() (*os.File, error) {
	f, e := os.OpenFile("/var/lib/panel-executor/nginx-switch.lock", os.O_CREATE|os.O_RDWR, 0600)
	if e != nil {
		return nil, e
	}
	if e = syscall.Flock(int(f.Fd()), syscall.LOCK_EX); e != nil {
		f.Close()
		return nil, e
	}
	return f, nil
}
func guardPath(id string) string { return filepath.Join(nginxSwitchDir, id+".json") }
func saveGuard(g nginxGuard) error {
	if !core.ValidID(g.JobID) {
		return errors.New("invalid guard ID")
	}
	if e := os.MkdirAll(nginxSwitchDir, 0700); e != nil {
		return e
	}
	b, _ := json.Marshal(g)
	return atomicWrite(guardPath(g.JobID), b, 0600)
}
func readGuard(id string) (nginxGuard, error) {
	var g nginxGuard
	if !core.ValidID(id) {
		return g, errors.New("invalid guard ID")
	}
	b, e := os.ReadFile(guardPath(id))
	if e != nil {
		return g, e
	}
	e = json.Unmarshal(b, &g)
	if g.JobID != id {
		return g, errors.New("guard ID mismatch")
	}
	return g, e
}
func restoreGuard(ctx context.Context, g nginxGuard, restart bool) error {
	if g.State != "pending" {
		return nil
	}
	if e := writeNginx(g.OldID); e != nil {
		return e
	}
	if restart {
		if _, e := RunCommand(ctx, "/usr/bin/systemctl", "restart", "nginx"); e != nil {
			return e
		}
	}
	g.State = "rolled_back"
	return saveGuard(g)
}
func NginxRollback(id string) error {
	lock, e := nginxLock()
	if e != nil {
		return e
	}
	defer lock.Close()
	g, e := readGuard(id)
	if e != nil {
		return e
	}
	return restoreGuard(context.Background(), g, true)
}
func RecoverNginx() error {
	lock, e := nginxLock()
	if e != nil {
		return e
	}
	defer lock.Close()
	paths, e := filepath.Glob(filepath.Join(nginxSwitchDir, "*.json"))
	if e != nil {
		return e
	}
	for _, p := range paths {
		id := strings.TrimSuffix(filepath.Base(p), ".json")
		g, e := readGuard(id)
		if e != nil {
			return e
		}
		if e = restoreGuard(context.Background(), g, false); e != nil {
			return e
		}
	}
	return nil
}
func NginxCommand(mode string) error {
	lock, lockErr := runtimeUseLock()
	if lockErr != nil {
		return lockErr
	}
	defer lock.Close()
	id, e := activeNginx()
	if e != nil {
		return e
	}
	binary, e := nginxReleaseBinary(id)
	if e != nil {
		return e
	}
	args := []string{binary, "-c", "/etc/nginx/nginx.conf"}
	switch mode {
	case "start":
		args = append(args, "-g", "daemon on; master_process on;")
	case "test":
		args = append(args, "-t")
	case "reload":
		args = append(args, "-s", "reload")
	default:
		return errors.New("invalid nginx operation")
	}
	return syscall.Exec(binary, args, []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LANG=C"})
}
func checkSites(ctx context.Context, sites []core.Site) error {
	client := &http.Client{Timeout: 3 * time.Second, Transport: &http.Transport{Proxy: nil}, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	defer client.CloseIdleConnections()
	for _, site := range sites {
		if !core.ValidID(site.ID) || core.ValidateSite(site.Name, site.Slug) != nil || !core.ValidDomain(site.Domain) {
			return errors.New("无效站点清单")
		}
		if site.Status != "running" && site.Status != "stopped" {
			return fmt.Errorf("站点 %s 尚有异常或未完成任务", site.Domain)
		}
		if e := verifySiteIngress(ctx, site, true); e != nil {
			return e
		}
		req, _ := http.NewRequestWithContext(ctx, "GET", "http://127.0.0.1:19101/", nil)
		req.Host = site.Domain
		resp, e := client.Do(req)
		if e != nil {
			return fmt.Errorf("站点 %s: %w", site.Domain, e)
		}
		resp.Body.Close()
		if site.Status == "stopped" && resp.StatusCode != 404 {
			return fmt.Errorf("停用站点 %s HTTP %d，期望 404", site.Domain, resp.StatusCode)
		}
		if site.Status == "running" && (resp.StatusCode < 200 || resp.StatusCode >= 500) {
			return fmt.Errorf("站点 %s HTTP %d，首页不可用", site.Domain, resp.StatusCode)
		}
		if site.Status == "running" && site.Settings.TLS != nil {
			if site.Settings.TLS.Redirect && resp.StatusCode != 301 {
				return errors.New("HTTP 未跳转到 HTTPS")
			}
			secure, e := siteHTTPSClient(site, site.Domain)
			if e != nil {
				return e
			}
			_, e = verifySiteHomepage(ctx, secure, site)
			secure.CloseIdleConnections()
			if e != nil {
				return e
			}
		}
		if site.Status == "running" && site.Settings.Mode == "redirect" && (site.Settings.TLS == nil || !site.Settings.TLS.Redirect) && resp.StatusCode != site.Settings.RedirectCode {
			return fmt.Errorf("站点 %s 重定向状态不匹配", site.Domain)
		}
	}
	return nil
}
func (s *Service) switchNginx(ctx context.Context, id, release string, sites []core.Site) (result core.ApplyResult, ret error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	result.Steps = []core.Step{}
	add := func(m string) { result.Steps = append(result.Steps, core.Step{Time: core.Now(), Message: m}) }
	if !core.ValidID(id) {
		return result, errors.New("无效任务标识")
	}
	binary, e := nginxReleaseBinary(release)
	if e != nil {
		return result, e
	}
	lock, e := nginxLock()
	if e != nil {
		return result, e
	}
	defer lock.Close()
	priorPaths, e := filepath.Glob(filepath.Join(nginxSwitchDir, "*.json"))
	if e != nil {
		return result, e
	}
	for _, path := range priorPaths {
		priorID := strings.TrimSuffix(filepath.Base(path), ".json")
		prior, e := readGuard(priorID)
		if e != nil {
			return result, e
		}
		if prior.State == "pending" {
			if e = restoreGuard(context.Background(), prior, true); e != nil {
				return result, fmt.Errorf("恢复先前中断的入口失败: %w", e)
			}
			add("恢复先前未提交的 Nginx 入口变更")
		}
	}

	old, e := activeNginx()
	if e != nil {
		return result, e
	}
	if e = checkSites(ctx, sites); e != nil {
		return result, fmt.Errorf("当前站点预检失败，未切换: %w", e)
	}
	add(fmt.Sprintf("当前 %d 个网站 HTTP 状态全部通过预检", len(sites)))
	if _, e = s.Config.Run(ctx, binary, "-t", "-c", "/etc/nginx/nginx.conf"); e != nil {
		return result, fmt.Errorf("目标 Nginx 配置或模块不兼容，未切换: %w", e)
	}
	add("目标版本通过全站配置与模块语法校验")
	g := nginxGuard{JobID: id, OldID: old, NewID: release, State: "pending"}
	if e = saveGuard(g); e != nil {
		return result, e
	}
	timer := "panel-nginx-rollback@" + id + ".timer"
	if _, e = s.Config.Run(ctx, "/usr/bin/systemctl", "start", timer); e != nil {
		g.State = "aborted"
		_ = saveGuard(g)
		return result, e
	}
	add("已启用独立的超时恢复计时器")
	committed := false
	defer func() {
		if !committed {
			if e := restoreGuard(context.Background(), g, true); e != nil {
				ret = fmt.Errorf("%v；旧入口恢复失败: %w", ret, e)
			} else {
				add("旧 Nginx 入口已恢复")
			}
		}
		_, _ = s.Config.Run(context.Background(), "/usr/bin/systemctl", "stop", timer)
	}()
	if e = writeNginx(release); e != nil {
		return result, e
	}
	if _, e = s.Config.Run(ctx, "/usr/bin/systemctl", "restart", "nginx"); e != nil {
		return result, fmt.Errorf("Nginx 目标版本启动失败: %w", e)
	}
	pid, e := s.Config.Run(ctx, "/usr/bin/systemctl", "show", "-p", "MainPID", "--value", "nginx")
	if e != nil {
		return result, e
	}
	exe, e := os.Readlink("/proc/" + strings.TrimSpace(pid) + "/exe")
	if e != nil || exe != binary {
		return result, fmt.Errorf("实际 Nginx 主进程与目标程序不一致: %s: %v", exe, e)
	}
	add("实际 Nginx 主进程已运行目标二进制 " + release)
	if e = checkSites(ctx, sites); e != nil {
		return result, fmt.Errorf("切换后网站验证失败: %w", e)
	}
	add(fmt.Sprintf("切换后 %d 个网站实际访问通过", len(sites)))
	g.State = "committed"
	if e = saveGuard(g); e != nil {
		return result, e
	}
	committed = true
	result.Status = "running"
	add("入口切换已提交，取消超时恢复")
	return result, nil
}
func (s *Service) nginxRoutes(m *http.ServeMux) {
	m.HandleFunc("POST /v1/nginx/switch", func(w http.ResponseWriter, r *http.Request) {
		var in struct {
			JobID     string      `json:"job_id"`
			ReleaseID string      `json:"release_id"`
			Sites     []core.Site `json:"sites"`
		}
		if !readJSON(w, r, &in) {
			return
		}
		result, e := s.switchNginx(r.Context(), in.JobID, in.ReleaseID, in.Sites)
		if e != nil {
			respond(w, 409, map[string]any{"error": e.Error(), "steps": result.Steps})
			return
		}
		respond(w, 200, result)
	})
}
