package executor

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io"
	"local/panel/internal/core"
	"local/panel/internal/runtimecatalog"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"
)

type Command func(context.Context, string, ...string) (string, error)
type TimedCommand func(context.Context, time.Duration, string, ...string) (string, error)
type Config struct {
	SitesDir, ConfDir, StateDir, NginxBin, TerminalSocket, RootTerminalSocket, ApacheSiteConfig string
	SecurityDir, NginxConf, SystemRoot                                                          string
	Run                                                                                         Command
	RunWait                                                                                     TimedCommand
}
type Service struct {
	Config                Config
	mu                    sync.Mutex
	terminal              *terminalManager
	phpWorkerQueueMu      sync.Mutex
	phpWorkerQueueStarted bool
	phpWorkerQueueWake    chan struct{}
	moduleAutoBlocked     map[string]bool // Guarded by mu; stop automatic writes after persistence failure.
	moduleWorkerStarted   bool
	moduleWatchWake       chan struct{}
	moduleWatchStatus     map[string]moduleRealtimeStatus // Guarded by mu; runtime status is never a persisted promise.
	lbHealthStatusMu      sync.Mutex
	lbHealthWorkerError   string
	// Only a freshly constructed internal transaction adapter sets this.
	// Never accepted from an API request or persisted configuration.
	fileTransactionApplication string
}

type moduleRealtimeStatus struct {
	State       string `json:"state"`
	Directories int    `json:"directories"`
	Overflows   uint64 `json:"overflows"`
	Error       string `json:"error,omitempty"`
	UpdatedAt   string `json:"updated_at"`
}

func New(c Config) *Service {
	if c.ApacheSiteConfig == "" {
		c.ApacheSiteConfig = "/etc/panel/apache/httpd.conf"
	}
	if c.RunWait == nil {
		if c.Run == nil {
			c.RunWait = RunCommandWithTimeout
		} else {
			command := c.Run
			c.RunWait = func(ctx context.Context, wait time.Duration, name string, args ...string) (string, error) {
				bounded, cancel := context.WithTimeout(ctx, wait)
				defer cancel()
				return command(bounded, name, args...)
			}
		}
	}
	if c.Run == nil {
		c.Run = RunCommand
	}
	if c.SecurityDir == "" {
		c.SecurityDir = "/etc/panel/security-apps"
	}
	if c.NginxConf == "" {
		c.NginxConf = "/etc/nginx/nginx.conf"
	}
	if c.SystemRoot == "" {
		c.SystemRoot = "/"
	}
	return &Service{Config: c, terminal: newTerminalManager("panel-task")}
}

type boundedBuffer struct {
	bytes.Buffer
	max       int
	truncated bool
}

func (b *boundedBuffer) Write(p []byte) (int, error) {
	n := len(p)
	if n > b.max-b.Len() {
		b.truncated = true
	}
	if b.Len() < b.max {
		keep := b.max - b.Len()
		if keep > n {
			keep = n
		}
		_, _ = b.Buffer.Write(p[:keep])
	}
	return n, nil
}
func RunCommand(ctx context.Context, name string, args ...string) (string, error) {
	return RunCommandWithTimeout(ctx, 20*time.Second, name, args...)
}
func RunCommandWithTimeout(ctx context.Context, wait time.Duration, name string, args ...string) (string, error) {
	c, cancel := context.WithTimeout(ctx, wait)
	defer cancel()
	cmd := exec.CommandContext(c, name, args...)
	cmd.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LANG=C", "LC_ALL=C"}
	out := &boundedBuffer{max: 32 * 1024}
	cmd.Stdout = out
	cmd.Stderr = out
	cmd.WaitDelay = time.Second
	err := cmd.Run()
	if err != nil {
		return out.String(), fmt.Errorf("%s: %w: %s", filepath.Base(name), err, out.String())
	}
	return out.String(), nil
}
func runCommandInput(ctx context.Context, input []byte, name string, args ...string) (string, error) {
	c, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	cmd := exec.CommandContext(c, name, args...)
	cmd.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LANG=C", "LC_ALL=C"}
	cmd.Stdin = bytes.NewReader(input)
	out := &boundedBuffer{max: 32 * 1024}
	cmd.Stdout = out
	cmd.Stderr = out
	cmd.WaitDelay = time.Second
	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("%s: %w: %s", filepath.Base(name), err, out.String())
	}
	if out.truncated {
		return "", errors.New("命令输出超出限制")
	}
	return out.String(), nil
}
func atomicWrite(path string, b []byte, mode os.FileMode) error {
	owner, err := existingFileOwner(path)
	if err != nil {
		return err
	}
	return atomicWriteWithOwner(path, b, mode, owner)
}

func atomicWriteWithOwner(path string, b []byte, mode os.FileMode, owner *fileOwner) error {
	if _, err := existingFileOwner(path); err != nil {
		return err
	}
	f, err := os.CreateTemp(filepath.Dir(path), ".panel-write-")
	if err != nil {
		return err
	}
	name := f.Name()
	defer os.Remove(name)
	if owner != nil {
		err = f.Chown(int(owner.UID), int(owner.GID))
	}
	if err == nil {
		err = f.Chmod(mode)
	}
	if err == nil {
		_, err = f.Write(b)
	}
	if err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	if err = os.Rename(name, path); err != nil {
		return err
	}
	dir, err := os.Open(filepath.Dir(path))
	if err == nil {
		defer dir.Close()
		err = dir.Sync()
	}
	return err
}
func ordinary(path string, dir bool) error {
	st, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if st.Mode()&os.ModeSymlink != 0 || st.IsDir() != dir || (!dir && !st.Mode().IsRegular()) {
		return fmt.Errorf("受管路径类型异常: %s", path)
	}
	return nil
}
func (s *Service) Apply(ctx context.Context, in core.ApplyRequest) (core.ApplyResult, error) {
	// A long PHP stop holds the lifecycle lock. Reject a new site mutation
	// before HTTP deadlines expire, and never start writing after cancellation.
	if e := s.phpWorkerMutationBusy(); e != nil {
		return core.ApplyResult{Restored: true}, e
	}
	for !s.mu.TryLock() {
		select {
		case <-ctx.Done():
			return core.ApplyResult{Restored: true}, ctx.Err()
		case <-time.After(10 * time.Millisecond):
		}
	}
	defer s.mu.Unlock()
	if e := ctx.Err(); e != nil {
		return core.ApplyResult{Restored: true}, e
	}
	finishWAF, wafErr := s.lockWAFSiteMutation()
	if wafErr != nil {
		return core.ApplyResult{Restored: true}, wafErr
	}
	defer finishWAF()
	finishApache, apacheErr := s.lockApacheWAFSiteMutation()
	if apacheErr != nil {
		return core.ApplyResult{}, apacheErr
	}
	defer finishApache()
	unlock, lockErr := s.lockRuntimeUse()
	if lockErr != nil {
		return core.ApplyResult{}, lockErr
	}
	defer unlock()
	result := core.ApplyResult{Steps: []core.Step{}, Restored: true}
	add := func(m string) { result.Steps = append(result.Steps, core.Step{Time: core.Now(), Message: m}) }
	if !core.ValidID(in.Site.ID) || !core.ValidID(in.JobID) || core.ValidateSite(in.Site.Name, in.Site.Slug) != nil || !core.ValidDomain(in.Site.Domain) {
		return result, errors.New("站点标识或主域名无效")
	}
	for _, p := range []string{s.Config.SitesDir, s.Config.ConfDir, s.Config.StateDir} {
		if err := ordinary(p, true); err != nil {
			return result, err
		}
	}
	in.Site.Settings = core.DefaultSiteSettings(in.Site.Settings)
	if err := core.ValidateSiteSettings(in.Site.Settings, in.Site.Domain, in.Site.PHPVersionID); err != nil {
		return result, err
	}
	if err := s.checkPHPWorkerSiteChange(in); err != nil {
		return result, err
	}
	if in.Enabled && in.Site.Settings.TLS != nil {
		cert, e := LoadCertificate(in.Site.Settings.TLS.CertificateID)
		if e != nil {
			return result, e
		}
		if e = cert.ValidateDomains(in.Site.Domain, in.Site.Settings.Domains, time.Now()); e != nil {
			return result, e
		}
	}
	if err := s.checkDomainOwners(in.Site); err != nil {
		return result, err
	}
	if in.ExpectedConfigSHA != "" {
		cfg := filepath.Join(s.Config.ConfDir, in.Site.ID+".conf")
		if err := ordinary(cfg, false); err != nil {
			return result, err
		}
		old, err := os.ReadFile(cfg)
		if err != nil {
			return result, err
		}
		if core.Hash(string(old)) != in.ExpectedConfigSHA {
			return result, errors.New("实际 Nginx 配置已发生变化，请重新预览")
		}
	}
	add("校验站点标识、目录归属与期望状态")
	dir := filepath.Join(s.Config.SitesDir, in.Site.ID)
	if _, err := os.Lstat(dir); errors.Is(err, os.ErrNotExist) {
		if !in.Enabled {
			return result, errors.New("站点目录不存在，无法停用")
		}
		if err = os.Mkdir(dir, 0755); err != nil {
			return result, err
		}
	} else if err != nil {
		return result, err
	}
	if err := ordinary(dir, true); err != nil {
		return result, err
	}
	marker := filepath.Join(dir, ".panel-site.json")
	expected := map[string]string{"id": in.Site.ID, "domain": in.Site.Domain}
	if old, err := os.ReadFile(marker); err == nil {
		var found map[string]string
		if json.Unmarshal(old, &found) != nil || found["id"] != in.Site.ID || found["domain"] != in.Site.Domain {
			return result, errors.New("站点目录归属不匹配")
		}
	} else if errors.Is(err, os.ErrNotExist) {
		entries, er := os.ReadDir(dir)
		if er != nil || len(entries) > 0 {
			return result, errors.New("拒绝接管非空未知目录")
		}
		b, _ := json.Marshal(expected)
		if err = atomicWrite(marker, b, 0600); err != nil {
			return result, err
		}
	} else {
		return result, err
	}
	// Public static content must remain traversable despite the service umask.
	if err := os.Chmod(dir, 0755); err != nil {
		return result, err
	}
	public := filepath.Join(dir, "public")
	if _, er := os.Lstat(public); errors.Is(er, os.ErrNotExist) {
		if er = os.Mkdir(public, 0755); er != nil {
			return result, er
		}
		if er = os.Chmod(public, 0755); er != nil {
			return result, er
		}
	}
	if err := ordinary(public, true); err != nil {
		return result, err
	}
	index := filepath.Join(public, "index.html")
	if _, err := os.Lstat(index); errors.Is(err, os.ErrNotExist) {
		var body bytes.Buffer
		// Preserve the previous static homepage when adopting the public subdirectory.
		if old, er := os.ReadFile(filepath.Join(dir, "index.html")); er == nil {
			body.Write(old)
		} else if err = welcome.Execute(&body, in.Site); err != nil {
			return result, err
		}
		if err = atomicWrite(index, body.Bytes(), 0644); err != nil {
			return result, err
		}
	} else if err != nil {
		return result, err
	} else if err = ordinary(index, false); err != nil {
		return result, err
	}
	if in.Site.PHPVersionID != "" {
		phpIndex := filepath.Join(public, "index.php")
		var body bytes.Buffer
		if er := welcome.Execute(&body, in.Site); er != nil {
			return result, er
		}
		existing, er := os.ReadFile(phpIndex)
		// Upgrade only our exact original welcome template; never replace app code.
		if (errors.Is(er, os.ErrNotExist) && in.Site.Status == "provisioning") || (er == nil && string(existing) == body.String()) {
			content := strings.Replace(body.String(), "</main>", `<p data-php-runtime="<?php echo PHP_VERSION; ?>">实际运行 PHP <?php echo PHP_VERSION; ?></p></main>`, 1)
			if er = atomicWrite(phpIndex, []byte(content), 0644); er != nil {
				return result, er
			}
		}
	}

	documentRoot, rootErr := websiteRoot(in.Site, public)
	if rootErr != nil {
		return result, rootErr
	}
	add("核对并准备站点目录与默认首页")
	finishPHP, socket, phpErr := s.preparePHP(ctx, in.Site, dir, add)
	if phpErr != nil {
		return result, phpErr
	}
	committed := false
	defer func() {
		if !committed {
			_ = finishPHP(false)
		}
	}()
	probeName := "panel-check-" + core.ID() + ".php"
	probe := filepath.Join(documentRoot, probeName)
	if in.Site.PHPVersionID != "" {
		probeRoot, err := os.OpenRoot(public)
		if err != nil {
			return result, err
		}
		defer probeRoot.Close()
		rel := filepath.Join(in.Site.Settings.DocumentRoot, probeName)
		file, err := probeRoot.OpenFile(rel, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0644)
		if err != nil {
			return result, err
		}
		defer probeRoot.Remove(rel)
		_, err = file.WriteString(phpProbeScript(in.Site))
		if err == nil {
			err = file.Chmod(0644)
		}
		ce := file.Close()
		if err != nil {
			return result, err
		}
		if ce != nil {
			return result, ce
		}
		if err := fastCGIProbe(ctx, socket, probe, phpProbeExpected(in.Site)); err != nil {
			return result, fmt.Errorf("候选 PHP 进程验证失败，原站点配置未切换: %w", err)
		}
		add("通过候选 FPM Socket 执行 PHP，确认版本 " + phpVersion(in.Site.PHPVersionID))
	}
	configPath := filepath.Join(s.Config.ConfDir, in.Site.ID+".conf")
	old, readErr := os.ReadFile(configPath)
	hadOld := readErr == nil
	if readErr != nil && !errors.Is(readErr, os.ErrNotExist) {
		return result, readErr
	}
	if hadOld {
		if err := ordinary(configPath, false); err != nil {
			return result, err
		}
	}
	if in.ExpectedConfigSHA != "" && core.Hash(string(old)) != in.ExpectedConfigSHA {
		return result, errors.New("保存期间实际 Nginx 配置已变化，请重新预览")
	}
	content, renderErr := renderSiteConfig(in.Site, public)
	if renderErr != nil {
		return result, renderErr
	}
	if !in.Enabled {
		content = fmt.Sprintf("# managed by panel; site=%s; disabled\n", in.Site.ID)
	} else {
		content, renderErr = s.preserveWAFBodySiteConfig(content, in.Site.ID)
		if renderErr != nil {
			return result, renderErr
		}
	}
	backupDir := filepath.Join(s.Config.StateDir, "backups")
	if err := os.MkdirAll(backupDir, 0700); err != nil {
		return result, err
	}
	if hadOld {
		if err := atomicWrite(filepath.Join(backupDir, in.JobID+".conf"), old, 0600); err != nil {
			return result, err
		}
	}
	rollback := func() error {
		if hadOld {
			return atomicWrite(configPath, old, 0644)
		}
		err := os.Remove(configPath)
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}
	if err := atomicWrite(configPath, []byte(content), 0644); err != nil {
		return result, err
	}
	result.Restored = false
	apacheSites := in.Sites
	if len(apacheSites) == 0 {
		candidate := in.Site
		if !in.Enabled {
			candidate.Status = "stopped"
		} else {
			candidate.Status = "running"
		}
		apacheSites = []core.Site{candidate}
	}
	apacheRollback, err := s.applyApacheSites(ctx, apacheSites, add)
	if err != nil {
		if re := rollback(); re == nil && !strings.Contains(err.Error(), "恢复失败") {
			result.Restored = true
		}
		return result, err
	}
	apacheCommitted := false
	restoreAttempted := false
	defer func() {
		if !apacheCommitted && !restoreAttempted && apacheRollback != nil {
			_ = apacheRollback()
		}
	}()
	restoreApplied := func(reload bool) (error, error) {
		restoreAttempted = true
		nginxRestore := rollback()
		var reloadErr error
		if reload {
			_, reloadErr = s.Config.Run(context.Background(), "/usr/bin/systemctl", "reload", "nginx")
		}
		apacheRestore := apacheRollback()
		result.Restored = nginxRestore == nil && reloadErr == nil && apacheRestore == nil
		return errors.Join(nginxRestore, apacheRestore), reloadErr
	}
	nginxBin, err := s.nginxBinary()
	if err != nil {
		_, _ = restoreApplied(false)
		return result, err
	}
	if _, err := s.Config.Run(ctx, nginxBin, "-t"); err != nil {
		if re, _ := restoreApplied(false); re != nil {
			return result, fmt.Errorf("配置校验失败且恢复失败: %v / %w", err, re)
		}
		return result, fmt.Errorf("配置校验失败，原配置已恢复: %w", err)
	}
	add("生成配置并通过 nginx -t 语法校验")
	if _, err := s.Config.Run(ctx, "/usr/bin/systemctl", "reload", "nginx"); err != nil {
		re, rr := restoreApplied(true)
		return result, fmt.Errorf("重载失败；配置恢复=%v，服务重载=%v: %w", re, rr, err)
	}
	add("重载 Nginx，保留旧进程处理已有连接")
	expectedCode := 200
	if !in.Enabled {
		expectedCode = 404
	}
	var healthErr error
	client := &http.Client{Timeout: 3 * time.Second, Transport: &http.Transport{Proxy: nil, DisableKeepAlives: true}, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	if in.Enabled && in.Site.Settings.TLS != nil {
		var e error
		client, e = siteHTTPSClient(in.Site, in.Site.Domain)
		if e != nil {
			_, _ = restoreApplied(true)
			return result, e
		}
	}
	defer client.CloseIdleConnections()
	for i := 0; i < 12; i++ {
		checking := in.Site
		checking.Status = "running"
		if !in.Enabled {
			checking.Status = "stopped"
		}
		if er := verifySiteIngress(ctx, checking, false); er != nil {
			healthErr = er
			select {
			case <-ctx.Done():
				i = 12
			case <-time.After(200 * time.Millisecond):
			}
			continue
		}
		probeURL := "http://127.0.0.1:19101" + siteHealthPath(in.Site)
		if in.Enabled && in.Site.PHPVersionID != "" {
			probeURL = siteURL(in.Site, "/"+probeName)
		}
		req, _ := http.NewRequestWithContext(ctx, "GET", probeURL, nil)
		req.Host = in.Site.Domain
		resp, err := client.Do(req)
		if err == nil {
			body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
			resp.Body.Close()
			if resp.StatusCode == expectedCode && (!in.Enabled || in.Site.PHPVersionID == "" || strings.TrimSpace(string(body)) == phpProbeExpected(in.Site)) {
				healthErr = nil
				if in.Enabled {
					code, er := verifySiteHomepage(ctx, client, in.Site)
					healthErr = er
					if er == nil {
						add(fmt.Sprintf("网站首页实际返回 HTTP %d", code))
					}
				}
				if healthErr == nil {
					break
				}
				select {
				case <-ctx.Done():
					i = 12
				case <-time.After(200 * time.Millisecond):
				}
				continue
			}
			err = fmt.Errorf("HTTP %d，期望 %d", resp.StatusCode, expectedCode)
		}
		healthErr = err
		select {
		case <-ctx.Done():
			i = 12
		case <-time.After(200 * time.Millisecond):
		}
	}
	if healthErr == nil {
		checking := in.Site
		checking.Status = "running"
		if !in.Enabled {
			checking.Status = "stopped"
		}
		healthErr = verifySiteIngress(ctx, checking, false)
	}
	if healthErr != nil {
		re, rr := restoreApplied(true)
		return result, fmt.Errorf("HTTP 验证失败；配置恢复=%v，服务重载=%v: %w", re, rr, healthErr)
	}
	add(fmt.Sprintf("使用 %s 请求本机 Nginx，确认 HTTP %d", in.Site.Domain, expectedCode))
	if err := finishPHP(true); err != nil {
		re, rr := restoreApplied(true)
		return result, fmt.Errorf("保存 PHP 绑定失败；配置恢复=%v，重载=%v: %w", re, rr, err)
	}
	committed = true
	apacheCommitted = true
	if in.Site.PHPVersionID != "" {
		add("保存站点 PHP 与 CLI 绑定，其他网站保持原版本")
	}

	result.Status = "running"
	if !in.Enabled {
		result.Status = "stopped"
	}
	b, _ := json.Marshal(result)
	if err := atomicWrite(filepath.Join(s.Config.StateDir, in.JobID+".json"), b, 0600); err != nil {
		return result, fmt.Errorf("站点已应用，但执行记录写入失败，需要核对: %w", err)
	}
	return result, nil
}
func (s *Service) Handler() http.Handler {
	m := http.NewServeMux()
	m.HandleFunc("GET /v1/health", func(w http.ResponseWriter, r *http.Request) { respond(w, 200, map[string]string{"status": "ok"}) })
	runtimeRoutes(m)
	phpExtensionRoutes(m)
	s.certificateRoutes(m)
	mysqlRoutes(m)
	s.nginxRoutes(m)
	s.fileRoutes(m)
	s.systemFileRoutes(m)
	s.siteSettingsRoutes(m)
	s.siteTrafficRoutes(m)
	s.databaseMetricRoutes(m)
	s.databaseConnectionRoutes(m)
	s.siteArchiveRoutes(m)
	runtimeReferenceRoutes(m)
	s.lifecycleRoutes(m)
	s.monitorServiceRoutes(m)
	s.monitorProcessRoutes(m)
	s.securityRoutes(m)
	s.siteSecurityScanRoutes(m)
	s.fail2banRoutes(m)
	s.systemBackupRoutes(m)
	s.terminalRoutes(m)
	s.sftpRoutes(m)
	s.dockerRoutes(m)
	s.redisRoutes(m)
	s.mariadbRoutes(m)
	s.nodeRoutes(m)
	s.phpWorkerRoutes(m)
	s.softwareRoutes(m)
	s.appModuleRoutes(m)
	m.HandleFunc("POST /v1/sites/apply", func(w http.ResponseWriter, r *http.Request) {
		var in core.ApplyRequest
		if !readJSON(w, r, &in) {
			return
		}
		result, err := s.Apply(r.Context(), in)
		if err != nil {
			respond(w, 500, map[string]any{"error": err.Error(), "steps": result.Steps, "status": result.Status, "restored": result.Restored})
			return
		}
		respond(w, 200, result)
	})
	m.HandleFunc("POST /v1/sites/config", func(w http.ResponseWriter, r *http.Request) {
		var v struct {
			ID string `json:"id"`
		}
		if !readJSON(w, r, &v) {
			return
		}
		if !core.ValidID(v.ID) {
			respond(w, 400, map[string]string{"error": "无效标识"})
			return
		}
		path := filepath.Join(s.Config.ConfDir, v.ID+".conf")
		if err := ordinary(path, false); err != nil {
			respond(w, 404, map[string]string{"error": "站点配置尚不存在"})
			return
		}
		b, err := os.ReadFile(path)
		if err != nil {
			respond(w, 500, map[string]string{"error": "读取配置失败"})
			return
		}
		respond(w, 200, map[string]string{"path": path, "content": string(b)})
	})
	m.HandleFunc("GET /v1/runtimes", func(w http.ResponseWriter, r *http.Request) {
		unlock, e := s.lockRuntimeUse()
		if e != nil {
			respond(w, 409, map[string]string{"error": e.Error()})
			return
		}
		defer unlock()
		version, err := s.Config.Run(r.Context(), s.Config.NginxBin, "-v")
		if err != nil {
			respond(w, 503, map[string]string{"error": "无法读取 Nginx 版本"})
			return
		}
		pkg, pkgErr := s.Config.Run(r.Context(), "/usr/bin/dpkg-query", "-W", "-f=${Version}", "nginx")
		if pkgErr != nil {
			respond(w, 503, map[string]string{"error": "无法核对 Nginx 软件包版本"})
			return
		}
		major := runtimecatalog.HostPlatform()
		debianSource := "系统软件包"
		if major != "" {
			debianSource = major + " 系统软件包"
		}
		installed := []map[string]any{{"id": "nginx-system", "family": "nginx", "version": strings.TrimSpace(version), "source": debianSource, "binary": s.Config.NginxBin, "status": "verified_base", "package_version": strings.TrimSpace(pkg), "architecture": runtime.GOARCH}}
		installed = append(installed, phpInventory(r.Context())...)
		active, er := activeNginx()
		if er != nil {
			respond(w, 503, map[string]string{"error": er.Error()})
			return
		}
		retired, er := retiredInventory()
		if er != nil {
			respond(w, 409, map[string]string{"error": er.Error()})
			return
		}
		respond(w, 200, map[string]any{"installed": installed, "active_nginx": active, "retired": retired})
	})
	m.HandleFunc("GET /v1/overview", func(w http.ResponseWriter, r *http.Request) {
		metrics := Snapshot()
		active, err := s.Config.Run(r.Context(), "/usr/bin/systemctl", "is-active", "nginx")
		metrics["nginx_active"] = err == nil && strings.TrimSpace(active) == "active"
		metrics["sampled_at"] = core.Now()
		respond(w, 200, metrics)
	})
	return m
}
func readJSON(w http.ResponseWriter, r *http.Request, v any) bool {
	d := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64*1024))
	d.DisallowUnknownFields()
	if d.Decode(v) != nil {
		respond(w, 400, map[string]string{"error": "无效请求"})
		return false
	}
	if d.Decode(&struct{}{}) != io.EOF {
		respond(w, 400, map[string]string{"error": "请求必须为单个对象"})
		return false
	}
	return true
}
func respond(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

var welcome = template.Must(template.New("welcome").Parse(`<!doctype html><html lang="zh-CN"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>{{.Name}}</title><style>body{margin:0;min-height:100vh;display:grid;place-items:center;background:#f3f7f6;color:#182e2b;font:16px system-ui}main{max-width:600px;padding:60px}small{color:#087f6a;letter-spacing:3px}h1{font-size:44px;line-height:1.2}p{line-height:1.8;color:#61726d}code{background:#e2eeea;padding:8px 12px;border-radius:6px}.mark{font-size:60px;color:#0f766e}</style><main><div class="mark">✓</div><small>YOUR SERVER · YOUR SPACE</small><h1>{{.Name}}</h1><p>站点已经创建。这一页由开发虚拟机中的 Nginx 实际提供。</p><p><code>{{.Domain}}</code></p><p>下一步可以在面板中查看任务、检查配置，或停用和启用这个站点。</p></main></html>`))
