//go:build linux

package executor

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"local/panel/internal/core"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
)

const wafEventReadBytes int64 = 1024 * 1024
const wafEventLimit = 100

func (s *Service) wafEvents() (core.WAFEventsPage, error) {
	return s.readWAFEvents(wafEventReadBytes, wafEventLimit)
}
func (s *Service) readWAFEvents(maxBytes int64, limit int) (core.WAFEventsPage, error) {
	page := core.WAFEventsPage{Events: []core.WAFEvent{}}
	path := s.systemPath("/var/log/nginx/panel-waf.log")
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if errors.Is(err, os.ErrNotExist) {
		return page, nil
	}
	if err != nil {
		return page, err
	}
	defer f.Close()
	stat, err := f.Stat()
	if err != nil || !stat.Mode().IsRegular() {
		return page, errors.New("WAF 事件日志不是普通文件")
	}
	start := max(0, stat.Size()-maxBytes)
	if _, err = f.Seek(start, io.SeekStart); err != nil {
		return page, err
	}
	data, err := io.ReadAll(io.LimitReader(f, maxBytes))
	if err != nil {
		return page, err
	}
	lines := bytes.Split(data, []byte{'\n'})
	if start > 0 {
		lines = lines[1:]
		page.HasMore = true
	}
	for i := len(lines) - 1; i >= 0; i-- {
		line := bytes.TrimSpace(lines[i])
		if len(line) == 0 || len(line) > 4096 {
			continue
		}
		var event core.WAFEvent
		if json.Unmarshal(line, &event) != nil || event.Time == "" || event.Site == "" || event.IP == "" {
			continue
		}
		if len(page.Events) == limit {
			page.HasMore = true
			break
		}
		page.Events = append(page.Events, event)
	}
	return page, nil
}

type softwareManifest struct {
	ID          string            `json:"id"`
	Version     string            `json:"version"`
	Settings    map[string]any    `json:"settings"`
	Previous    map[string]string `json:"previous,omitempty"`
	InstalledAt string            `json:"installed_at"`
}

func (s *Service) systemPath(path string) string {
	if s.Config.SystemRoot == "/" {
		return path
	}
	return filepath.Join(s.Config.SystemRoot, strings.TrimPrefix(path, "/"))
}
func (s *Service) softwareManifestPath(id string) string {
	return filepath.Join(s.Config.SecurityDir, id+".json")
}
func (s *Service) writeSoftwareManifest(v softwareManifest) error {
	if e := os.MkdirAll(s.Config.SecurityDir, 0700); e != nil {
		return e
	}
	if e := ordinary(s.Config.SecurityDir, true); e != nil {
		return e
	}
	b, _ := json.MarshalIndent(v, "", "  ")
	return atomicWrite(s.softwareManifestPath(v.ID), append(b, '\n'), 0600)
}

func softwareInt(settings map[string]any, key string) int {
	switch n := settings[key].(type) {
	case float64:
		return int(n)
	case int:
		return n
	case json.Number:
		v, _ := n.Int64()
		return int(v)
	}
	return 0
}

func wafFiles(s *Service) (string, string) {
	base := s.systemPath("/etc/panel/waf")
	return filepath.Join(base, "http.d/10-panel-waf.conf"), filepath.Join(base, "server.d/10-panel-waf.conf")
}
func renderWAF(settings map[string]any) (string, string) {
	if _, advanced := settings["policy"]; advanced {
		cfg, err := core.DecodeWAFConfig(settings)
		if err == nil {
			return renderWAFPolicy(cfg)
		}
	}
	return renderLegacyWAF(settings)
}
func renderLegacyWAF(settings map[string]any) (string, string) {
	profile, _ := settings["profile"].(string)
	rate := softwareInt(settings, "rate_per_second")
	patterns := `(?:<|%3c)(?:script|iframe)|(?:union(?:%20|\\s)+select)|(?:/etc/passwd|\\.\\./)|(?:base64_decode|eval\\s*\\()`
	ua := `(?:sqlmap|nikto|masscan|nmap|acunetix|nessus|wpscan)`
	if profile == "strict" {
		patterns = `(?:<|%3c)(?:script|iframe|object)|(?:union(?:%20|\\s)+select)|(?:select(?:%20|\\s)+.+(?:%20|\\s)+from)|(?:/etc/passwd|\\.\\./|%2e%2e%2f)|(?:base64_decode|eval\\s*\\(|assert\\s*\\()`
		ua = `(?:sqlmap|nikto|masscan|nmap|acunetix|nessus|wpscan|zgrab|dirbuster|gobuster)`
	}
	httpConfig := fmt.Sprintf("# managed by panel nginx-waf 1.1\nlimit_req_zone $binary_remote_addr zone=panel_waf_per_ip:10m rate=%dr/s;\nmap $request_method $panel_waf_bad_method { default 0; TRACE 1; TRACK 1; }\nmap $args $panel_waf_bad_args { default 0; ~*%s 1; }\nmap $request_uri $panel_waf_bad_uri { default 0; ~*%s 1; }\nmap $http_user_agent $panel_waf_bad_agent { default 0; ~*%s 1; }\nmap \"$panel_waf_bad_method$panel_waf_bad_args$panel_waf_bad_uri$panel_waf_bad_agent\" $panel_waf_detected { \"0000\" 0; default 1; }\nmap \"$status:$panel_waf_detected:$limit_req_status\" $panel_waf_event { default 0; ~^403:1: 1; ~^405:1: 1; \"429:0:REJECTED\" 1; }\nlog_format panel_waf escape=json '{\"time\":\"$time_iso8601\",\"site\":\"$server_name\",\"ip\":\"$remote_addr\",\"status\":$status,\"method\":\"$request_method\",\"bad_method\":\"$panel_waf_bad_method\",\"bad_args\":\"$panel_waf_bad_args\",\"bad_uri\":\"$panel_waf_bad_uri\",\"bad_agent\":\"$panel_waf_bad_agent\",\"rate\":\"$limit_req_status\"}';\n", rate, patterns, patterns, ua)
	serverConfig := "# managed by panel nginx-waf 1.1\nif ($panel_waf_bad_method) { return 405; }\nif ($panel_waf_bad_args) { return 403; }\nif ($panel_waf_bad_uri) { return 403; }\nif ($panel_waf_bad_agent) { return 403; }\nlimit_req zone=panel_waf_per_ip burst=60 nodelay;\nlimit_req_status 429;\naccess_log /var/log/nginx/panel-waf.log panel_waf if=$panel_waf_event;\nadd_header X-Panel-WAF active always;\n"
	return httpConfig, serverConfig
}

type fileBackup struct {
	path    string
	data    []byte
	existed bool
	mode    os.FileMode
	owner   *fileOwner
}

func backupFile(path string) (fileBackup, error) {
	b := fileBackup{path: path, mode: 0644}
	st, e := os.Lstat(path)
	if errors.Is(e, os.ErrNotExist) {
		return b, nil
	}
	if e != nil {
		return b, e
	}
	if !st.Mode().IsRegular() || st.Mode()&os.ModeSymlink != 0 {
		return b, errors.New("受管配置路径类型异常")
	}
	b.owner, e = fileOwnerForInfo(st)
	if e != nil {
		return b, e
	}
	b.data, e = os.ReadFile(path)
	b.existed = true
	b.mode = st.Mode().Perm()
	return b, e
}
func restoreFiles(backups []fileBackup) error {
	var out error
	for i := len(backups) - 1; i >= 0; i-- {
		b := backups[i]
		if b.existed {
			out = errors.Join(out, atomicWriteWithOwner(b.path, b.data, b.mode, b.owner))
		} else if e := os.Remove(b.path); e != nil && !errors.Is(e, os.ErrNotExist) {
			out = errors.Join(out, e)
		}
	}
	return out
}
func ensureLineAfter(content, marker, line string, all bool) (string, error) {
	if strings.Contains(content, line) {
		return content, nil
	}
	if !strings.Contains(content, marker) {
		return "", errors.New("无法在受管 Nginx 配置中定位安全插入点")
	}
	if all {
		return strings.ReplaceAll(content, marker, marker+line), nil
	}
	return strings.Replace(content, marker, marker+line, 1), nil
}
func (s *Service) ensureWAFIncludes() ([]fileBackup, error) {
	paths := []string{s.Config.NginxConf}
	entries, e := os.ReadDir(s.Config.ConfDir)
	if e == nil {
		for _, entry := range entries {
			if !entry.IsDir() && strings.HasSuffix(entry.Name(), ".conf") {
				paths = append(paths, filepath.Join(s.Config.ConfDir, entry.Name()))
			}
		}
	}
	backups := []fileBackup{}
	for _, path := range paths {
		backup, e := backupFile(path)
		if e != nil {
			return backups, e
		}
		content := string(backup.data)
		if path == s.Config.NginxConf {
			content, e = ensureLineAfter(content, "http {\n", "  include /etc/panel/waf/http.d/*.conf;\n", false)
		} else if strings.HasPrefix(content, "# managed by panel;") && strings.Contains(content, "server {\n") && !strings.Contains(strings.SplitN(content, "\n", 2)[0], "panel-waf-disabled") {
			id := strings.TrimSuffix(filepath.Base(path), ".conf")
			if !core.ValidID(id) || !strings.HasPrefix(content, "# managed by panel; site="+id) {
				continue
			}
			include := "  include /etc/panel/waf/server.d/*.conf;\n"
			line := "  set $panel_waf_site " + id + ";\n" + include
			if strings.Contains(content, include) && !strings.Contains(content, line) {
				content = strings.ReplaceAll(content, include, line)
			} else {
				content, e = ensureLineAfter(content, "server {\n", line, true)
			}
		} else {
			continue
		}
		if e != nil {
			return backups, e
		}
		if content != string(backup.data) {
			backups = append(backups, backup)
			if e = atomicWrite(path, []byte(content), backup.mode); e != nil {
				return backups, e
			}
		}
	}
	return backups, nil
}
func (s *Service) applyWAF(ctx context.Context, settings map[string]any, install bool, add func(string)) error {
	manifest, err := s.readSoftwareManifest("nginx-waf")
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("Nginx WAF 安装记录无法核对；未执行变更: %w", err)
	}
	// Refuse before acquiring a creating lock or entering recovery. Only the
	// explicit versioned upgrade path may migrate an old installed app.
	if !install && err == nil && manifest.Version != core.WAFVersion {
		return errors.New("请先通过应用商店更新 Nginx WAF；保存配置不能替代签名应用更新")
	}
	nginx, err := s.nginxBinary()
	if err != nil {
		return err
	}
	lock, err := s.lockWAFConfiguration()
	if err != nil {
		return err
	}
	defer lock.Close()
	unlock, err := s.lockRuntimeUse()
	if err != nil {
		return err
	}
	defer unlock()
	if !install {
		lockedManifest, err := s.readSoftwareManifest("nginx-waf")
		if err != nil || lockedManifest.Version != core.WAFVersion {
			return errors.New("Nginx WAF 安装版本已变化，请刷新并通过应用商店核对；未执行恢复或保存")
		}
	}
	if err := s.recoverWAFBeforeMutation(ctx, nginx); err != nil {
		return err
	}
	manifest, e := s.readSoftwareManifest("nginx-waf")
	if install && e == nil {
		return errors.New("Nginx WAF 已安装，请使用配置操作")
	} else if !install && e != nil {
		return errors.New("请先安装 Nginx WAF")
	}
	if !install && manifest.Version != core.WAFVersion {
		return errors.New("请先通过应用商店更新 Nginx WAF；保存配置不能替代签名应用更新")
	}
	if !install && s.wafReplayMatches(settings) {
		if _, err := s.Config.Run(ctx, nginx, "-t", "-c", s.Config.NginxConf); err != nil {
			return err
		}
		add("恢复已提交的同一修订配置任务：实际规则文件一致且 Nginx 校验通过")
		manifest, err := s.readSoftwareManifest("nginx-waf")
		if err != nil {
			return err
		}
		current, err := core.DecodeWAFConfig(manifest.Settings)
		if err != nil {
			return err
		}
		if err := s.verifyWAFTrustedProxy(ctx, current, nginx); err != nil {
			return err
		}
		if err := s.verifyWAFBodyEngine(current); err != nil {
			return err
		}
		if err = s.verifyWAFReload(ctx, current, nginx); err != nil {
			return err
		}
		return nil
	}
	cfg, e := s.prepareWAFSettings(settings, install)
	if e != nil {
		return e
	}
	cfg.Policy.Revision++
	return s.applyWAFTransaction(ctx, cfg, false, nginx, add)
}
func (s *Service) uninstallWAF(ctx context.Context, add func(string)) error {
	nginx, err := s.nginxBinary()
	if err != nil {
		return err
	}
	lock, err := s.lockWAFConfiguration()
	if err != nil {
		return err
	}
	defer lock.Close()
	unlock, err := s.lockRuntimeUse()
	if err != nil {
		return err
	}
	defer unlock()
	if err := s.recoverWAFBeforeMutation(ctx, nginx); err != nil {
		return err
	}
	manifest, e := s.readSoftwareManifest("nginx-waf")
	if e != nil {
		return errors.New("Nginx WAF 未安装")
	}
	cfg, e := core.DecodeWAFConfig(manifest.Settings)
	if e != nil {
		return e
	}
	return s.applyWAFTransaction(ctx, cfg, true, nginx, add)
}

func hardeningValues(profile string) map[string]string {
	v := map[string]string{"fs.protected_hardlinks": "1", "fs.protected_symlinks": "1", "fs.protected_fifos": "2", "fs.protected_regular": "2", "kernel.kptr_restrict": "2", "kernel.dmesg_restrict": "1", "kernel.yama.ptrace_scope": "1", "net.ipv4.conf.all.accept_redirects": "0", "net.ipv4.conf.default.accept_redirects": "0", "net.ipv4.conf.all.send_redirects": "0", "net.ipv4.conf.default.send_redirects": "0", "net.ipv6.conf.all.accept_redirects": "0", "net.ipv6.conf.default.accept_redirects": "0"}
	if profile == "strict" {
		v["kernel.unprivileged_bpf_disabled"] = "2"
		v["net.ipv4.conf.all.log_martians"] = "1"
	}
	return v
}
func renderSysctl(values map[string]string) string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	var out strings.Builder
	out.WriteString("# managed by panel system-hardening 1.0\n")
	for _, key := range keys {
		fmt.Fprintf(&out, "%s = %s\n", key, values[key])
	}
	return out.String()
}
func (s *Service) sysctlValue(ctx context.Context, key string) (string, error) {
	out, e := s.Config.Run(ctx, "/usr/sbin/sysctl", "-n", key)
	return strings.TrimSpace(out), e
}
func (s *Service) applyHardening(ctx context.Context, settings map[string]any, install bool, add func(string)) error {
	return s.applyHardeningTransition(ctx, settings, install, add)
}
func (s *Service) uninstallHardening(ctx context.Context, add func(string)) error {
	return s.uninstallHardeningTransition(ctx, add)
}

func renderIntrusion(settings map[string]any) string {
	return fmt.Sprintf("# managed by panel intrusion-prevention 1.0\n[sshd]\nenabled = true\nbackend = systemd\nmaxretry = %d\nfindtime = %dm\nbantime = %dm\n", softwareInt(settings, "max_retry"), softwareInt(settings, "find_time_minutes"), softwareInt(settings, "ban_time_minutes"))
}

func (s *Service) applyIntrusion(ctx context.Context, settings map[string]any, install bool, add func(string)) error {
	action := "configure"
	if install {
		action = "install"
	}
	return s.applyIntrusionOperation(ctx, settings, action, add)
}

func (s *Service) uninstallIntrusion(ctx context.Context, add func(string)) error {
	return s.applyIntrusionOperation(ctx, nil, "uninstall", add)
}

func (s *Service) softwareStatus(ctx context.Context, id string) core.SoftwareAppStatus {
	return s.softwareStatusWithWAFLock(ctx, id, nil)
}

func (s *Service) softwareStatusWithWAFLock(ctx context.Context, id string, wafLock *os.File) core.SoftwareAppStatus {
	if id == "intrusion-prevention" {
		return s.intrusionSoftwareStatus(ctx)
	}
	if id == "system-hardening" {
		inspection, err := s.inspectHardening(ctx)
		out := core.SoftwareAppStatus{ID: id, Installed: inspection.Installed, Enabled: inspection.Installed, Healthy: inspection.Healthy, Version: inspection.Version, Detail: inspection.Detail}
		if err != nil {
			out.StateUnknown = true
			out.Healthy = false
			out.Detail = err.Error()
		} else if inspection.Installed {
			out.Settings = map[string]any{"profile": inspection.Profile}
		}
		return out
	}
	if _, ok := core.FindAppModule(id); ok {
		return s.appModuleStatus(ctx, id)
	}
	out := core.SoftwareAppStatus{ID: id, Detail: "未安装"}
	manifest, e := s.readSoftwareManifest(id)
	if e != nil {
		if !errors.Is(e, os.ErrNotExist) {
			out.StateUnknown = true
			out.Detail = "软件安装记录无法核对，未将异常当作未安装"
		}
		return out
	}
	out.Installed = true
	out.Version = manifest.Version
	out.Settings = manifest.Settings
	switch id {
	case "nginx-waf":
		httpPath, serverPath := wafFiles(s)
		_, h := os.Stat(httpPath)
		_, v := os.Stat(serverPath)
		out.Enabled = h == nil && v == nil
		cfg, configErr := core.DecodeWAFConfig(manifest.Settings)
		if configErr != nil {
			out.Detail = "防火墙清单不可解析，请核对；未确认规则生效"
			return out
		}
		if _, err := os.Lstat(s.wafPendingPath()); !errors.Is(err, os.ErrNotExist) {
			out.Detail = "存在未完成防火墙配置事务，需恢复后重新核对；未确认新规则生效"
			return out
		}
		// A panel program upgrade does not rewrite installed application state.
		// Accept only byte-identical 2.0.1 (no-body) and 2.1.0 implementations
		// as migratable old installs; all site files, manifest, syntax and the
		// real live old fingerprint must still pass. Never bypass health merely
		// because a newer catalog version exists.
		checkedVersion := core.WAFVersion
		legacy := manifest.Version != core.WAFVersion && wafHistoricalVersionValid(manifest.Version, cfg)
		if legacy {
			checkedVersion = manifest.Version
			if configErr := s.wafLegacyMigrationReferences(cfg); configErr != nil {
				out.Detail = configErr.Error()
				return out
			}
		}
		plan, configErr := s.planWAFConfigurationVersion(cfg, false, checkedVersion)
		if configErr != nil || len(plan) != 0 {
			out.Detail = "实际规则、网站配置或清单存在偏差；未确认已加载，请预览核对后安全应用"
			return out
		}
		if err := s.verifyWAFBodyEngine(cfg); err != nil {
			out.Detail = "原生请求体引擎核对失败：" + err.Error()
			return out
		}
		nginx, err := s.nginxBinary()
		if err == nil {
			_, err = s.Config.Run(ctx, nginx, "-t", "-c", s.Config.NginxConf)
		}
		if err == nil {
			err = s.verifyWAFReloadVersion(ctx, cfg, nginx, checkedVersion)
		}
		e = err
		out.Healthy = out.Enabled && e == nil
		if cfg.Policy.Mode == "off" {
			out.Enabled = false
		}
		if out.Healthy {
			out.Detail = "实际配置与清单一致、Nginx 校验及生效指纹通过；请求体防护仅作用于明确选中且未停用的网站"
			if legacy {
				out.Detail = "旧版 " + manifest.Version + " 规则、网站配置及实际生效指纹通过；可安全更新并保留原策略与请求体引擎选择"
			}
			if cfg.Body != nil {
				for _, site := range cfg.Body.Sites {
					if _, active := core.WAFEffectiveBodyPolicy(cfg, site.SiteID); !active {
						continue
					}
					var err error
					if wafLock == nil {
						err = s.wafBodyLogHealth(ctx)
					} else {
						err = s.wafBodyLogHealthUnderLock(ctx, wafLock)
					}
					if err != nil {
						out.Healthy = false
						out.Detail = "规则生效指纹已核实，但请求体日志需要核对：" + err.Error() + "；防护继续执行，原证据保留"
					}
					break
				}
			}
		} else {
			out.Detail = "请核对：WAF 配置缺失、Nginx 校验失败或服务未运行"
		}
	}
	return out
}

func (s *Service) softwareRoutes(m *http.ServeMux) {
	s.loadBalanceStreamInstallRoutes(m)
	s.loadBalanceStreamControlRoutes(m)
	s.hardeningInspectionRoutes(m)
	s.intrusionInspectionRoutes(m)
	s.wafWorkspaceRoutes(m)
	m.HandleFunc("GET /v1/software/nginx-waf/events", func(w http.ResponseWriter, r *http.Request) {
		if _, err := s.readSoftwareManifest("nginx-waf"); err != nil {
			if !errors.Is(err, os.ErrNotExist) {
				respond(w, 409, map[string]any{"error": "Nginx WAF 安装记录无法核对；未读取事件", "state_unknown": true})
				return
			}
			respond(w, 409, map[string]string{"error": "Nginx WAF 未安装"})
			return
		}
		page, err := s.wafEvents()
		if err != nil {
			respond(w, 503, map[string]string{"error": "WAF 事件日志读取失败"})
			return
		}
		respond(w, 200, page)
	})
	m.HandleFunc("GET /v1/software", func(w http.ResponseWriter, r *http.Request) {
		ids := []string{"nginx-waf", "system-hardening", "intrusion-prevention"}
		for _, d := range core.AppModules() {
			ids = append(ids, d.ID)
		}
		out := make([]core.SoftwareAppStatus, 0, len(ids))
		for _, id := range ids {
			out = append(out, s.softwareStatus(r.Context(), id))
		}
		respond(w, 200, out)
	})
	m.HandleFunc("POST /v1/software/{id}/{action}", func(w http.ResponseWriter, r *http.Request) {
		id, action := r.PathValue("id"), r.PathValue("action")
		var in struct {
			Settings map[string]any `json:"settings"`
			Version  string         `json:"version"`
			JobID    string         `json:"job_id"`
		}
		if id == "intrusion-prevention" {
			raw, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 4096))
			if err != nil || decodeProgramQueueJSON(raw, &in) != nil {
				respond(w, 400, map[string]string{"error": "防入侵原任务请求缺失、重复、未知或超过固定边界"})
				return
			}
		} else if !readJSON(w, r, &in) {
			return
		}
		if id != "system-hardening" && id != "intrusion-prevention" && in.JobID != "" {
			respond(w, 400, map[string]string{"error": "原队列任务协议仅用于受管事务安全应用，未忽略其他应用的额外参数"})
			return
		}
		_, moduleOK := core.FindAppModule(id)
		if !moduleOK && id != "nginx-waf" && id != "system-hardening" && id != "intrusion-prevention" {
			respond(w, 404, map[string]string{"error": "软件不在受管目录中"})
			return
		}
		if action != "install" && action != "configure" && action != "uninstall" && action != "update" && !((id == "system-hardening" || id == "intrusion-prevention") && action == "recover") {
			respond(w, 400, map[string]string{"error": "软件操作无效"})
			return
		}
		result := core.ApplyResult{Steps: []core.Step{}}
		add := func(message string) {
			result.Steps = append(result.Steps, core.Step{Time: core.Now(), Message: message})
		}
		s.mu.Lock()
		defer s.mu.Unlock()
		if !moduleOK {
			if _, err := s.readSoftwareManifest(id); err != nil && !errors.Is(err, os.ErrNotExist) {
				respond(w, 409, map[string]any{"error": "软件安装记录无法核对；未执行安装、配置、卸载或更新", "state_unknown": true})
				return
			}
		}
		var e error
		install := action == "install"
		if id == "nginx-waf" && install && in.Version != core.WAFVersion {
			respond(w, 409, map[string]string{"error": "Nginx WAF 安装须使用应用商店中与面板能力匹配的签名版本；未隐式提升旧包"})
			return
		}
		if id == "system-hardening" && install && in.Version != core.HardeningAppVersion {
			respond(w, 409, map[string]string{"error": "系统加固1.1.0须通过匹配版本的签名应用安装；未隐式提升旧包能力"})
			return
		}
		ctx := r.Context()
		if id == "intrusion-prevention" {
			ctx = context.WithValue(ctx, intrusionJobContextKey{}, in.JobID)
			if _, err := intrusionOriginalJob(ctx); err != nil {
				respond(w, 400, map[string]string{"error": err.Error()})
				return
			}
			if install && in.Version != core.IntrusionAppVersion {
				respond(w, 409, map[string]string{"error": "防入侵1.1.0须通过匹配版本的签名应用安装；未提升旧包或直接安装"})
				return
			}
			if !install && action != "update" && in.Version != "" || (action == "update" || action == "uninstall") && len(in.Settings) != 0 {
				respond(w, 400, map[string]string{"error": "防入侵请求附带未知版本或限额；未忽略额外意图"})
				return
			}
		}
		if action == "recover" {
			if id == "intrusion-prevention" {
				e = s.recoverIntrusionOperation(ctx, in.Settings, add)
			} else {
				e = s.recoverHardeningOperation(context.WithValue(ctx, hardeningJobContextKey{}, in.JobID), in.Settings, add)
			}
		} else if action == "update" {
			if id == "system-hardening" {
				ctx = context.WithValue(ctx, hardeningJobContextKey{}, in.JobID)
			}
			e = s.updateSoftware(ctx, id, in.Version, add)
		} else if moduleOK {
			e = s.appModuleLifecycleVersion(r.Context(), id, action, in.Settings, in.Version, add)
		} else if action == "uninstall" {
			switch id {
			case "nginx-waf":
				e = s.uninstallWAF(r.Context(), add)
			case "system-hardening":
				e = s.uninstallHardening(context.WithValue(r.Context(), hardeningJobContextKey{}, in.JobID), add)
			case "intrusion-prevention":
				e = s.uninstallIntrusion(ctx, add)
			}
		} else {
			switch id {
			case "nginx-waf":
				e = s.applyWAF(r.Context(), in.Settings, install, add)
			case "system-hardening":
				e = s.applyHardening(context.WithValue(r.Context(), hardeningJobContextKey{}, in.JobID), in.Settings, install, add)
			case "intrusion-prevention":
				e = s.applyIntrusion(ctx, in.Settings, install, add)
			}
		}
		if e != nil {
			respond(w, 409, map[string]any{"error": e.Error(), "steps": result.Steps})
			return
		}
		result.Status = map[bool]string{true: "installed", false: "configured"}[install]
		if action == "uninstall" {
			result.Status = "uninstalled"
		}
		if action == "update" {
			result.Status = "updated"
		}
		if action == "recover" {
			result.Status = "recovered"
		}
		respond(w, 200, result)
	})
}
