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
	"time"
)

const wafEventReadBytes int64 = 1024 * 1024
const wafEventLimit = 100

func (s *Service) wafEvents() (core.WAFEventsPage, error) {
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
	start := max(0, stat.Size()-wafEventReadBytes)
	if _, err = f.Seek(start, io.SeekStart); err != nil {
		return page, err
	}
	data, err := io.ReadAll(io.LimitReader(f, wafEventReadBytes))
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
		if len(page.Events) == wafEventLimit {
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
func (s *Service) readSoftwareManifest(id string) (softwareManifest, error) {
	var v softwareManifest
	b, e := os.ReadFile(s.softwareManifestPath(id))
	if e != nil {
		return v, e
	}
	if e = json.Unmarshal(b, &v); e != nil || v.ID != id || (v.Version != "1.0" && !(id == "nginx-waf" && v.Version == "1.1")) {
		return v, errors.New("软件安装清单无效")
	}
	return v, nil
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
			out = errors.Join(out, atomicWrite(b.path, b.data, b.mode))
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
			content, e = ensureLineAfter(content, "server {\n", "  include /etc/panel/waf/server.d/*.conf;\n", true)
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
	if _, e := s.readSoftwareManifest("nginx-waf"); install && e == nil {
		return errors.New("Nginx WAF 已安装，请使用配置操作")
	} else if !install && e != nil {
		return errors.New("请先安装 Nginx WAF")
	}
	httpPath, serverPath := wafFiles(s)
	for _, dir := range []string{filepath.Dir(httpPath), filepath.Dir(serverPath)} {
		if e := os.MkdirAll(dir, 0750); e != nil {
			return e
		}
	}
	httpConfig, serverConfig := renderWAF(settings)
	backups := []fileBackup{}
	for _, path := range []string{httpPath, serverPath} {
		b, e := backupFile(path)
		if e != nil {
			return e
		}
		backups = append(backups, b)
	}
	includeBackups, e := s.ensureWAFIncludes()
	backups = append(backups, includeBackups...)
	if e != nil {
		_ = restoreFiles(backups)
		return e
	}
	if e = atomicWrite(httpPath, []byte(httpConfig), 0640); e == nil {
		e = atomicWrite(serverPath, []byte(serverConfig), 0640)
	}
	if e == nil {
		_, e = s.Config.Run(ctx, s.Config.NginxBin, "-t", "-c", s.Config.NginxConf)
	}
	if e == nil {
		_, e = s.Config.Run(ctx, "/usr/bin/systemctl", "reload", "nginx")
	}
	if e != nil {
		restoreErr := restoreFiles(backups)
		return fmt.Errorf("WAF 配置未生效，已恢复=%v: %w", restoreErr == nil, e)
	}
	manifest := softwareManifest{ID: "nginx-waf", Version: "1.1", Settings: settings, InstalledAt: core.Now()}
	if old, er := s.readSoftwareManifest("nginx-waf"); er == nil {
		manifest.InstalledAt = old.InstalledAt
	}
	if e = s.writeSoftwareManifest(manifest); e != nil {
		_ = restoreFiles(backups)
		_, _ = s.Config.Run(context.Background(), "/usr/bin/systemctl", "reload", "nginx")
		return e
	}
	add("生成固定 WAF 规则并接入受管 Nginx 站点")
	add("通过 nginx -t 并重载服务")
	return nil
}
func (s *Service) uninstallWAF(ctx context.Context, add func(string)) error {
	if _, e := s.readSoftwareManifest("nginx-waf"); e != nil {
		return errors.New("Nginx WAF 未安装")
	}
	httpPath, serverPath := wafFiles(s)
	backups := []fileBackup{}
	for _, path := range []string{httpPath, serverPath} {
		b, e := backupFile(path)
		if e != nil {
			return e
		}
		backups = append(backups, b)
		if e = os.Remove(path); e != nil && !errors.Is(e, os.ErrNotExist) {
			_ = restoreFiles(backups)
			return e
		}
	}
	if _, e := s.Config.Run(ctx, s.Config.NginxBin, "-t", "-c", s.Config.NginxConf); e != nil {
		_ = restoreFiles(backups)
		return e
	}
	if _, e := s.Config.Run(ctx, "/usr/bin/systemctl", "reload", "nginx"); e != nil {
		_ = restoreFiles(backups)
		return e
	}
	if e := os.Remove(s.softwareManifestPath("nginx-waf")); e != nil {
		_ = restoreFiles(backups)
		return e
	}
	add("移除 WAF 规则并通过 Nginx 校验；保留空的安全 include 插入点")
	return nil
}

func hardeningValues(profile string) map[string]string {
	v := map[string]string{"fs.protected_hardlinks": "1", "fs.protected_symlinks": "1", "fs.protected_fifos": "2", "fs.protected_regular": "2", "kernel.kptr_restrict": "2", "kernel.dmesg_restrict": "1", "kernel.yama.ptrace_scope": "1", "net.ipv4.conf.all.accept_redirects": "0", "net.ipv4.conf.default.accept_redirects": "0", "net.ipv4.conf.all.send_redirects": "0", "net.ipv4.conf.default.send_redirects": "0", "net.ipv6.conf.all.accept_redirects": "0", "net.ipv6.conf.default.accept_redirects": "0"}
	if profile == "strict" {
		v["kernel.unprivileged_bpf_disabled"] = "1"
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
	old, oldErr := s.readSoftwareManifest("system-hardening")
	if install && oldErr == nil {
		return errors.New("系统基线加固已安装，请使用配置操作")
	}
	if !install && oldErr != nil {
		return errors.New("请先安装系统基线加固")
	}
	profile, _ := settings["profile"].(string)
	values := hardeningValues(profile)
	manifest := softwareManifest{ID: "system-hardening", Version: "1.0", Settings: settings, Previous: map[string]string{}, InstalledAt: core.Now()}
	if oldErr == nil {
		manifest.Previous = old.Previous
		manifest.InstalledAt = old.InstalledAt
	} else {
		for key := range values {
			value, e := s.sysctlValue(ctx, key)
			if e != nil {
				return fmt.Errorf("无法读取内核参数 %s: %w", key, e)
			}
			manifest.Previous[key] = value
		}
	}
	path := s.systemPath("/etc/sysctl.d/99-zz-panel-hardening.conf")
	legacyPath := s.systemPath("/etc/sysctl.d/90-panel-hardening.conf")
	if e := os.MkdirAll(filepath.Dir(path), 0755); e != nil {
		return e
	}
	backup, e := backupFile(path)
	if e != nil {
		return e
	}
	legacyBackup, e := backupFile(legacyPath)
	if e != nil {
		return e
	}
	if e = atomicWrite(path, []byte(renderSysctl(values)), 0644); e == nil {
		if legacyBackup.existed {
			e = os.Remove(legacyPath)
		}
	}
	if e == nil {
		_, e = s.Config.Run(ctx, "/usr/sbin/sysctl", "-p", path)
	}
	if e != nil {
		_ = restoreFiles([]fileBackup{backup, legacyBackup})
		for key, value := range manifest.Previous {
			_, _ = s.Config.Run(context.Background(), "/usr/sbin/sysctl", "-w", key+"="+value)
		}
		return e
	}
	for key, expected := range values {
		actual, er := s.sysctlValue(ctx, key)
		if er != nil || actual != expected {
			_ = restoreFiles([]fileBackup{backup, legacyBackup})
			return fmt.Errorf("内核参数 %s 实际值未生效", key)
		}
	}
	if e = s.writeSoftwareManifest(manifest); e != nil {
		return e
	}
	add("应用固定 sysctl 基线并逐项核对实际值")
	return nil
}
func (s *Service) uninstallHardening(ctx context.Context, add func(string)) error {
	manifest, e := s.readSoftwareManifest("system-hardening")
	if e != nil {
		return errors.New("系统基线加固未安装")
	}
	for _, path := range []string{s.systemPath("/etc/sysctl.d/99-zz-panel-hardening.conf"), s.systemPath("/etc/sysctl.d/90-panel-hardening.conf")} {
		if e = os.Remove(path); e != nil && !errors.Is(e, os.ErrNotExist) {
			return e
		}
	}
	for key, value := range manifest.Previous {
		if _, e = s.Config.Run(ctx, "/usr/sbin/sysctl", "-w", key+"="+value); e != nil {
			return fmt.Errorf("恢复内核参数 %s 失败: %w", key, e)
		}
	}
	if e = os.Remove(s.softwareManifestPath("system-hardening")); e != nil {
		return e
	}
	add("移除 sysctl 基线并恢复安装前的逐项实际值")
	return nil
}

func renderIntrusion(settings map[string]any) string {
	return fmt.Sprintf("# managed by panel intrusion-prevention 1.0\n[sshd]\nenabled = true\nbackend = systemd\nmaxretry = %d\nfindtime = %dm\nbantime = %dm\n", softwareInt(settings, "max_retry"), softwareInt(settings, "find_time_minutes"), softwareInt(settings, "ban_time_minutes"))
}

func (s *Service) waitFail2ban(ctx context.Context) error {
	var last error
	for attempt := 0; attempt < 10; attempt++ {
		if _, last = s.Config.Run(ctx, "/usr/bin/fail2ban-client", "status", "sshd"); last == nil {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(500 * time.Millisecond):
		}
	}
	return fmt.Errorf("Fail2ban SSHD Jail 未在 5 秒内就绪: %w", last)
}

func (s *Service) applyIntrusion(ctx context.Context, settings map[string]any, install bool, add func(string)) error {
	old, oldErr := s.readSoftwareManifest("intrusion-prevention")
	if install && oldErr == nil {
		return errors.New("SSH 防入侵已安装，请使用配置操作")
	}
	if !install && oldErr != nil {
		return errors.New("请先安装 SSH 防入侵")
	}
	if _, e := s.Config.Run(ctx, "/usr/bin/fail2ban-client", "--version"); e != nil {
		return errors.New("Debian Fail2ban 依赖不存在，请先修复面板基础依赖")
	}
	path := s.systemPath("/etc/fail2ban/jail.d/panel-intrusion.local")
	if e := os.MkdirAll(filepath.Dir(path), 0755); e != nil {
		return e
	}
	backup, e := backupFile(path)
	if e != nil {
		return e
	}
	if install && backup.existed {
		return errors.New("检测到未登记的同名 Fail2ban 配置，拒绝覆盖")
	}
	if e = atomicWrite(path, []byte(renderIntrusion(settings)), 0644); e == nil {
		_, e = s.Config.Run(ctx, "/usr/bin/fail2ban-client", "-t")
	}
	if e == nil {
		_, e = s.Config.Run(ctx, "/usr/bin/systemctl", "enable", "--now", "fail2ban")
	}
	if e == nil {
		_, e = s.Config.Run(ctx, "/usr/bin/systemctl", "restart", "fail2ban")
	}
	if e == nil {
		e = s.waitFail2ban(ctx)
	}
	if e != nil {
		_ = restoreFiles([]fileBackup{backup})
		_, _ = s.Config.Run(context.Background(), "/usr/bin/systemctl", "restart", "fail2ban")
		return e
	}
	manifest := softwareManifest{ID: "intrusion-prevention", Version: "1.0", Settings: settings, InstalledAt: core.Now()}
	if oldErr == nil {
		manifest.InstalledAt = old.InstalledAt
	}
	if e = s.writeSoftwareManifest(manifest); e != nil {
		return e
	}
	add("写入 SSHD Jail 并通过 fail2ban-client -t")
	add("启用并重启 Fail2ban，封禁状态由实际 Jail 读取")
	return nil
}
func (s *Service) uninstallIntrusion(ctx context.Context, add func(string)) error {
	if _, e := s.readSoftwareManifest("intrusion-prevention"); e != nil {
		return errors.New("SSH 防入侵未安装")
	}
	path := s.systemPath("/etc/fail2ban/jail.d/panel-intrusion.local")
	backup, e := backupFile(path)
	if e != nil {
		return e
	}
	if e = os.Remove(path); e != nil && !errors.Is(e, os.ErrNotExist) {
		return e
	}
	if _, e = s.Config.Run(ctx, "/usr/bin/fail2ban-client", "-t"); e == nil {
		_, e = s.Config.Run(ctx, "/usr/bin/systemctl", "restart", "fail2ban")
	}
	if e == nil {
		e = s.waitFail2ban(ctx)
	}
	if e != nil {
		_ = restoreFiles([]fileBackup{backup})
		return e
	}
	if e = os.Remove(s.softwareManifestPath("intrusion-prevention")); e != nil {
		return e
	}
	add("移除面板管理的 SSHD Jail；保留 Debian Fail2ban 依赖及其他 Jail")
	return nil
}

func (s *Service) softwareStatus(ctx context.Context, id string) core.SoftwareAppStatus {
	if _,ok:=core.FindAppModule(id);ok{return s.appModuleStatus(ctx,id)}
	out := core.SoftwareAppStatus{ID: id, Detail: "未安装"}
	manifest, e := s.readSoftwareManifest(id)
	if e != nil {
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
		_, e = s.Config.Run(ctx, s.Config.NginxBin, "-t", "-c", s.Config.NginxConf)
		out.Healthy = out.Enabled && e == nil
		if out.Healthy {
			out.Detail = "Nginx 规则已加载"
		} else {
			out.Detail = "WAF 配置缺失或 Nginx 校验失败"
		}
	case "system-hardening":
		out.Enabled = true
		out.Healthy = true
		profile, _ := manifest.Settings["profile"].(string)
		for key, expected := range hardeningValues(profile) {
			actual, er := s.sysctlValue(ctx, key)
			if er != nil || actual != expected {
				out.Healthy = false
				break
			}
		}
		if out.Healthy {
			out.Detail = "内核参数与已保存基线一致"
		} else {
			out.Detail = "检测到内核参数偏差"
		}
	case "intrusion-prevention":
		status, er := s.Config.Run(ctx, "/usr/bin/systemctl", "is-active", "fail2ban")
		out.Enabled = er == nil && strings.TrimSpace(status) == "active"
		_, er = s.Config.Run(ctx, "/usr/bin/fail2ban-client", "status", "sshd")
		out.Healthy = out.Enabled && er == nil
		if out.Healthy {
			out.Detail = "Fail2ban SSHD Jail 正在运行"
		} else {
			out.Detail = "Fail2ban 或 SSHD Jail 未正常运行"
		}
	}
	return out
}

func (s *Service) softwareRoutes(m *http.ServeMux) {
	m.HandleFunc("GET /v1/software/nginx-waf/events", func(w http.ResponseWriter, r *http.Request) {
		if _, err := s.readSoftwareManifest("nginx-waf"); err != nil {
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
		for _,d:=range core.AppModules(){ids=append(ids,d.ID)}
		out := make([]core.SoftwareAppStatus, 0, len(ids))
		for _, id := range ids {
			out = append(out, s.softwareStatus(r.Context(), id))
		}
		respond(w, 200, out)
	})
	m.HandleFunc("POST /v1/software/{id}/{action}", func(w http.ResponseWriter, r *http.Request) {
		var in struct {
			Settings map[string]any `json:"settings"`
		}
		if !readJSON(w, r, &in) {
			return
		}
		id, action := r.PathValue("id"), r.PathValue("action")
		_,moduleOK:=core.FindAppModule(id)
		if !moduleOK && id != "nginx-waf" && id != "system-hardening" && id != "intrusion-prevention" {
			respond(w, 404, map[string]string{"error": "软件不在受管目录中"})
			return
		}
		if action != "install" && action != "configure" && action != "uninstall" {
			respond(w, 400, map[string]string{"error": "软件操作无效"})
			return
		}
		result := core.ApplyResult{Steps: []core.Step{}}
		add := func(message string) {
			result.Steps = append(result.Steps, core.Step{Time: core.Now(), Message: message})
		}
		s.mu.Lock()
		defer s.mu.Unlock()
		var e error
		install := action == "install"
		if moduleOK {e=s.appModuleLifecycle(r.Context(),id,action,in.Settings,add)} else if action == "uninstall" {
			switch id {
			case "nginx-waf":
				e = s.uninstallWAF(r.Context(), add)
			case "system-hardening":
				e = s.uninstallHardening(r.Context(), add)
			case "intrusion-prevention":
				e = s.uninstallIntrusion(r.Context(), add)
			}
		} else {
			switch id {
			case "nginx-waf":
				e = s.applyWAF(r.Context(), in.Settings, install, add)
			case "system-hardening":
				e = s.applyHardening(r.Context(), in.Settings, install, add)
			case "intrusion-prevention":
				e = s.applyIntrusion(r.Context(), in.Settings, install, add)
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
		respond(w, 200, result)
	})
}
