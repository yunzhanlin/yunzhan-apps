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
	"regexp"
	"sort"
	"strings"
	"syscall"
	"time"
)

func (s *Service) apacheWAFSource() (string, map[string][]string, error) {
	if err := ordinary(s.Config.ApacheSiteConfig, false); err != nil {
		return "", nil, err
	}
	data, err := os.ReadFile(s.Config.ApacheSiteConfig)
	if err != nil || len(data) > 2<<20 {
		return "", nil, errors.New("Apache 配置不可读取或超过 2 MiB")
	}
	bindings, err := apacheWAFBindings(string(data))
	return string(data), bindings, err
}
func (s *Service) apacheWAFSettings(raw map[string]any, install bool) (core.WAFConfig, error) {
	cfg, err := core.DecodeApacheWAFConfig(raw)
	if err != nil {
		return cfg, err
	}
	var current struct {
		Settings map[string]any `json:"settings"`
	}
	err = moduleRead(filepath.Join(s.moduleDir("apache-waf"), "installed.json"), &current)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return cfg, errors.New("Apache WAF 安装记录损坏，未覆盖配置")
	}
	if err == nil {
		previous, err := core.DecodeApacheWAFConfig(current.Settings)
		if err != nil {
			return cfg, err
		}
		if len(raw) == 0 {
			cfg = previous
		} else if !install && cfg.Policy.Revision != previous.Policy.Revision {
			return cfg, errors.New("Apache WAF 配置已变化，请刷新后重新保存")
		}
	}
	return cfg, nil
}

func (s *Service) apacheWAFReplay(raw map[string]any) bool {
	cfg, err := core.DecodeApacheWAFConfig(raw)
	if err != nil || raw["policy"] == nil {
		return false
	}
	var current struct {
		Version  string         `json:"version"`
		Settings map[string]any `json:"settings"`
	}
	if moduleRead(filepath.Join(s.moduleDir("apache-waf"), "installed.json"), &current) != nil || current.Version != core.ApacheWAFVersion {
		return false
	}
	wanted, err := core.DecodeApacheWAFConfig(current.Settings)
	if err != nil || wanted.Policy.Revision != cfg.Policy.Revision+1 {
		return false
	}
	cfg.Policy.Revision = wanted.Policy.Revision
	a, _ := json.Marshal(cfg)
	b, _ := json.Marshal(wanted)
	if !bytes.Equal(a, b) {
		return false
	}
	_, bindings, err := s.apacheWAFSource()
	if err != nil {
		return false
	}
	rules, err := renderApacheWAF(wanted, bindings)
	if err != nil {
		return false
	}
	actual, err := os.ReadFile(filepath.Join(s.moduleDir("apache-waf"), "rules.conf"))
	return err == nil && string(actual) == rules
}

func (s *Service) applyApacheWAF(ctx context.Context, raw map[string]any, install bool, add func(string)) error {
	if s.apacheWAFReplay(raw) {
		add("Apache WAF 配置和修订号已提交，核对文件后确认幂等重放")
		return nil
	}
	cfg, err := s.apacheWAFSettings(raw, install)
	if err != nil {
		return err
	}
	source, bindings, err := s.apacheWAFSource()
	if err != nil {
		return err
	}
	if len(bindings) == 0 {
		return errors.New("请先创建并运行一个 Apache 网站")
	}
	cfg.Policy.Revision++
	rules, err := renderApacheWAF(cfg, bindings)
	if err != nil {
		return err
	}
	release, err := apacheRelease()
	if err != nil {
		return err
	}
	dir := s.moduleDir("apache-waf")
	paths := []string{s.Config.ApacheSiteConfig, filepath.Join(dir, "rules.conf"), filepath.Join(dir, "installed.json")}
	backups := []fileBackup{}
	for _, path := range paths {
		backup, err := backupFile(path)
		if err != nil {
			return err
		}
		backups = append(backups, backup)
	}
	base := filepath.Join(dir, "config-backups")
	if err = os.MkdirAll(base, 0700); err != nil {
		return err
	}
	if err = ordinary(base, true); err != nil {
		return err
	}
	entries, err := os.ReadDir(base)
	if err != nil {
		return err
	}
	if len(entries) >= 100 {
		return errors.New("Apache WAF 配置备份达到 100 份，请先归档备份再保存")
	}
	backupDir := filepath.Join(base, core.ID())
	if err = os.Mkdir(backupDir, 0700); err != nil {
		return err
	}
	index := []map[string]any{}
	for i, backup := range backups {
		name := fmt.Sprintf("%d.conf", i)
		if backup.existed {
			if err = atomicWrite(filepath.Join(backupDir, name), backup.data, 0600); err != nil {
				return err
			}
		}
		index = append(index, map[string]any{"source": backup.path, "file": name, "existed": backup.existed, "mode": backup.mode})
	}
	if err = moduleWrite(filepath.Join(backupDir, "index.json"), map[string]any{"created_at": core.Now(), "files": index}); err != nil {
		return err
	}
	add("已保存可恢复的 Apache 配置、规则与版本记录备份")
	rollback := func(cause error) error {
		if err := restoreFiles(backups); err != nil {
			return fmt.Errorf("Apache WAF 操作失败且配置回滚失败，备份保存在 %s：%w", backupDir, err)
		}
		rollbackCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if _, err := s.Config.Run(rollbackCtx, release.CLI(), "-t", "-f", s.Config.ApacheSiteConfig); err != nil {
			return errors.New("Apache WAF 旧配置已还原，但原生校验失败，请核对备份")
		}
		if _, err := s.Config.Run(rollbackCtx, "/usr/bin/systemctl", "reload", "panel-apache"); err != nil {
			return errors.New("Apache WAF 旧配置已还原，但服务重载失败，请核对服务")
		}
		return cause
	}
	updated := regexp.MustCompile(`(?ms)^<VirtualHost[^>]+>.*?</VirtualHost>`).ReplaceAllStringFunc(source, func(block string) string {
		id := regexp.MustCompile(`panel-([a-f0-9]{32})\.access\.log combined`).FindStringSubmatch(block)
		if len(id) == 2 && !strings.Contains(block, "PANEL_AW_SITE="+id[1]) {
			block = strings.Replace(block, "\n", "\n  SetEnvIfExpr \"true\" PANEL_AW_SITE="+id[1]+"\n", 1)
		}
		if strings.Contains(block, apacheWAFInclude) {
			return block
		}
		return strings.Replace(block, "\n", "\n  "+apacheWAFInclude, 1)
	})
	if err = atomicWrite(paths[0], []byte(updated), 0644); err != nil {
		return rollback(err)
	}
	if err = atomicWrite(paths[1], []byte(rules), 0644); err != nil {
		return rollback(err)
	}
	if _, err = s.Config.Run(ctx, release.CLI(), "-t", "-f", s.Config.ApacheSiteConfig); err != nil {
		return rollback(err)
	}
	if _, err = s.Config.Run(ctx, "/usr/bin/systemctl", "reload", "panel-apache"); err != nil {
		return rollback(err)
	}
	keys := make([]string, 0, len(bindings))
	for id := range bindings {
		keys = append(keys, id)
	}
	sort.Strings(keys)
	client := &http.Client{Timeout: 2 * time.Second, Transport: &http.Transport{Proxy: nil}, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	defer client.CloseIdleConnections()
	verified := false
	for i := 0; i < 8; i++ {
		req, _ := http.NewRequestWithContext(ctx, "HEAD", "http://127.0.0.1:19080/__yunzhan_waf_probe", nil)
		req.Host = bindings[keys[0]][0]
		response, err := client.Do(req)
		if err == nil {
			verified = response.Header.Get("X-Panel-Apache-WAF") == apacheWAFProbe(cfg)
			response.Body.Close()
		}
		if verified {
			break
		}
		select {
		case <-ctx.Done():
			return rollback(ctx.Err())
		case <-time.After(250 * time.Millisecond):
		}
	}
	if !verified {
		return rollback(errors.New("Apache 重载后未读到新配置指纹，已恢复旧配置"))
	}
	installedAt := core.Now()
	var previous map[string]any
	if moduleRead(paths[2], &previous) == nil {
		if at, ok := previous["installed_at"].(string); ok {
			installedAt = at
		}
	}
	if err = moduleWrite(paths[2], map[string]any{"id": "apache-waf", "version": core.ApacheWAFVersion, "settings": core.WAFSettings(cfg), "installed_at": installedAt, "updated_at": core.Now()}); err != nil {
		return rollback(err)
	}
	add("Apache 原生校验、平滑重载和回环配置指纹核对通过；保留网站、日志和配置历史")
	return nil
}

func (s *Service) readApacheWAFEvents() (core.WAFEventsPage, error) {
	page := core.WAFEventsPage{Events: []core.WAFEvent{}}
	f, err := os.OpenFile(s.systemPath("/var/log/apache2/panel-waf.events.log"), os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if errors.Is(err, os.ErrNotExist) {
		return page, nil
	}
	if err != nil {
		return page, err
	}
	defer f.Close()
	stat, err := f.Stat()
	if err != nil || !stat.Mode().IsRegular() {
		return page, errors.New("Apache 防护日志不是普通文件")
	}
	start := max(int64(0), stat.Size()-(4<<20))
	if _, err = f.Seek(start, io.SeekStart); err != nil {
		return page, err
	}
	data, err := io.ReadAll(io.LimitReader(f, 4<<20))
	if err != nil {
		return page, err
	}
	lines := bytes.Split(data, []byte{'\n'})
	if start > 0 {
		page.HasMore = true
		lines = lines[1:]
	}
	for i := len(lines) - 1; i >= 0; i-- {
		line := bytes.TrimSpace(lines[i])
		if len(line) == 0 {
			continue
		}
		if len(line) > 4096 {
			page.HasMore = true
			continue
		}
		var event struct {
			Epoch int64 `json:"epoch"`
			core.WAFEvent
		}
		// mod_log_config's \xHH escapes are converted to valid JSON escapes.
		line = regexp.MustCompile(`\\x([0-9a-fA-F]{2})`).ReplaceAll(line, []byte(`\u00$1`))
		if json.Unmarshal(line, &event) != nil || event.Epoch <= 0 || !core.ValidID(event.SiteID) || event.Reason == "" || event.Action != "block" && event.Action != "observe" {
			page.HasMore = true
			continue
		}
		event.Time = time.Unix(event.Epoch, 0).UTC().Format(time.RFC3339)
		page.Events = append(page.Events, event.WAFEvent)
		if len(page.Events) == 5000 {
			page.HasMore = true
			break
		}
	}
	return page, nil
}

func (s *Service) apacheWAFWorkspaceRoutes(m *http.ServeMux) {
	m.HandleFunc("GET /v1/software/apache-waf/config", func(w http.ResponseWriter, r *http.Request) {
		s.mu.Lock()
		defer s.mu.Unlock()
		cfg, err := s.apacheWAFSettings(nil, true)
		if err != nil {
			respond(w, 409, map[string]string{"error": err.Error()})
			return
		}
		respond(w, 200, map[string]any{"settings": cfg, "defaults": core.DefaultApacheWAFConfig(), "status": s.appModuleStatus(r.Context(), "apache-waf"), "implementation_version": core.ApacheWAFVersion})
	})
	m.HandleFunc("POST /v1/software/apache-waf/preview", func(w http.ResponseWriter, r *http.Request) {
		var raw map[string]any
		if !readJSON(w, r, &raw) {
			return
		}
		s.mu.Lock()
		defer s.mu.Unlock()
		cfg, err := s.apacheWAFSettings(raw, !s.moduleInstalled("apache-waf"))
		if err == nil {
			var bindings map[string][]string
			_, bindings, err = s.apacheWAFSource()
			if err == nil {
				var rules string
				rules, err = renderApacheWAF(cfg, bindings)
				if err == nil {
					respond(w, 200, map[string]any{"settings": cfg, "http_config": "# Apache 元数据防护；不包含 CC / POST 正文解析", "server_config": rules})
					return
				}
			}
		}
		respond(w, 409, map[string]string{"error": err.Error()})
	})
	m.HandleFunc("GET /v1/software/apache-waf/report", func(w http.ResponseWriter, r *http.Request) {
		events, err := s.readApacheWAFEvents()
		if err == nil {
			var report core.WAFReport
			report, err = core.BuildWAFReport(events, r.URL.Query(), time.Now())
			if err == nil {
				respond(w, 200, report)
				return
			}
		}
		respond(w, 409, map[string]string{"error": err.Error()})
	})
}
