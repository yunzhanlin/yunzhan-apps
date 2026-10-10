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
	"strings"
	"syscall"
	"time"
)

func (s *Service) apacheWAFSource() (string, map[string][]string, error) {
	data, err := apacheWAFReadStableFile(s.Config.ApacheSiteConfig, 2<<20)
	if err != nil {
		return "", nil, errors.New("Apache 配置不可读取或超过 2 MiB")
	}
	bindings, err := apacheWAFBindings(string(data))
	return string(data), bindings, err
}
func (s *Service) apacheWAFSettings(raw map[string]any, install bool) (core.WAFConfig, error) {
	return s.apacheWAFSettingsForApply(raw, install, false)
}

// A known 2.1 installation must remain readable while the signed app-store
// update is pending. This only decodes its retained settings: it performs no
// write, revision increase, reload, version promotion, or healthy-status claim.
// Preview and ordinary configure keep their separate legacy write refusal.
func (s *Service) apacheWAFReadSettings() (core.WAFConfig, error) {
	return s.apacheWAFSettingsForApply(nil, true, true)
}
func (s *Service) apacheWAFSettingsForApply(raw map[string]any, install, upgrading bool) (core.WAFConfig, error) {
	cfg, err := core.DecodeApacheWAFConfig(raw)
	if err != nil {
		return cfg, err
	}
	var current struct {
		Version  string         `json:"version"`
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
		} else {
			if _, present := raw["trusted_proxy"]; !present {
				cfg.TrustedProxy = previous.TrustedProxy
			}
			if _, advanced := raw["policy"]; !advanced {
				if _, explicit := raw["trusted_proxy"]; explicit {
					return cfg, errors.New("Apache 可信代理策略需要完整 policy 和当前修订号")
				}
				profile, rate := cfg.Profile, cfg.Rate
				cfg = previous
				cfg.Profile, cfg.Rate = profile, rate
			} else if !install && cfg.Policy.Revision != previous.Policy.Revision {
				return cfg, errors.New("Apache WAF 配置已变化，请刷新后重新保存")
			}
		}
		if cfg.TrustedProxy != nil && current.Version != core.ApacheWAFVersion && !(upgrading && (current.Version == "2.1.0" || current.Version == "2.2.0")) {
			return cfg, errors.New("可信代理策略需要先通过应用商店升级 Apache WAF，不以面板版本冒充应用已升级")
		}
	}
	if _, explicit := raw["trusted_proxy"]; explicit && raw["policy"] == nil {
		return cfg, errors.New("Apache 可信代理策略需要完整 policy 和当前修订号")
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
	if _, present := raw["trusted_proxy"]; !present {
		cfg.TrustedProxy = wanted.TrustedProxy
	}
	cfg.Policy.Revision = wanted.Policy.Revision
	a, _ := json.Marshal(cfg)
	b, _ := json.Marshal(wanted)
	if !bytes.Equal(a, b) {
		return false
	}
	source, bindings, err := s.apacheWAFSource()
	if err != nil {
		return false
	}
	release, err := apacheRelease()
	if err != nil {
		return false
	}
	prepared, err := prepareApacheWAFTrustedProxySource(source, wanted.TrustedProxy, filepath.Join(release.Prefix(), "modules/mod_remoteip.so"))
	if err != nil || prepared != source {
		return false
	}
	if wanted.TrustedProxy != nil && wanted.TrustedProxy.Enabled && verifyApacheWAFRemoteIPModule(filepath.Join(release.Prefix(), "modules/mod_remoteip.so")) != nil {
		return false
	}
	rules, err := renderApacheWAF(wanted, bindings)
	if err != nil {
		return false
	}
	actual, err := apacheWAFReadStableFile(filepath.Join(s.moduleDir("apache-waf"), "rules.conf"), 1<<20)
	return err == nil && string(actual) == rules
}

// Identical persisted bytes do not prove that the live daemon has loaded them.
// A lost-ack retry may only succeed after the same read-only integrity check as
// a healthy application. Never reload or repair files to make a replay succeed.
func (s *Service) confirmApacheWAFReplay(ctx context.Context, raw map[string]any) (bool, error) {
	if !s.apacheWAFReplay(raw) {
		return false, nil
	}
	var current struct {
		Version  string         `json:"version"`
		Settings map[string]any `json:"settings"`
	}
	if err := moduleRead(filepath.Join(s.moduleDir("apache-waf"), "installed.json"), &current); err != nil {
		return true, fmt.Errorf("Apache WAF 重放无法核实安装记录: %w", err)
	}
	if err := s.verifyApacheWAFHealth(ctx, current.Version, current.Settings); err != nil {
		return true, fmt.Errorf("Apache WAF 重放未确认实际防护，未重新写入或重载: %w", err)
	}
	return true, nil
}

func (s *Service) applyApacheWAF(ctx context.Context, raw map[string]any, install, upgrading bool, add func(string)) error {
	txs := s.apacheWAFTransactionService()
	lock, err := txs.lockWAFConfiguration()
	if err != nil {
		return err
	}
	defer lock.Close()
	if err = txs.recoverApacheWAFBeforeMutation(ctx); err != nil {
		return err
	}
	if replay, err := s.confirmApacheWAFReplay(ctx, raw); replay || err != nil {
		if err != nil {
			return err
		}
		add("Apache WAF 配置和修订号已提交，全部受管站点挂载、规则及实际加载指纹核对后确认幂等重放")
		return nil
	}
	cfg, err := s.apacheWAFSettingsForApply(raw, install, upgrading)
	if err != nil {
		return err
	}
	if !install && !upgrading {
		var installed struct {
			Version string `json:"version"`
		}
		if err := moduleRead(filepath.Join(s.moduleDir("apache-waf"), "installed.json"), &installed); err != nil || installed.Version != core.ApacheWAFVersion {
			return errors.New("先通过应用商店执行 Apache WAF 签名升级；保存配置不能隐式切换应用版本")
		}
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
	modulePath := filepath.Join(release.Prefix(), "modules/mod_remoteip.so")
	source, err = prepareApacheWAFTrustedProxySource(source, cfg.TrustedProxy, modulePath)
	if err != nil {
		return err
	}
	if cfg.TrustedProxy != nil && cfg.TrustedProxy.Enabled {
		if err = verifyApacheWAFRemoteIPModule(modulePath); err != nil {
			return err
		}
	}
	paths := txs.apacheWAFConfigurationPaths()
	backups := []fileBackup{}
	for _, path := range paths {
		backup, err := txs.apacheWAFStableBackup(path)
		if err != nil {
			return err
		}
		backups = append(backups, backup)
	}
	installedAt := core.Now()
	if backups[2].existed {
		var previous struct {
			ID          string         `json:"id"`
			Version     string         `json:"version"`
			InstalledAt string         `json:"installed_at"`
			Settings    map[string]any `json:"settings"`
		}
		if err = json.Unmarshal(backups[2].data, &previous); err != nil || previous.ID != "apache-waf" {
			return errors.New("Apache 安装记录身份异常，未开始修改")
		}
		if previous.Version != core.ApacheWAFVersion && !upgrading {
			return errors.New("先通过应用商店执行 Apache WAF 签名升级")
		}
		if previous.Version != core.ApacheWAFVersion {
			if err = s.verifyApacheWAFLegacyUpgrade(ctx, core.SoftwareAppStatus{Installed: true, Version: previous.Version, Settings: previous.Settings}); err != nil {
				return err
			}
		} else if err = s.verifyApacheWAFHealth(ctx, previous.Version, previous.Settings); err != nil {
			return err
		}
		if previous.InstalledAt != "" {
			installedAt = previous.InstalledAt
		}
	}
	// The owner-aware journal below already persists all three complete old
	// and next files before mutation. Keep old config-backups untouched, but
	// do not create a second unmaintainable backup namespace in version 2.3.
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
	manifest := map[string]any{"id": "apache-waf", "version": core.ApacheWAFVersion, "settings": core.WAFSettings(cfg), "installed_at": installedAt, "updated_at": core.Now()}
	plan, err := txs.planApacheWAFTransaction(backups, updated, rules, manifest, false)
	if err != nil {
		return err
	}
	if err = txs.applyApacheWAFPlanned(ctx, plan, func(bounded context.Context) error {
		domain, e := apacheWAFConfigurationFilesMatch(updated, cfg, modulePath, paths[1])
		if e != nil {
			return e
		}
		return apacheWAFWaitLoadedVersion(bounded, cfg, domain, core.ApacheWAFVersion)
	}, add); err != nil {
		return err
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
	s.apacheWAFHistoryRoutes(m)
	m.HandleFunc("GET /v1/software/apache-waf/config", func(w http.ResponseWriter, r *http.Request) {
		s.mu.Lock()
		defer s.mu.Unlock()
		cfg, err := s.apacheWAFReadSettings()
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
					if release, releaseErr := apacheRelease(); releaseErr == nil {
						modulePath := filepath.Join(release.Prefix(), "modules/mod_remoteip.so")
						source, _, sourceErr := s.apacheWAFSource()
						prepared, prepareErr := prepareApacheWAFTrustedProxySource(source, cfg.TrustedProxy, modulePath)
						if sourceErr == nil && prepareErr == nil && cfg.TrustedProxy != nil && cfg.TrustedProxy.Enabled {
							prepareErr = verifyApacheWAFRemoteIPModule(modulePath)
						}
						if sourceErr != nil {
							err = sourceErr
						} else if prepareErr != nil {
							err = prepareErr
						} else {
							respond(w, 200, map[string]any{"settings": cfg, "http_config": prepared, "server_config": rules})
							return
						}
					} else {
						err = releaseErr
					}
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

// The library and each containing directory must be root-owned, non-symlinked
// and not writable by another user. Native -t still checks ABI compatibility;
// a file merely existing must not be reported as an available safe module.
func verifyApacheWAFRemoteIPModule(path string) error {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return errors.New("Apache 模块路径须为固定规范绝对路径")
	}
	for current := path; ; current = filepath.Dir(current) {
		st, err := os.Lstat(current)
		if err != nil || st.Mode()&os.ModeSymlink != 0 || st.Mode().Perm()&0022 != 0 || st.Mode()&(os.ModeSetuid|os.ModeSetgid) != 0 {
			return errors.New("Apache remoteip 模块缺失或路径权限异常；不会自动重编译或启用代理信任")
		}
		owner, ok := st.Sys().(*syscall.Stat_t)
		if !ok || owner.Uid != 0 || current == path && (!st.Mode().IsRegular() || owner.Nlink != 1) || current != path && !st.IsDir() {
			return errors.New("Apache remoteip 模块和目录须由 root 独占管理，拒绝异常类型和硬链接")
		}
		if current == "/" {
			return nil
		}
	}
}
