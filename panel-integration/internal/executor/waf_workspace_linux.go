//go:build linux

package executor

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"local/panel/internal/core"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// A durable worker may lose the successful reply after files and manifest were
// committed. A matching next revision is acknowledged only if both generated
// rule files still match exactly; different stale drafts continue to fail.
func (s *Service) wafReplayMatches(raw map[string]any) bool {
	if _, advanced := raw["policy"]; !advanced {
		return false
	}
	wanted, e := core.DecodeWAFConfig(raw)
	if e != nil {
		return false
	}
	manifest, e := s.readSoftwareManifest("nginx-waf")
	if e != nil || manifest.Version != core.WAFVersion {
		return false
	}
	current, e := core.DecodeWAFConfig(manifest.Settings)
	if e != nil || current.Policy.Revision != wanted.Policy.Revision+1 {
		return false
	}
	// Omitted independent fields mean preserve, including after a committed
	// request loses its reply. Only an explicit object can change that policy.
	if _, present := raw["body"]; !present {
		wanted.Body = current.Body
	}
	if _, present := raw["trusted_proxy"]; !present {
		wanted.TrustedProxy = current.TrustedProxy
	}
	if _, present := raw["body_log_rotation"]; !present {
		wanted.BodyLogRotation = current.BodyLogRotation
	}
	if _, present := raw["body_log_retention"]; !present {
		wanted.BodyLogRetention = current.BodyLogRetention
	}
	wanted.Policy.Revision = current.Policy.Revision
	a, _ := json.Marshal(wanted)
	b, _ := json.Marshal(current)
	if !bytes.Equal(a, b) {
		return false
	}
	h, v := wafFiles(s)
	expectedH, expectedV := renderWAFPolicy(current)
	actualH, e := os.ReadFile(h)
	if e != nil || string(actualH) != expectedH {
		return false
	}
	actualV, e := os.ReadFile(v)
	if e != nil || string(actualV) != expectedV {
		return false
	}
	plan, e := s.planWAFConfiguration(current, false)
	return e == nil && len(plan) == 0
}

func (s *Service) prepareWAFSettings(raw map[string]any, install bool) (core.WAFConfig, error) {
	cfg, e := core.DecodeWAFConfig(raw)
	if e != nil {
		return cfg, e
	}
	if cfg.BodyLogRetention != nil {
		if _, advanced := raw["policy"]; !advanced {
			return cfg, errors.New("自动快照清理需要完整 policy 和当前修订号")
		}
		if core.WAFVersion != "2.5.0" {
			return cfg, errors.New("自动快照清理尚未在此应用版本发布，不能用面板升级代替应用更新")
		}
	}
	if _, body := raw["body"]; body {
		if _, advanced := raw["policy"]; !advanced {
			return cfg, errors.New("请求体策略必须包含完整 policy 和当前修订号")
		}
	}
	if _, proxy := raw["trusted_proxy"]; proxy {
		if _, advanced := raw["policy"]; !advanced {
			return cfg, errors.New("可信代理策略必须包含完整 policy 和当前修订号")
		}
	}
	if _, rotation := raw["body_log_rotation"]; rotation {
		if _, advanced := raw["policy"]; !advanced {
			return cfg, errors.New("自动轮转策略必须包含完整 policy 和当前修订号")
		}
	}
	old, oldErr := s.readSoftwareManifest("nginx-waf")
	if !install && oldErr == nil {
		previous, e := core.DecodeWAFConfig(old.Settings)
		if e != nil {
			return cfg, e
		}
		if _, present := raw["body"]; !present {
			cfg.Body = previous.Body
		}
		if _, present := raw["trusted_proxy"]; !present {
			cfg.TrustedProxy = previous.TrustedProxy
		}
		if _, present := raw["body_log_rotation"]; !present {
			cfg.BodyLogRotation = previous.BodyLogRotation
		}
		if _, present := raw["body_log_retention"]; !present {
			cfg.BodyLogRetention = previous.BodyLogRetention
		}
		if cfg.BodyLogRetention != nil && old.Version != "2.5.0" {
			return cfg, errors.New("自动快照清理需要先通过应用商店升级 Nginx WAF")
		}
		if cfg.BodyLogRotation != nil && old.Version != core.WAFVersion {
			return cfg, errors.New("自动轮转策略需要先升级已安装的 Nginx WAF 应用")
		}
		if cfg.TrustedProxy != nil && old.Version != core.WAFVersion {
			return cfg, errors.New("可信代理策略需要先通过应用商店升级 Nginx WAF；不能用面板版本代替已安装应用版本")
		}
		if _, advanced := raw["policy"]; !advanced {
			// Older API clients can still adjust their two supported fields, but
			// cannot erase independently configured policies, lists or rules.
			profile, rate := cfg.Profile, cfg.Rate
			cfg = previous
			cfg.Profile = profile
			cfg.Rate = rate
		} else if cfg.Policy.Revision != previous.Policy.Revision {
			return cfg, errors.New("WAF 配置已变化，请刷新后重新预览和保存")
		}
	}
	if e := core.ValidateWAFBodyLogRotationSource(cfg); e != nil {
		return cfg, e
	}
	for _, id := range core.WAFScopedSites(cfg) {
		path := filepath.Join(s.Config.ConfDir, id+".conf")
		if e := ordinary(path, false); e != nil {
			return cfg, errors.New("WAF 站点配置不可读取或路径类型异常")
		}
		b, e := os.ReadFile(path)
		if e != nil || !strings.HasPrefix(string(b), "# managed by panel; site="+id) {
			return cfg, errors.New("WAF 策略仅允许已存在的受管站点")
		}
	}
	return cfg, nil
}

// Persist recoverable configuration evidence before the first write. Never
// silently delete old snapshots; the bounded quota fails closed instead.
func (s *Service) backupWAFConfiguration() (string, error) {
	base := filepath.Join(s.Config.SecurityDir, "waf-backups")
	if e := os.MkdirAll(base, 0700); e != nil {
		return "", e
	}
	if e := ordinary(base, true); e != nil {
		return "", e
	}
	entries, e := os.ReadDir(base)
	if e != nil {
		return "", e
	}
	if len(entries) >= 100 {
		return "", errors.New("WAF 配置备份已达 100 份，请先归档管理备份再应用")
	}
	paths := []string{s.Config.NginxConf, s.softwareManifestPath("nginx-waf")}
	h, v := wafFiles(s)
	paths = append(paths, h, v)
	paths = append(paths, s.systemPath("/etc/panel/waf/http.d/20-panel-native-waf.conf"))
	if xs, e := os.ReadDir(s.systemPath("/etc/panel/waf/body.d")); e == nil {
		if len(xs) > 64 {
			return "", errors.New("请求体规则超过 64 条，拒绝不完整备份")
		}
		for _, x := range xs {
			if !core.ValidID(strings.TrimSuffix(x.Name(), ".conf")) || !strings.HasSuffix(x.Name(), ".conf") {
				return "", errors.New("请求体目录存在未知条目，未开始修改")
			}
			paths = append(paths, s.systemPath("/etc/panel/waf/body.d/"+x.Name()))
		}
	} else if !errors.Is(e, os.ErrNotExist) {
		return "", e
	}
	if xs, e := os.ReadDir(s.Config.ConfDir); e == nil {
		for _, x := range xs {
			if !x.IsDir() && strings.HasSuffix(x.Name(), ".conf") {
				paths = append(paths, filepath.Join(s.Config.ConfDir, x.Name()))
			}
		}
	}
	backups := []fileBackup{}
	total := 0
	for _, path := range paths {
		if st, err := os.Lstat(path); err == nil && st.Size() > int64((8<<20)-total) {
			return "", errors.New("WAF 配置备份超过 8 MiB，未开始修改")
		}
		b, e := backupFile(path)
		if e != nil {
			return "", e
		}
		total += len(b.data)
		if total > 8<<20 {
			return "", errors.New("WAF 配置备份超过 8 MiB，未开始修改")
		}
		backups = append(backups, b)
	}
	id := core.ID()
	dir := filepath.Join(base, id)
	if e = os.Mkdir(dir, 0700); e != nil {
		return "", e
	}
	index := []map[string]any{}
	for i, b := range backups {
		file := fmt.Sprintf("%03d.conf", i)
		if b.existed {
			if e = atomicWrite(filepath.Join(dir, file), b.data, 0600); e != nil {
				return "", e
			}
		}
		index = append(index, map[string]any{"source": b.path, "file": file, "existed": b.existed, "mode": b.mode, "owner": b.owner, "sha256": core.Hash(string(b.data))})
	}
	if e = moduleWrite(filepath.Join(dir, "index.json"), map[string]any{"created_at": core.Now(), "files": index}); e != nil {
		return "", e
	}
	return dir, nil
}

func (s *Service) wafWorkspaceRoutes(m *http.ServeMux) {
	s.wafEngineRoutes(m)
	s.wafBodyReportRoutes(m)
	m.HandleFunc("GET /v1/software/nginx-waf/config", func(w http.ResponseWriter, r *http.Request) {
		s.mu.Lock()
		defer s.mu.Unlock()
		v := core.DefaultWAFConfig()
		manifest, e := s.readSoftwareManifest("nginx-waf")
		if e == nil {
			v, e = core.DecodeWAFConfig(manifest.Settings)
			if e != nil {
				respond(w, 409, map[string]string{"error": e.Error()})
				return
			}
		}
		respond(w, 200, map[string]any{"settings": v, "defaults": core.DefaultWAFConfig(), "status": s.softwareStatus(r.Context(), "nginx-waf"), "installed_at": manifest.InstalledAt, "implementation_version": core.WAFVersion})
	})
	m.HandleFunc("POST /v1/software/nginx-waf/preview", func(w http.ResponseWriter, r *http.Request) {
		var raw map[string]any
		if !readJSON(w, r, &raw) {
			return
		}
		s.mu.Lock()
		defer s.mu.Unlock()
		_, e := s.readSoftwareManifest("nginx-waf")
		v, e := s.prepareWAFSettings(raw, e != nil)
		if e != nil {
			respond(w, 409, map[string]string{"error": e.Error()})
			return
		}
		h, b := renderWAFPolicy(v)
		if _, err := os.Lstat(s.wafPendingPath()); !errors.Is(err, os.ErrNotExist) {
			respond(w, 409, map[string]string{"error": "存在未完成防火墙事务，请先恢复再预览新配置"})
			return
		}
		if err := s.verifyWAFBodyEngine(v); err != nil {
			respond(w, 409, map[string]string{"error": err.Error()})
			return
		}
		if v.TrustedProxy != nil && v.TrustedProxy.Enabled {
			nginx, err := s.nginxBinary()
			if err == nil {
				err = s.verifyWAFTrustedProxy(r.Context(), v, nginx)
			}
			if err != nil {
				respond(w, 409, map[string]string{"error": err.Error()})
				return
			}
		}
		plan, err := s.planWAFConfiguration(v, false)
		if err != nil {
			respond(w, 409, map[string]string{"error": err.Error()})
			return
		}
		changes := []map[string]any{}
		bodyRules := []map[string]string{}
		for _, change := range plan {
			changes = append(changes, map[string]any{"path": change.Path, "action": map[bool]string{true: "write", false: "remove"}[change.NextExists], "previous_sha256": core.Hash(string(change.OldData)), "next_sha256": core.Hash(string(change.NextData))})
			if filepath.Dir(change.Path) == s.systemPath("/etc/panel/waf/body.d") && change.NextExists {
				bodyRules = append(bodyRules, map[string]string{"site_id": strings.TrimSuffix(filepath.Base(change.Path), ".conf"), "configuration": string(change.NextData)})
			}
		}
		respond(w, 200, map[string]any{"http_config": h, "server_config": b, "settings": v, "changes": changes, "body_rules": bodyRules, "read_only": true, "body_activation_explicit": true})
	})
	m.HandleFunc("GET /v1/software/nginx-waf/report", func(w http.ResponseWriter, r *http.Request) {
		if _, e := s.readSoftwareManifest("nginx-waf"); e != nil {
			respond(w, 409, map[string]string{"error": "请先安装 Nginx 防火墙"})
			return
		}
		page, e := s.readWAFEvents(4<<20, 5000)
		if e != nil {
			respond(w, 503, map[string]string{"error": e.Error()})
			return
		}
		out, e := core.BuildWAFReport(page, r.URL.Query(), time.Now())
		if e != nil {
			respond(w, 400, map[string]string{"error": e.Error()})
			return
		}
		respond(w, 200, out)
	})
}
