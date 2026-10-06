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
	return e == nil && string(actualV) == expectedV
}

func (s *Service) prepareWAFSettings(raw map[string]any, install bool) (core.WAFConfig, error) {
	cfg, e := core.DecodeWAFConfig(raw)
	if e != nil {
		return cfg, e
	}
	old, oldErr := s.readSoftwareManifest("nginx-waf")
	if !install && oldErr == nil {
		previous, e := core.DecodeWAFConfig(old.Settings)
		if e != nil {
			return cfg, e
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
		index = append(index, map[string]any{"source": b.path, "file": file, "existed": b.existed, "mode": b.mode})
	}
	if e = moduleWrite(filepath.Join(dir, "index.json"), map[string]any{"created_at": core.Now(), "files": index}); e != nil {
		return "", e
	}
	return dir, nil
}

func (s *Service) wafWorkspaceRoutes(m *http.ServeMux) {
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
		respond(w, 200, map[string]any{"http_config": h, "server_config": b, "settings": v})
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
