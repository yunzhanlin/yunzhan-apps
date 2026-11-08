//go:build linux

package executor

import (
	"context"
	"encoding/json"
	"errors"
	"local/panel/internal/core"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"syscall"
)

// Only the original installed version is rendered. A difference report is not
// a repair token, migration grant or evidence that Nginx loaded any rules.
func (s *Service) inspectInstalledWAFConfiguration(ctx context.Context) (core.WAFConfigurationInspection, error) {
	out := core.WAFConfigurationInspection{Format: 1, ReadOnly: true, Differences: []core.WAFConfigurationDifference{}}
	lock, info, err := s.openExistingWAFBackupLock(ctx, syscall.LOCK_SH)
	if err != nil {
		return out, err
	}
	defer lock.Close()
	if err = wafBackupLockUnchanged(lock, filepath.Join(s.Config.SecurityDir, "waf-configuration.lock"), info); err != nil {
		return out, err
	}
	if _, err = os.Lstat(s.wafPendingPath()); !errors.Is(err, os.ErrNotExist) {
		return out, errors.New("存在未完成 WAF 事务，未生成配置差异；请核对原事务")
	}
	manifest, err := s.readSoftwareManifest("nginx-waf")
	if err != nil {
		return out, errors.New("已安装 WAF 原清单不可核对；未创建或修改文件")
	}
	if !core.WAFInspectionVersionSupported(manifest.Version) {
		return out, errors.New("已安装 WAF 版本没有严格的原版渲染器")
	}
	cfg, err := core.DecodeWAFConfig(manifest.Settings)
	if err != nil || !wafHistoricalVersionValid(manifest.Version, cfg) {
		return out, errors.New("已安装 WAF 原策略或版本无法严格核对")
	}
	if err = s.wafLegacyMigrationReferences(cfg); err != nil {
		return out, err
	}
	// Two complete bounded plans must agree under the same existing lock. Any
	// cooperative mutation is excluded; concurrent external drift fails closed.
	changes, err := s.planWAFConfigurationVersion(cfg, false, manifest.Version)
	if err != nil {
		return out, err
	}
	again, err := s.planWAFConfigurationVersion(cfg, false, manifest.Version)
	if err != nil || !reflect.DeepEqual(changes, again) {
		return out, errors.New("WAF 配置读取期间改变；未返回部分差异")
	}
	after, err := s.readSoftwareManifest("nginx-waf")
	if err != nil || !reflect.DeepEqual(manifest, after) {
		return out, errors.New("WAF 原清单核对期间改变")
	}
	if err = ctx.Err(); err != nil {
		return out, err
	}
	if err = wafBackupLockUnchanged(lock, filepath.Join(s.Config.SecurityDir, "waf-configuration.lock"), info); err != nil {
		return out, err
	}
	raw, err := json.Marshal(manifest)
	if err != nil {
		return out, err
	}
	out.InstalledVersion = manifest.Version
	out.PolicyRevision = strconv.FormatInt(cfg.Policy.Revision, 10)
	out.SemanticRecordSHA = core.Hash(string(raw))
	out.FilesystemMatches = len(changes) == 0
	for _, change := range changes {
		row := core.WAFConfigurationDifference{ActualExists: change.OldExists, ExpectedExists: change.NextExists, ActualSHA: core.Hash(string(change.OldData)), ExpectedSHA: core.Hash(string(change.NextData)), ActualBytes: len(change.OldData), ExpectedBytes: len(change.NextData)}
		if change.OldExists {
			row.ActualMode = uint32(change.OldMode.Perm())
		}
		if change.NextExists {
			row.ExpectedMode = uint32(change.NextMode.Perm())
		}
		httpPath, serverPath := wafFiles(s)
		switch change.Path {
		case s.Config.NginxConf:
			row.Scope = "nginx-main"
		case httpPath:
			row.Scope = "http-rules"
		case serverPath:
			row.Scope = "server-rules"
		case s.systemPath("/etc/panel/waf/http.d/20-panel-native-waf.conf"):
			row.Scope = "native-log"
		case s.softwareManifestPath("nginx-waf"):
			row.Scope = "manifest"
		default:
			row.SiteID = strings.TrimSuffix(filepath.Base(change.Path), ".conf")
			if !core.ValidID(row.SiteID) || filepath.Base(change.Path) != row.SiteID+".conf" {
				return out, errors.New("配置差异包含未知资源，未返回部分结果")
			}
			switch filepath.Dir(change.Path) {
			case s.Config.ConfDir:
				row.Scope = "site"
			case s.systemPath("/etc/panel/waf/body.d"):
				row.Scope = "body-site"
			default:
				return out, errors.New("配置差异路径不在固定范围")
			}
		}
		out.Differences = append(out.Differences, row)
	}
	serialized, err := json.Marshal(out)
	if err != nil {
		return out, err
	}
	return core.DecodeWAFConfigurationInspection(serialized)
}
func (s *Service) wafConfigurationInspectionRoutes(m *http.ServeMux) {
	m.HandleFunc("GET /v1/software/nginx-waf/config-inspection", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		if r.URL.RawQuery != "" || r.URL.ForceQuery || r.ContentLength != 0 || len(r.TransferEncoding) != 0 {
			respond(w, 400, map[string]string{"error": "只接受固定无参数只读配置核对"})
			return
		}
		s.mu.Lock()
		defer s.mu.Unlock()
		out, err := s.inspectInstalledWAFConfiguration(r.Context())
		if err != nil {
			respond(w, 409, map[string]string{"error": err.Error()})
			return
		}
		respond(w, 200, out)
	})
}
