//go:build linux

package executor

import (
	"context"
	"errors"
	"local/panel/internal/core"
	"net/http"
	"os"
	"time"
)

func (s *Service) wafBodyRetentionRoutes(m *http.ServeMux) {
	m.HandleFunc("GET /v1/software/nginx-waf/body-log/retention", func(w http.ResponseWriter, r *http.Request) {
		if len(r.URL.Query()) != 0 {
			respond(w, 400, map[string]string{"error": "自动清理状态不接受自定义路径或参数"})
			return
		}
		lock, err := s.lockWAFObservation()
		if err != nil {
			respond(w, 503, map[string]string{"error": err.Error()})
			return
		}
		defer lock.Close()
		record, sha, err := s.readWAFBodyRetentionRecord()
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			respond(w, 503, map[string]string{"error": err.Error()})
			return
		}
		enabled, revision := false, int64(-1)
		if manifest, e := s.readSoftwareManifest("nginx-waf"); e == nil {
			cfg, e := core.DecodeWAFConfig(manifest.Settings)
			if e != nil || core.ValidateWAFBodyLogRotationSource(cfg) != nil {
				respond(w, 503, map[string]string{"error": "实际清理策略不可核验，未当成未启用或成功"})
				return
			}
			if wafRetentionVersion(manifest.Version) {
				enabled, revision = cfg.BodyLogRetention != nil && cfg.BodyLogRetention.Enabled, cfg.Policy.Revision
			}
		} else if !errors.Is(e, os.ErrNotExist) {
			respond(w, 503, map[string]string{"error": "实际应用清单不可读取"})
			return
		}
		if errors.Is(err, os.ErrNotExist) {
			respond(w, 200, map[string]any{"available": false, "enabled": enabled, "stale": enabled, "history_limit": wafBodyRetentionHistoryLimit, "no_automatic_retry": true})
			return
		}
		checked, _ := time.Parse(time.RFC3339, record.CheckedAt)
		blocked := record.Operation != nil && (record.Operation.State == "deleting" || record.Operation.State == "unknown")
		preserved, err := s.wafRetainedUnknownArchiveIDs(r.Context(), record)
		if err != nil {
			respond(w, 503, map[string]string{"error": "原未知计划残留快照不可核验；状态未当成成功，自动清理不得重新授权"})
			return
		}
		respond(w, 200, map[string]any{"available": true, "enabled": enabled, "record": record, "sha256": sha, "read_only": true, "blocked_unknown": blocked, "blocked_retained_unknown": len(preserved) > 0, "retained_unknown_archive_ids": preserved, "stale": enabled && (time.Since(checked) > 200*time.Second || checked.After(time.Now().Add(time.Minute)) || record.Revision != revision), "history_limit": wafBodyRetentionHistoryLimit, "no_automatic_retry": true})
	})
	m.HandleFunc("POST /v1/software/nginx-waf/body-log/retention/retain", func(w http.ResponseWriter, r *http.Request) {
		var in core.WAFBodyLogRetentionRetainRequest
		if !readJSON(w, r, &in) {
			return
		}
		if !in.Valid() || len(r.URL.Query()) != 0 {
			respond(w, 400, map[string]string{"error": "自动清理摘要或未知结果确认无效"})
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
		defer cancel()
		out, err := s.retainWAFBodyRetentionOutcome(ctx, in.SHA256, time.Now().UTC())
		if err != nil {
			respond(w, 409, map[string]string{"error": err.Error()})
			return
		}
		respond(w, 200, map[string]any{"record": out, "deletion_outcome": "unknown_retained_not_marked_successful", "current_log_untouched": true, "archives_not_deleted": true, "original_plan_not_retried": true})
	})
}
