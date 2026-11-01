//go:build linux

package executor

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"local/panel/internal/core"
	"net/http"
	"os"
	"sort"
	"strings"
	"time"
)

// Bounded strict objects, including duplicate, escaped-key, null and trailing
// rejection. Neither public Core nor private transport may inject a pathname.
func apacheNumericLogRequest(r *http.Request, out any, kind string) error {
	if err := r.Context().Err(); err != nil {
		return err
	}
	raw, err := io.ReadAll(io.LimitReader(r.Body, 4097))
	if err != nil {
		return err
	}
	values, err := core.DecodeApacheNumericLogMaintenance(raw, kind)
	if err != nil {
		return err
	}
	data, err := json.Marshal(values)
	if err != nil {
		return err
	}
	return json.Unmarshal(data, out)
}

// Whole bounded inventory is checked before returning any indexed items.
// A staging record or an uncertain copy is shown as pending, never zero use.
func (s *Service) apacheNumericInventory(ctx context.Context) (map[string]any, error) {
	stages, err := s.apacheNumericLogIndexStages(ctx)
	if err != nil {
		return nil, err
	}
	recovery, err := s.apacheNumericLogRecoveryEntries(ctx)
	if err != nil {
		return nil, err
	}
	rows := []apacheNumericLogArchive{}
	directory := s.apacheNumericLogArchiveDirectory()
	files, err := os.ReadDir(directory)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	ids := map[string]bool{}
	for _, file := range files {
		id, suffix, ok := strings.Cut(file.Name(), ".")
		if !ok || !core.ValidID(id) || (suffix != "json" && suffix != "log") {
			return nil, errors.New("Apache 快照有未知条目，库存未完成")
		}
		ids[id] = true
	}
	for id := range ids {
		row, _, err := s.readApacheNumericLogIndex(id)
		if err != nil {
			return nil, err
		}
		rows = append(rows, row)
	}
	sort.Slice(rows, func(i, j int) bool {
		if rows[i].CapturedAt == rows[j].CapturedAt {
			return rows[i].ID > rows[j].ID
		}
		return rows[i].CapturedAt > rows[j].CapturedAt
	})
	healthy := len(stages) == 0 && len(recovery) == 0
	for _, row := range rows {
		if row.State != "completed" {
			healthy = false
		}
	}
	return map[string]any{"archives": rows, "recovery": recovery, "index_stages": stages, "inventory_complete": true, "maintenance_healthy": healthy, "max_archives": apacheNumericLogArchiveLimit, "max_archive_bytes": apacheNumericLogLimit, "read_only": true, "numeric_only": true, "rotation_reloads_apache": false}, nil
}

func (s *Service) apacheNumericLogRoutes(m *http.ServeMux) {
	// Every exposed operation is fixed to the native application's private
	// namespace. The internal SystemRoot fixture adapter cannot grant HTTP access.
	ready := func(w http.ResponseWriter) bool {
		if s.Config.SystemRoot != "/" || s.Config.SitesDir != "/srv/panel/sites" || os.Geteuid() != 0 {
			respond(w, 503, map[string]string{"error": "Apache 日志维护仅允许真实受管环境"})
			return false
		}
		record, err := s.moduleInstalledRecord("apache-waf")
		if err != nil || record["version"] != core.ApacheWAFNativeBodyVersion {
			respond(w, 409, map[string]string{"error": "请先完成 Apache2.4.0 原签名安装；日志未创建或接管"})
			return false
		}
		return true
	}
	register := func(pattern string, write bool, run func(context.Context, *Service, *http.Request) (any, error)) {
		m.HandleFunc(pattern, func(w http.ResponseWriter, r *http.Request) {
			if len(r.URL.Query()) != 0 {
				respond(w, 400, map[string]string{"error": "日志维护不接受路径或查询参数"})
				return
			}
			if id := r.PathValue("id"); id != "" && !core.ValidID(id) {
				respond(w, 400, map[string]string{"error": "日志快照标识无效"})
				return
			}
			if !ready(w) {
				return
			}
			if write {
				s.mu.Lock()
				defer s.mu.Unlock()
			}
			logs := s.apacheNumericLogService()
			ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
			defer cancel()
			out, err := run(ctx, logs, r)
			if err != nil {
				respond(w, 409, map[string]string{"error": err.Error()})
				return
			}
			respond(w, 200, out)
		})
	}
	register("GET /v1/software/apache-waf/body-log/archives", false, func(ctx context.Context, logs *Service, r *http.Request) (any, error) {
		lock, err := logs.lockWAFObservation()
		if err != nil {
			return nil, err
		}
		defer lock.Close()
		return logs.apacheNumericInventory(ctx)
	})
	register("GET /v1/software/apache-waf/body-log/archives/{id}", false, func(ctx context.Context, logs *Service, r *http.Request) (any, error) {
		lock, err := logs.lockWAFObservation()
		if err != nil {
			return nil, err
		}
		defer lock.Close()
		entry, index, err := logs.readApacheNumericLogIndex(r.PathValue("id"))
		if err != nil {
			return nil, err
		}
		return logs.exportApacheNumericLogArchive(ctx, entry, index)
	})
	register("POST /v1/software/apache-waf/body-log/rotate", true, func(ctx context.Context, logs *Service, r *http.Request) (any, error) {
		var in struct{}
		if apacheNumericLogRequest(r, &in, "rotate") != nil {
			return nil, errors.New("请求格式无效")
		}
		entry, err := logs.rotateApacheNumericLog(ctx)
		if err != nil {
			return nil, err
		}
		return map[string]any{"archive": entry, "same_inode_rotation": true, "no_apache_reload": true}, nil
	})
	register("POST /v1/software/apache-waf/body-log/archives/{id}/remove", true, func(ctx context.Context, logs *Service, r *http.Request) (any, error) {
		var in struct {
			SHA     string `json:"sha256"`
			Confirm bool   `json:"confirm_delete"`
		}
		if apacheNumericLogRequest(r, &in, "remove") != nil || !wafLogDigestValid(in.SHA) || !in.Confirm {
			return nil, errors.New("移除快照需要原摘要及明确删除确认")
		}
		err := logs.removeApacheNumericLogArchive(ctx, r.PathValue("id"), in.SHA)
		if err != nil {
			return nil, err
		}
		return map[string]any{"removed": true, "archive_id": r.PathValue("id"), "sha256": in.SHA, "current_log_untouched": true}, nil
	})
	register("POST /v1/software/apache-waf/body-log/archives/{id}/retain", true, func(ctx context.Context, logs *Service, r *http.Request) (any, error) {
		var in struct {
			IndexSHA        string `json:"index_sha256"`
			SnapshotSHA     string `json:"snapshot_sha256"`
			SnapshotMissing bool   `json:"snapshot_missing"`
			Confirm         bool   `json:"confirm_unknown"`
		}
		if apacheNumericLogRequest(r, &in, "retain") != nil || !in.Confirm || !wafLogDigestValid(in.IndexSHA) || !in.SnapshotMissing && !wafLogDigestValid(in.SnapshotSHA) || in.SnapshotMissing && in.SnapshotSHA != "" {
			return nil, errors.New("保留未知结果需要完整原摘要和明确确认")
		}
		// Load the server's complete original record; never trust an injected
		// archive object or caller-selected source path.
		lock, err := logs.lockWAFObservation()
		if err != nil {
			return nil, err
		}
		pending, err := logs.apacheNumericLogRecoveryEntries(ctx)
		lock.Close()
		if err != nil {
			return nil, err
		}
		for _, p := range pending {
			if p.Archive.ID == r.PathValue("id") && p.IndexSHA == in.IndexSHA && p.SnapshotSHA == in.SnapshotSHA && p.SnapshotMissing == in.SnapshotMissing {
				if err := logs.retainApacheNumericLogSnapshot(ctx, p); err != nil {
					return nil, err
				}
				return map[string]any{"retained_unknown": true, "archive_id": p.Archive.ID, "current_log_untouched": true, "original_rotation_not_repeated": true}, nil
			}
		}
		return nil, errors.New("未知结果或摘要已变化，未接管")
	})
	register("POST /v1/software/apache-waf/body-log/index-stages/{id}/retain", true, func(ctx context.Context, logs *Service, r *http.Request) (any, error) {
		var in struct {
			SHA     string `json:"sha256"`
			Confirm bool   `json:"confirm_unknown"`
		}
		if apacheNumericLogRequest(r, &in, "retain-stage") != nil || !in.Confirm || !wafLogDigestValid(in.SHA) {
			return nil, errors.New("索引残件保留需要原摘要及确认")
		}
		id, err := logs.retainApacheNumericLogIndexStage(ctx, r.PathValue("id"), in.SHA)
		if err != nil {
			return nil, err
		}
		return map[string]any{"retained_id": id, "uncommitted_index_never_applied": true, "current_log_untouched": true}, nil
	})
}
