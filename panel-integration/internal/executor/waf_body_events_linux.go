//go:build linux

package executor

import (
	"bytes"
	"context"
	"errors"
	"io"
	"local/panel/internal/core"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"time"
)

var wafBodyEventPattern = regexp.MustCompile(`^(\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2}) \[warn\] [0-9]+#[0-9]+: yunzhan_waf_body rule=([0-9]+) phase=([1-5]) severity=([0-7]) disruptive=([01]) site=([a-f0-9]{32}|unmanaged)$`)

func parseWAFBodyEvent(line []byte) (core.WAFBodyEvent, bool) {
	var out core.WAFBodyEvent
	if len(line) > 512 {
		return out, false
	}
	match := wafBodyEventPattern.FindSubmatch(line)
	if len(match) != 7 {
		return out, false
	}
	at, err := time.ParseInLocation("2006/01/02 15:04:05", string(match[1]), time.Local)
	if err != nil {
		return out, false
	}
	rule, err := strconv.Atoi(string(match[2]))
	if err != nil || rule < 1 || rule > 2147483647 {
		return out, false
	}
	phase, _ := strconv.Atoi(string(match[3]))
	severity, _ := strconv.Atoi(string(match[4]))
	return core.WAFBodyEvent{Time: at.UTC().Format(time.RFC3339), SiteID: string(match[6]), RuleID: rule, Phase: phase, Severity: severity, Disruptive: string(match[5]) == "1"}, true
}

func (s *Service) readWAFBodyEvents() (core.WAFBodyEventsPage, error) {
	lock, err := s.lockWAFConfiguration()
	if err != nil {
		return core.WAFBodyEventsPage{}, err
	}
	defer lock.Close()
	return s.readWAFBodyEventsLocked()
}

// Caller owns the WAF configuration lock, including when checking the log and
// its recovery inventory as one coherent health observation.
func (s *Service) readWAFBodyEventsLocked() (core.WAFBodyEventsPage, error) {
	legacy := false
	f, err := s.openWAFBodyLog(false, false)
	if errors.Is(err, os.ErrNotExist) {
		legacy = true
		f, err = s.openWAFBodyLog(false, true)
	}
	if errors.Is(err, os.ErrNotExist) {
		return core.WAFBodyEventsPage{Events: []core.WAFBodyEvent{}, BestEffort: true}, nil
	}
	if err != nil {
		return core.WAFBodyEventsPage{}, err
	}
	defer f.Close()
	return readWAFBodyEventsFile(f, legacy)
}

func readWAFBodyEventsFile(f *os.File, legacy bool) (core.WAFBodyEventsPage, error) {
	page := core.WAFBodyEventsPage{Events: []core.WAFBodyEvent{}, BestEffort: true, LegacyLog: legacy}
	st, err := f.Stat()
	if err != nil || !st.Mode().IsRegular() {
		return page, errors.New("请求体元数据日志不是普通文件")
	}
	page.Available = true
	page.LogBytes = st.Size()
	if !legacy {
		page.MaxBytes = wafBodyLogLimit
		page.CapacityExhausted = st.Size() > wafBodyLogLimit-512
		page.Partial = page.CapacityExhausted
	}
	const budget = 4 << 20
	start := max(0, st.Size()-budget)
	if _, err := f.Seek(start, io.SeekStart); err != nil {
		return page, err
	}
	data, err := io.ReadAll(io.LimitReader(f, budget))
	if err != nil {
		return page, err
	}
	lines := bytes.Split(data, []byte{'\n'})
	if start > 0 {
		lines = lines[1:]
		page.Partial = true
	}
	for i := len(lines) - 1; i >= 0; i-- {
		line := lines[i]
		if len(line) == 0 {
			continue
		}
		if len(page.Events) >= 5000 {
			page.Partial = true
			break
		}
		if event, ok := parseWAFBodyEvent(line); ok {
			page.Events = append(page.Events, event)
		} else {
			page.Rejected++
		}
	}
	return page, nil
}

func (s *Service) wafBodyReportRoutes(m *http.ServeMux) {
	m.HandleFunc("POST /v1/software/nginx-waf/body-log/index-stages/{id}/retain", func(w http.ResponseWriter, r *http.Request) {
		var in core.WAFBodyLogIndexRetainRequest
		if !readJSON(w, r, &in) {
			return
		}
		if !in.Valid() || !core.ValidID(r.PathValue("id")) || len(r.URL.Query()) != 0 {
			respond(w, 400, map[string]string{"error": "索引残件标识、摘要或不接管确认无效"})
			return
		}
		s.mu.Lock()
		defer s.mu.Unlock()
		ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
		defer cancel()
		retained, err := s.retainWAFBodyLogIndexStage(ctx, r.PathValue("id"), in.SHA256)
		if err != nil {
			respond(w, 409, map[string]string{"error": err.Error()})
			return
		}
		respond(w, 200, map[string]any{"retained_id": retained, "source_id": r.PathValue("id"), "sha256": in.SHA256, "never_applied_as_index": true, "current_log_untouched": true, "original_inode_preserved": true})
	})
	m.HandleFunc("POST /v1/software/nginx-waf/body-log/archives/{id}/retain", func(w http.ResponseWriter, r *http.Request) {
		var in core.WAFBodyLogRetainRequest
		if !readJSON(w, r, &in) {
			return
		}
		if !in.Valid() || !core.ValidID(r.PathValue("id")) || len(r.URL.Query()) != 0 {
			respond(w, 400, map[string]string{"error": "恢复记录身份、摘要或未知结果确认无效"})
			return
		}
		s.mu.Lock()
		defer s.mu.Unlock()
		ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
		defer cancel()
		selected := wafBodyLogRecovery{Archive: wafBodyLogArchive{ID: r.PathValue("id")}, IndexSHA: in.IndexSHA256, SnapshotSHA: in.SnapshotSHA256, SnapshotMissing: in.SnapshotMissing}
		if err := s.retainWAFBodyLogSnapshot(ctx, selected); err != nil {
			respond(w, 409, map[string]string{"error": err.Error()})
			return
		}
		respond(w, 200, map[string]any{"retained_id": r.PathValue("id"), "current_log_untouched": true, "rotation_outcome": "unknown_not_marked_successful"})
	})
	m.HandleFunc("POST /v1/software/nginx-waf/body-log/archives/{id}/remove", func(w http.ResponseWriter, r *http.Request) {
		var in struct {
			SHA256       string `json:"sha256"`
			Acknowledged bool   `json:"acknowledge_bounded_export_and_permanent_removal"`
		}
		if !readJSON(w, r, &in) {
			return
		}
		if !in.Acknowledged || len(r.URL.Query()) != 0 {
			respond(w, 400, map[string]string{"error": "删除备份必须明确确认导出有界且此操作不可恢复；不接受自定义路径"})
			return
		}
		s.mu.Lock()
		defer s.mu.Unlock()
		ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
		defer cancel()
		if err := s.removeWAFBodyLogArchive(ctx, r.PathValue("id"), in.SHA256); err != nil {
			respond(w, 409, map[string]string{"error": err.Error()})
			return
		}
		respond(w, 200, map[string]any{"removed_id": r.PathValue("id"), "current_log_untouched": true, "permanent": true})
	})
	m.HandleFunc("GET /v1/software/nginx-waf/body-log/archives", func(w http.ResponseWriter, r *http.Request) {
		if len(r.URL.Query()) != 0 {
			respond(w, 400, map[string]string{"error": "备份列表不接受自定义路径或参数"})
			return
		}
		lock, lockErr := s.lockWAFConfiguration()
		if lockErr != nil {
			respond(w, 503, map[string]string{"error": lockErr.Error()})
			return
		}
		defer lock.Close()
		entries, err := s.wafBodyLogArchives()
		ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
		defer cancel()
		stages, stageErr := s.wafBodyLogIndexStages(ctx)
		if stageErr != nil {
			respond(w, 503, map[string]string{"error": stageErr.Error()})
			return
		}
		recovery, recoveryErr := s.wafBodyLogRecoveryEntries(ctx)
		if recoveryErr != nil {
			respond(w, 503, map[string]string{"error": recoveryErr.Error()})
			return
		}
		warning := ""
		if err != nil {
			if len(recovery) == 0 {
				respond(w, 503, map[string]string{"error": err.Error()})
				return
			}
			warning = err.Error()
			entries = []wafBodyLogArchive{}
		}
		respond(w, 200, map[string]any{"entries": entries, "recovery_entries": recovery, "index_stages": stages, "inventory_warning": warning, "limit": wafBodyLogArchiveLimit, "snapshot_contract": "independent_before_truncate_snapshots_may_overlap_after_failure"})
	})
	m.HandleFunc("GET /v1/software/nginx-waf/body-log/archives/{id}", func(w http.ResponseWriter, r *http.Request) {
		if len(r.URL.Query()) != 0 || !core.ValidID(r.PathValue("id")) {
			respond(w, 400, map[string]string{"error": "备份标识或参数无效"})
			return
		}
		lock, lockErr := s.lockWAFConfiguration()
		if lockErr != nil {
			respond(w, 503, map[string]string{"error": lockErr.Error()})
			return
		}
		defer lock.Close()
		entries, err := s.wafBodyLogArchives()
		if err != nil {
			respond(w, 503, map[string]string{"error": err.Error()})
			return
		}
		for _, entry := range entries {
			if entry.ID == r.PathValue("id") {
				if entry.State == "retained-missing" {
					respond(w, 200, map[string]any{"archive": entry, "metadata": core.WAFBodyEventsPage{Events: []core.WAFBodyEvent{}, BestEffort: true}, "export_contract": "missing_snapshot_intent_only_no_rule_events_available"})
					return
				}
				ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
				defer cancel()
				sha, err := wafNativeFileSHA(ctx, filepath.Join(s.wafBodyLogArchiveDirectory(), entry.ID+".log"), wafBodyLogLimit)
				if err != nil || sha != entry.SHA256 {
					respond(w, 503, map[string]string{"error": "元数据备份摘要核对失败，未导出"})
					return
				}
				f, err := s.openWAFBodyLogArchive(entry.ID)
				if err != nil {
					respond(w, 503, map[string]string{"error": err.Error()})
					return
				}
				defer f.Close()
				page, err := readWAFBodyEventsFile(f, false)
				if err != nil {
					respond(w, 503, map[string]string{"error": err.Error()})
					return
				}
				respond(w, 200, map[string]any{"archive": entry, "metadata": page, "export_contract": "numeric_only_recent_4MiB_5000_rules_not_full_raw_archive"})
				return
			}
		}
		respond(w, 404, map[string]string{"error": "元数据备份不存在"})
	})
	m.HandleFunc("POST /v1/software/nginx-waf/body-log/rotate", func(w http.ResponseWriter, r *http.Request) {
		var in struct{}
		if !readJSON(w, r, &in) {
			return
		}
		if len(r.URL.Query()) != 0 {
			respond(w, 400, map[string]string{"error": "日志轮转不接受自定义参数"})
			return
		}
		s.mu.Lock()
		defer s.mu.Unlock()
		ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
		defer cancel()
		entry, err := s.rotateWAFBodyLog(ctx)
		if err != nil {
			respond(w, 409, map[string]string{"error": err.Error()})
			return
		}
		respond(w, 200, map[string]any{"archive": entry, "same_inode_rotation": true, "no_nginx_reload": true})
	})
	m.HandleFunc("GET /v1/software/nginx-waf/body-report", func(w http.ResponseWriter, r *http.Request) {
		if _, err := s.readSoftwareManifest("nginx-waf"); err != nil {
			respond(w, 409, map[string]string{"error": "请先安装 Nginx 请求防火墙"})
			return
		}
		page, err := s.readWAFBodyEvents()
		if err != nil {
			respond(w, 503, map[string]string{"error": err.Error()})
			return
		}
		out, err := core.BuildWAFBodyReport(page, r.URL.Query(), time.Now())
		if err != nil {
			respond(w, 400, map[string]string{"error": err.Error()})
			return
		}
		respond(w, 200, out)
	})
}
