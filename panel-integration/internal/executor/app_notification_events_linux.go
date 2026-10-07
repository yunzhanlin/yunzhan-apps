//go:build linux

package executor

import (
	"encoding/json"
	"local/panel/internal/core"
	"net/http"
	"strconv"
)

func (s *Service) moduleAlertRoutes(m *http.ServeMux) {
	m.HandleFunc("GET /v1/module-alert-events", func(w http.ResponseWriter, r *http.Request) {
		module := r.URL.Query().Get("module")
		allowed := false
		for _, id := range []string{"file-monitor", "website-tamper-proof", "enterprise-tamper-proof", "files-sync"} {
			allowed = allowed || module == id
		}
		cursor, e := strconv.ParseInt(r.URL.Query().Get("cursor"), 10, 64)
		if !allowed || e != nil || cursor < -1 {
			respond(w, 400, map[string]string{"error": "事件游标或模块无效"})
			return
		}
		page := core.ModuleAlertPage{Cursor: cursor, Events: []core.ModuleAlertEvent{}}
		if page.Cursor < 0 {
			page.Cursor = 0
		}
		s.mu.Lock()
		defer s.mu.Unlock()
		if !s.moduleInstalled(module) {
			respond(w, 200, page)
			return
		}
		db, e := s.openModuleLedger(r.Context(), module)
		if e != nil {
			respond(w, 409, map[string]string{"error": "应用事件数据库不可读取"})
			return
		}
		defer db.Close()
		var first, last int64
		if e = db.QueryRowContext(r.Context(), `SELECT COALESCE(MIN(seq),0),MAX(COALESCE(MAX(seq),0),COALESCE((SELECT CAST(value AS INTEGER) FROM metadata WHERE key='last-event-sequence'),0)) FROM module_events`).Scan(&first, &last); e != nil {
			respond(w, 409, map[string]string{"error": "应用事件游标不可读取"})
			return
		}
		if cursor == -1 {
			page.Cursor = last
			respond(w, 200, page)
			return
		}
		if cursor > last {
			respond(w, 409, map[string]string{"error": "应用历史序列回退，请核对数据库"})
			return
		}
		page.Gap = (first > cursor+1) || (first == 0 && last > cursor)
		rows, e := db.QueryContext(r.Context(), `SELECT seq,payload FROM module_events WHERE seq>? ORDER BY seq LIMIT 500`, cursor)
		if e != nil {
			respond(w, 409, map[string]string{"error": "读取应用事件失败"})
			return
		}
		for rows.Next() {
			var seq int64
			var raw string
			var event moduleEvent
			if e = rows.Scan(&seq, &raw); e != nil {
				break
			}
			if e = json.Unmarshal([]byte(raw), &event); e != nil {
				break
			}
			page.Events = append(page.Events, core.ModuleAlertEvent{Sequence: seq, ID: event.ID, Time: event.Time, Outcome: event.Outcome, Changes: event.Changes, Conflicts: event.Conflicts})
			page.Cursor = seq
		}
		if e == nil {
			e = rows.Err()
		}
		rows.Close()
		if e != nil {
			respond(w, 409, map[string]string{"error": "应用事件摘要损坏"})
			return
		}
		if len(page.Events) == 0 {
			page.Cursor = last
		}
		respond(w, 200, page)
	})
}
