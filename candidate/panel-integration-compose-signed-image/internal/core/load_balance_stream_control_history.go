package core

import (
	"context"
	"database/sql"
	"net/http"
	"strconv"
	"time"
)

const loadBalanceStreamHistoryPageSize = 32

// Historical evidence is actor-owned and read-only. Listing a reservation does
// not revive its grant, dispatch it, reconcile Root, or declare current health.
type loadBalanceStreamControlHistory struct {
	Format     int                           `json:"format"`
	ActorID    string                        `json:"actor_id"`
	Offset     int                           `json:"offset"`
	Total      int                           `json:"total"`
	NextOffset *int                          `json:"next_offset"`
	Rows       []loadBalanceStreamControlRow `json:"rows"`
}

func (s *Store) loadBalanceStreamControlsForActor(ctx context.Context, actor string, offset int) (loadBalanceStreamControlHistory, error) {
	out := loadBalanceStreamControlHistory{Format: 1, ActorID: actor, Offset: offset, Rows: []loadBalanceStreamControlRow{}}
	if s == nil || s.DB == nil || ctx == nil || ctx.Err() != nil || !ValidID(actor) || offset < 0 || offset > loadBalanceStreamControlLimit || offset%loadBalanceStreamHistoryPageSize != 0 {
		return out, errLoadBalanceStreamControl
	}
	tx, err := s.DB.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return out, err
	}
	defer tx.Rollback()
	access, err := readUserAccessContext(ctx, tx, actor)
	if err != nil || !fullAdministrator(access) || len(access.SiteIDs) != 0 || access.Revision < 1 || streamControlSchema(ctx, tx) != nil {
		return out, errLoadBalanceStreamControl
	}
	var global int
	if tx.QueryRowContext(ctx, "SELECT count(*),coalesce(sum(actor_id=?),0) FROM load_balance_stream_controls", actor).Scan(&global, &out.Total) != nil || global > loadBalanceStreamControlLimit || out.Total > global {
		return out, errLoadBalanceStreamControl
	}
	rows, err := tx.QueryContext(ctx, "SELECT "+loadBalanceStreamControlColumns+" FROM load_balance_stream_controls WHERE actor_id=? ORDER BY created_at DESC,request_id DESC LIMIT ? OFFSET ?", actor, loadBalanceStreamHistoryPageSize, offset)
	if err != nil {
		return out, err
	}
	defer rows.Close()
	for rows.Next() {
		row, found, err := scanStreamControl(rows, "")
		if err != nil || !found || row.Operation.ActorID != actor {
			return out, errLoadBalanceStreamControl
		}
		out.Rows = append(out.Rows, row)
	}
	if err := rows.Err(); err != nil {
		return out, err
	}
	if err := rows.Close(); err != nil {
		return out, err
	}
	if offset+len(out.Rows) < out.Total {
		next := offset + loadBalanceStreamHistoryPageSize
		out.NextOffset = &next
	}
	return out, tx.Commit()
}

func (a *Server) loadBalanceStreamControlHistoryRoutes(m *http.ServeMux) {
	m.HandleFunc("GET /api/app-registry/load-balance/stream/controls", a.authorize(func(w http.ResponseWriter, r *http.Request, actor identity) {
		w.Header().Set("Cache-Control", "no-store")
		// No caller-selected actor, SQL, limit, cursor identity, or execution flag.
		offset := 0
		if r.URL.RawQuery != "" {
			q := r.URL.Query()
			value := q.Get("offset")
			parsed, err := strconv.Atoi(value)
			if err != nil || len(q) != 1 || len(q["offset"]) != 1 || strconv.Itoa(parsed) != value || parsed < 0 || parsed > loadBalanceStreamControlLimit || parsed%loadBalanceStreamHistoryPageSize != 0 || r.URL.RawQuery != "offset="+value {
				fail(w, 400, "历史查询只接受固定页边界，不接受动作或身份参数")
				return
			}
			offset = parsed
		}
		ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
		defer cancel()
		out, err := a.Store.loadBalanceStreamControlsForActor(ctx, actor.ID, offset)
		if err != nil {
			fail(w, 403, "需要当前完整管理员及完整的本人原请求历史")
			return
		}
		// A page is a fresh observation, not a cross-page snapshot or grant.
		send(w, 200, out)
	}))
}
